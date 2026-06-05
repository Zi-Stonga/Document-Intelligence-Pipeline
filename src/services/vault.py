"""
DynamoDB vault service for writing PII classification records.

Implements idempotent writes using a condition expression that requires both
document_id and version to be absent. ConditionalCheckFailedException is
treated as an idempotent skip, not a failure.
"""

import json
import time
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from src.config.settings import Settings
from src.models.pii_record import PiiRecord
from src.models.pii_result import PiiClassification
from src.utils.crypto import sha256_hex
from src.utils.exceptions import VaultWriteError
from src.utils.logger import log_info, log_warn

_CONDITIONAL_CHECK_FAILED = "ConditionalCheckFailedException"
_RETRYABLE_ERRORS = frozenset(
    {
        "ThrottlingException",
        "ServiceUnavailableException",
        "ProvisionedThroughputExceededException",
    }
)

_TRUNCATED_PII_DATA = json.dumps(
    {
        "other_pii": [
            {"type": "TRUNCATED", "value": "Response too large. Reprocess with chunked input."}
        ]
    }
)


def write_vault_record(
    source_key: str,
    source_bucket: str,
    classification: PiiClassification,
    start_time_ms: int,
    settings: Settings,
    client: Any = None,
) -> bool:
    """
    Write a PII classification result to the DynamoDB pii-vault table.

    Args:
        source_key: Original S3 object key.
        source_bucket: Source S3 bucket name.
        classification: Masked PiiClassification. SSNs must be masked before call.
        start_time_ms: Processing start time in epoch milliseconds.
        settings: Application settings.
        client: boto3 DynamoDB client. Injected for testability.

    Returns:
        True if the record was written, False if it was an idempotent skip.

    Raises:
        VaultWriteError: If the DynamoDB write fails after all retries.
    """
    dynamo = client or _default_client()

    document_id = sha256_hex(source_key)
    source_key_hash = sha256_hex(source_key)
    version = start_time_ms
    now_ms = int(time.time() * 1000)

    pii_data_json = _serialize_pii_data(classification, settings.max_pii_bytes)
    expires_at = _calculate_expires_at(settings.pii_ttl_days)

    record = PiiRecord(
        document_id=document_id,
        version=version,
        source_key=source_key,
        source_bucket=source_bucket,
        source_key_hash=source_key_hash,
        pii_counts=json.dumps(classification.counts()),
        pii_data=pii_data_json,
        processed_at=datetime.now(tz=timezone.utc).isoformat(),
        duration_ms=now_ms - start_time_ms,
        expires_at=expires_at,
    )

    for attempt in range(1, settings.max_retry_attempts + 1):
        try:
            dynamo.put_item(
                TableName=settings.dynamodb_table,
                Item=record.to_dynamodb_item(),
                ConditionExpression=(
                    "attribute_not_exists(document_id) AND attribute_not_exists(version)"
                ),
            )
            log_info("vault_write_success", document_id=document_id, version=version)
            return True
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]

            if error_code == _CONDITIONAL_CHECK_FAILED:
                log_info("vault_write_skipped_duplicate", document_id=document_id, version=version)
                return False

            if error_code not in _RETRYABLE_ERRORS or attempt == settings.max_retry_attempts:
                raise VaultWriteError(
                    f"DynamoDB PutItem failed for document_id={document_id} "
                    f"after {attempt} attempt(s): {error_code}. "
                    "Verify the table exists, the Lambda role has PutItem, "
                    "and the KMS key policy allows DynamoDB."
                ) from exc

            delay_ms = _calculate_delay_ms(attempt, settings.retry_base_delay_ms)
            log_warn("vault_write_retry", attempt=attempt, error_code=error_code, delay_ms=delay_ms)
            time.sleep(delay_ms / 1000)

    raise VaultWriteError(
        f"DynamoDB PutItem exhausted all retry attempts for document_id={document_id}."
    )


def _serialize_pii_data(classification: PiiClassification, max_bytes: int) -> str:
    """
    Serialize PiiClassification to JSON, truncating if it exceeds the byte limit.

    Args:
        classification: Masked PiiClassification.
        max_bytes: Maximum bytes allowed for the pii_data field.

    Returns:
        JSON string, possibly replaced with a truncation marker if too large.
    """
    serialized = json.dumps(classification.to_dict())
    if len(serialized.encode("utf-8")) > max_bytes:
        log_warn("pii_data_truncated", original_bytes=len(serialized.encode("utf-8")))
        return _TRUNCATED_PII_DATA
    return serialized


def _calculate_expires_at(ttl_days: int) -> int:
    """
    Calculate the DynamoDB TTL value for a record.

    Args:
        ttl_days: Number of days before expiry from Settings.

    Returns:
        Unix epoch seconds ttl_days from now.
    """
    return int(time.time()) + (ttl_days * 86_400)


def _calculate_delay_ms(attempt: int, base_delay_ms: int) -> int:
    """
    Calculate exponential backoff delay.

    Args:
        attempt: Current attempt number (1-indexed).
        base_delay_ms: Base delay in milliseconds.

    Returns:
        Delay in milliseconds.
    """
    return base_delay_ms * (2 ** (attempt - 1))


def _default_client() -> Any:
    """
    Create a boto3 DynamoDB client using the Lambda execution role.

    Returns:
        boto3 DynamoDB client.
    """
    return boto3.client("dynamodb")
