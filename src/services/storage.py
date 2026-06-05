"""
S3 storage service for writing output and audit records.

Audit records deliberately exclude pii_data so the compliance team can audit
processing history without accessing sensitive classified values.
"""

import json
import time
from datetime import date, datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from src.config.settings import Settings
from src.models.pii_result import PiiClassification
from src.utils.exceptions import StorageWriteError
from src.utils.logger import log_info, log_warn

_RETRYABLE_ERRORS = frozenset(
    {
        "ThrottlingException",
        "ServiceUnavailableException",
        "SlowDown",
    }
)


def write_output(
    document_id: str,
    version: int,
    classification: PiiClassification,
    output_key: str,
    settings: Settings,
    client: Any = None,
) -> None:
    """
    Write a processed output summary record to the S3 output bucket.

    Contains document_id, version, and pii_counts. No pii_data.

    Args:
        document_id: SHA-256 of the source S3 key.
        version: Epoch milliseconds processing timestamp.
        classification: Masked PiiClassification. Only counts are written.
        output_key: S3 object key under the output bucket.
        settings: Application settings.
        client: boto3 S3 client. Injected for testability.

    Raises:
        StorageWriteError: If all retry attempts fail.
    """
    body = json.dumps(
        {
            "document_id": document_id,
            "version": version,
            "pii_counts": classification.counts(),
        },
        indent=2,
    )

    _put_object(
        bucket=settings.output_bucket,
        key=output_key,
        body=body,
        settings=settings,
        client=client or _default_client(),
        context=f"output for document_id={document_id}",
    )
    log_info("output_written", document_id=document_id, key=output_key)


def write_audit(
    document_id: str,
    version: int,
    source_key_hash: str,
    source_bucket: str,
    classification: PiiClassification,
    expires_at: int,
    start_time_ms: int,
    settings: Settings,
    client: Any = None,
) -> None:
    """
    Write a tamper-evident audit record to the S3 audit bucket.

    Contains document_id, version, source_key_hash, pii_counts, expires_at,
    processed_at, and duration_ms. Does NOT contain pii_data.

    Args:
        document_id: SHA-256 of the source S3 key.
        version: Epoch milliseconds processing timestamp.
        source_key_hash: SHA-256 of the source S3 key.
        source_bucket: Source S3 bucket name.
        classification: Masked PiiClassification. Only counts are written.
        expires_at: Unix epoch seconds for TTL alignment.
        start_time_ms: Processing start time for duration calculation.
        settings: Application settings.
        client: boto3 S3 client. Injected for testability.

    Raises:
        StorageWriteError: If all retry attempts fail.
    """
    now_ms = int(time.time() * 1000)
    audit_date = date.today().isoformat()
    audit_key = f"lambda-audit/{audit_date}/{document_id}-{version}.json"

    body = json.dumps(
        {
            "document_id": document_id,
            "version": version,
            "source_key_hash": source_key_hash,
            "source_bucket": source_bucket,
            "pii_counts": classification.counts(),
            "expires_at": expires_at,
            "processed_at": datetime.now(tz=timezone.utc).isoformat(),
            "duration_ms": now_ms - start_time_ms,
        },
        indent=2,
    )

    _put_object(
        bucket=settings.audit_bucket,
        key=audit_key,
        body=body,
        settings=settings,
        client=client or _default_client(),
        context=f"audit for document_id={document_id}",
    )
    log_info("audit_written", document_id=document_id, key=audit_key)


def _put_object(
    bucket: str,
    key: str,
    body: str,
    settings: Settings,
    client: Any,
    context: str,
) -> None:
    """
    Call S3 PutObject with KMS encryption and exponential backoff retry.

    Args:
        bucket: S3 bucket name.
        key: S3 object key.
        body: JSON string to write.
        settings: Application settings for KMS ARN and retry config.
        client: boto3 S3 client.
        context: Human-readable context string for error messages.

    Raises:
        StorageWriteError: If all retry attempts fail.
    """
    for attempt in range(1, settings.max_retry_attempts + 1):
        try:
            client.put_object(
                Bucket=bucket,
                Key=key,
                Body=body.encode("utf-8"),
                ContentType="application/json",
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=settings.kms_key_arn,
            )
            return
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code not in _RETRYABLE_ERRORS or attempt == settings.max_retry_attempts:
                raise StorageWriteError(
                    f"S3 PutObject failed for {context} after {attempt} attempt(s): "
                    f"{error_code}. Verify the bucket exists and the Lambda role "
                    "has PutObject for the relevant prefix."
                ) from exc

            delay_ms = _calculate_delay_ms(attempt, settings.retry_base_delay_ms)
            log_warn("s3_put_retry", attempt=attempt, error_code=error_code, delay_ms=delay_ms)
            time.sleep(delay_ms / 1000)


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
    Create a boto3 S3 client using the Lambda execution role.

    Returns:
        boto3 S3 client.
    """
    return boto3.client("s3")
