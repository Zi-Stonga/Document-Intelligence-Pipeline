"""
Lambda entry point for the PII processing pipeline.

Receives SQS batch events and processes each record independently.
Failed records are returned in batchItemFailures so SQS retries only
the failed messages, not the entire batch.

Settings is loaded once at module level (cold start) so configuration
errors fail fast and visibly rather than on first invocation.
"""

import json
import time
import urllib.parse
from typing import Any

from src.config.settings import Settings, get_settings
from src.services.anthropic import classify_pii
from src.services.secrets import get_api_key
from src.services.storage import write_audit, write_output
from src.services.textract import extract_text
from src.services.vault import write_vault_record
from src.utils.crypto import sha256_hex
from src.utils.exceptions import PipelineError, ValidationError
from src.utils.logger import log_error, log_info, log_warn
from src.utils.masking import mask_ssns
from src.utils.validation import make_output_key, validate_inputs

_settings: Settings = get_settings()


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    AWS Lambda handler for SQS batch events.

    Args:
        event: SQS event dict from AWS Lambda, containing a Records list.
        context: Lambda context object (unused, present for AWS signature).

    Returns:
        Dict with batchItemFailures list. Empty list means all records succeeded.
    """
    records: list[dict[str, Any]] = event.get("Records", [])
    log_info("batch_received", record_count=len(records))

    batch_item_failures: list[dict[str, str]] = []

    for record in records:
        message_id: str = record.get("messageId", "unknown")
        try:
            _process_record(record)
        except (PipelineError, ValidationError) as exc:
            log_error(
                "record_failed",
                message_id=message_id,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            batch_item_failures.append({"itemIdentifier": message_id})
        except Exception as exc:
            log_error(
                "record_failed_unexpected",
                message_id=message_id,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            batch_item_failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": batch_item_failures}


def _process_record(record: dict[str, Any]) -> None:
    """
    Process a single SQS record through the full pipeline.

    Sequence:
    1. Parse source_bucket and source_key from SQS message body
    2. validate_inputs fails fast with no AWS calls
    3. extract_text via Textract
    4. classify_pii via Anthropic API
    5. mask_ssns deterministic code masking before any storage
    6. write_vault_record to DynamoDB (idempotent)
    7. write_output to S3 output bucket
    8. write_audit to S3 audit bucket

    Args:
        record: Single SQS record dict from the batch event.

    Raises:
        ValidationError: On invalid source_bucket or source_key.
        PipelineError: On any service failure after all retries.
    """
    start_time_ms = int(time.time() * 1000)

    source_bucket, source_key = _parse_s3_event(record)
    validate_inputs(source_bucket, source_key)

    document_id = sha256_hex(source_key)
    source_key_hash = sha256_hex(source_key)

    log_info("record_processing_start", document_id=document_id)

    text = extract_text(source_bucket, source_key, _settings)

    if not text or not text.strip():
        log_warn("no_text_extracted", document_id=document_id)
        return

    api_key = get_api_key(_settings)
    raw_classification = classify_pii(text, api_key, _settings)
    masked_classification = mask_ssns(raw_classification)

    written = write_vault_record(
        source_key=source_key,
        source_bucket=source_bucket,
        classification=masked_classification,
        start_time_ms=start_time_ms,
        settings=_settings,
    )

    if not written:
        log_info("record_skipped_duplicate", document_id=document_id)
        return

    output_key = make_output_key(source_key)
    write_output(
        document_id=document_id,
        version=start_time_ms,
        classification=masked_classification,
        output_key=output_key,
        settings=_settings,
    )

    expires_at = int(time.time()) + (_settings.pii_ttl_days * 86_400)
    write_audit(
        document_id=document_id,
        version=start_time_ms,
        source_key_hash=source_key_hash,
        source_bucket=source_bucket,
        classification=masked_classification,
        expires_at=expires_at,
        start_time_ms=start_time_ms,
        settings=_settings,
    )

    log_info(
        "record_processing_complete",
        document_id=document_id,
        duration_ms=int(time.time() * 1000) - start_time_ms,
        pii_counts=masked_classification.counts(),
    )


def _parse_s3_event(record: dict[str, Any]) -> tuple[str, str]:
    """
    Extract source_bucket and source_key from an SQS record.

    Handles two formats:
    1. Standard S3 event notification wrapped in SQS body JSON.
    2. Simplified direct injection: {"bucket": "...", "key": "..."}.

    Args:
        record: Single SQS record dict.

    Returns:
        Tuple of (source_bucket, source_key).

    Raises:
        ValidationError: If the message body cannot be parsed.
    """
    try:
        body: dict[str, Any] = json.loads(record["body"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise ValidationError(
            "SQS record body is missing or not valid JSON. "
            "Check that the S3 event notification is correctly configured."
        ) from exc

    if "Records" in body and body["Records"]:
        s3_record: dict[str, Any] = body["Records"][0].get("s3", {})
        raw_bucket: str = s3_record.get("bucket", {}).get("name", "")
        raw_key: str = s3_record.get("object", {}).get("key", "")
        return raw_bucket, urllib.parse.unquote_plus(raw_key)

    if "bucket" in body and "key" in body:
        return str(body["bucket"]), str(body["key"])

    raise ValidationError(
        "SQS message body does not contain a recognisable S3 event. "
        "Expected Records[0].s3 structure or {bucket, key} direct format."
    )
