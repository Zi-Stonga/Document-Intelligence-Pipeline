"""
Amazon Textract service for document text extraction.

Uses the synchronous DetectDocumentText API. Documents are referenced
directly from S3 with no base64 encoding.
"""

import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

from src.config.settings import Settings
from src.utils.exceptions import TextractError
from src.utils.logger import log_warn

_RETRYABLE_ERRORS = frozenset(
    {
        "ThrottlingException",
        "ServiceUnavailableException",
        "InternalServerError",
    }
)


def extract_text(
    bucket: str,
    key: str,
    settings: Settings,
    client: Any = None,
) -> str:
    """
    Extract plain text from a document stored in S3 using Amazon Textract.

    Retries on transient failures using exponential backoff.

    Args:
        bucket: S3 bucket containing the document.
        key: S3 object key of the document.
        settings: Application settings containing retry configuration.
        client: boto3 Textract client. Injected for testability.

    Returns:
        Extracted text as a single string. Empty string if no text found.

    Raises:
        TextractError: If all retry attempts fail or a non-retryable error occurs.
    """
    textract = client or _default_client()

    for attempt in range(1, settings.max_retry_attempts + 1):
        try:
            response = textract.detect_document_text(
                Document={"S3Object": {"Bucket": bucket, "Name": key}}
            )
            return _parse_text_blocks(response)
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code not in _RETRYABLE_ERRORS or attempt == settings.max_retry_attempts:
                raise TextractError(
                    f"Textract failed for s3://{bucket}/{key} after {attempt} attempt(s): "
                    f"{error_code}. Verify the object exists and is a supported format."
                ) from exc

            delay_ms = _calculate_delay_ms(attempt, settings.retry_base_delay_ms)
            log_warn(
                "textract_retry",
                attempt=attempt,
                error_code=error_code,
                delay_ms=delay_ms,
            )
            time.sleep(delay_ms / 1000)

    raise TextractError(f"Textract failed for s3://{bucket}/{key}: exhausted all retry attempts.")


def _parse_text_blocks(response: dict[str, Any]) -> str:
    """
    Extract LINE block text from a Textract DetectDocumentText response.

    Args:
        response: Raw boto3 Textract response dict.

    Returns:
        Newline-joined string of all LINE block text values.
    """
    blocks = response.get("Blocks", [])
    lines = [
        block["Text"] for block in blocks if block.get("BlockType") == "LINE" and block.get("Text")
    ]
    return "\n".join(lines)


def _calculate_delay_ms(attempt: int, base_delay_ms: int) -> int:
    """
    Calculate exponential backoff delay.

    Args:
        attempt: Current attempt number (1-indexed).
        base_delay_ms: Base delay in milliseconds from Settings.

    Returns:
        Delay in milliseconds.
    """
    return int(base_delay_ms * (2 ** (attempt - 1)))


def _default_client() -> Any:
    """
    Create a boto3 Textract client using the Lambda execution role.

    Returns:
        boto3 Textract client.
    """
    return boto3.client("textract")
