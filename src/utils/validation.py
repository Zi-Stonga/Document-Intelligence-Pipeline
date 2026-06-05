"""
Input validation for the PII processing pipeline.

All functions are pure: no side effects, no AWS calls, no state mutation.
Validation runs as the absolute first step before any AWS API call is made.
"""

import os

from src.utils.exceptions import ValidationError

MAX_KEY_LENGTH = 1024
REQUIRED_KEY_PREFIX = "incoming/"


def validate_inputs(source_bucket: str, source_key: str) -> None:
    """
    Validate the source bucket and key from an SQS message before any processing.

    Args:
        source_bucket: The S3 bucket name from the SQS event.
        source_key: The S3 object key from the SQS event.

    Raises:
        ValidationError: If any validation rule fails.
    """
    if not source_bucket or not isinstance(source_bucket, str):
        raise ValidationError(
            "source_bucket is missing or not a string. "
            "Check that the SQS message contains a valid S3 event."
        )

    expected_bucket = os.environ.get("INPUT_BUCKET", "")
    if expected_bucket and source_bucket != expected_bucket:
        raise ValidationError(
            f"source_bucket '{source_bucket}' does not match expected "
            f"INPUT_BUCKET '{expected_bucket}'. "
            "Check that the S3 event notification is wired to the correct bucket."
        )

    if not source_key or not isinstance(source_key, str):
        raise ValidationError(
            "source_key is missing or not a string. "
            "Check that the SQS message contains a valid S3 event."
        )

    if not source_key.startswith(REQUIRED_KEY_PREFIX):
        raise ValidationError(
            f"source_key '{source_key}' must start with '{REQUIRED_KEY_PREFIX}'. "
            "Upload documents to the incoming/ prefix only."
        )

    if ".." in source_key:
        raise ValidationError(
            f"source_key '{source_key}' contains a path traversal sequence. "
            "Object keys must not contain '..'."
        )

    if len(source_key) > MAX_KEY_LENGTH:
        raise ValidationError(
            f"source_key length {len(source_key)} exceeds maximum {MAX_KEY_LENGTH}. "
            "Use a shorter file path."
        )


def make_output_key(source_key: str) -> str:
    """
    Convert an incoming/ source key to a processed/ output key.

    Args:
        source_key: The original S3 object key.

    Returns:
        S3 key string with processed/ prefix.
    """
    stripped = source_key.removeprefix(REQUIRED_KEY_PREFIX)
    return f"processed/{stripped}"
