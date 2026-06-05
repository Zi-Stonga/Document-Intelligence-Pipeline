"""
Cryptographic utility functions for the PII processing pipeline.

All functions are pure: no side effects, no state mutation, deterministic output.
"""

import hashlib


def sha256_hex(value: str) -> str:
    """
    Compute the SHA-256 hash of a string and return it as a hex digest.

    Used to produce document_id (hash of source S3 key) and source_key_hash
    (chain-of-custody reference stored in audit records).

    Args:
        value: String to hash. Must not be empty.

    Returns:
        64-character lowercase hexadecimal string.

    Raises:
        ValueError: If value is empty.
    """
    if not value:
        raise ValueError("Cannot hash an empty string")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
