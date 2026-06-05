"""
Data model for a DynamoDB pii-vault record.

PiiRecord is the write shape for DynamoDB. Produced by src/services/vault.py.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PiiRecord:
    """
    A single DynamoDB item in the pii-vault table.

    The composite key (document_id, version) ensures each processing attempt
    for a given document is stored as a separate record. ConditionalCheckFailed
    on write means the exact same (document_id, version) already exists and
    is treated as an idempotent skip.
    """

    document_id: str
    """SHA-256 of source_key. HASH key. Stable across retries."""

    version: int
    """Epoch milliseconds at processing time. RANGE key. Unique per attempt."""

    source_key: str
    """Original S3 object key, e.g. incoming/report.pdf."""

    source_bucket: str
    """Source S3 bucket name."""

    source_key_hash: str
    """SHA-256 of source_key. Chain-of-custody reference in audit records."""

    pii_counts: str
    """JSON-encoded counts dict. Contains counts only, not PII values."""

    pii_data: str
    """JSON-encoded PiiClassification. SSNs must be masked before this is set."""

    processed_at: str
    """ISO 8601 timestamp of when processing completed."""

    duration_ms: int
    """Wall-clock time from handler entry to DynamoDB write in milliseconds."""

    expires_at: int
    """Unix epoch seconds. DynamoDB TTL attribute. 365 days from now."""

    def to_dynamodb_item(self) -> dict[str, dict[str, str]]:
        """
        Serialize to the DynamoDB item format expected by boto3 PutItem.

        Returns:
            Dict with DynamoDB type annotations for boto3 DynamoDB client.
        """
        return {
            "document_id": {"S": self.document_id},
            "version": {"N": str(self.version)},
            "source_key": {"S": self.source_key},
            "source_bucket": {"S": self.source_bucket},
            "source_key_hash": {"S": self.source_key_hash},
            "pii_counts": {"S": self.pii_counts},
            "pii_data": {"S": self.pii_data},
            "processed_at": {"S": self.processed_at},
            "duration_ms": {"N": str(self.duration_ms)},
            "expires_at": {"N": str(self.expires_at)},
        }
