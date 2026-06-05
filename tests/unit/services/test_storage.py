"""Unit tests for src/services/storage.py"""

import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from src.services.storage import write_audit, write_output
from src.utils.exceptions import StorageWriteError

DOC_ID = "abc123"
VERSION = 1_700_000_000_000
OUTPUT_KEY = "processed/report.pdf"
SOURCE_BUCKET = "pii-pipeline-input-test"
SOURCE_KEY_HASH = "hash123"
EXPIRES_AT = 1_731_536_000
START_MS = 1_700_000_000_000


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "PutObject")


class TestWriteOutput:
    def test_calls_put_object_on_output_bucket(self, settings, full_classification) -> None:
        # Arrange
        mock_client = MagicMock()
        # Act
        write_output(DOC_ID, VERSION, full_classification, OUTPUT_KEY, settings, client=mock_client)
        # Assert
        assert mock_client.put_object.call_args[1]["Bucket"] == settings.output_bucket

    def test_body_contains_counts_not_pii_data(self, settings, full_classification) -> None:
        # Arrange
        mock_client = MagicMock()
        # Act
        write_output(DOC_ID, VERSION, full_classification, OUTPUT_KEY, settings, client=mock_client)
        # Assert
        body = json.loads(mock_client.put_object.call_args[1]["Body"].decode())
        assert "pii_counts" in body
        assert "pii_data" not in body

    def test_uses_kms_encryption(self, settings, full_classification) -> None:
        # Arrange
        mock_client = MagicMock()
        # Act
        write_output(DOC_ID, VERSION, full_classification, OUTPUT_KEY, settings, client=mock_client)
        # Assert
        kwargs = mock_client.put_object.call_args[1]
        assert kwargs["ServerSideEncryption"] == "aws:kms"
        assert kwargs["SSEKMSKeyId"] == settings.kms_key_arn

    def test_raises_storage_write_error_after_retries(self, settings, full_classification) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.put_object.side_effect = _client_error("ThrottlingException")
        # Act
        with pytest.raises(StorageWriteError):
            write_output(
                DOC_ID, VERSION, full_classification, OUTPUT_KEY, settings, client=mock_client
            )


class TestWriteAudit:
    def test_calls_put_object_on_audit_bucket(self, settings, full_classification) -> None:
        # Arrange
        mock_client = MagicMock()
        # Act
        write_audit(
            DOC_ID,
            VERSION,
            SOURCE_KEY_HASH,
            SOURCE_BUCKET,
            full_classification,
            EXPIRES_AT,
            START_MS,
            settings,
            client=mock_client,
        )
        # Assert
        assert mock_client.put_object.call_args[1]["Bucket"] == settings.audit_bucket

    def test_audit_key_under_lambda_audit_prefix(self, settings, full_classification) -> None:
        # Arrange
        mock_client = MagicMock()
        # Act
        write_audit(
            DOC_ID,
            VERSION,
            SOURCE_KEY_HASH,
            SOURCE_BUCKET,
            full_classification,
            EXPIRES_AT,
            START_MS,
            settings,
            client=mock_client,
        )
        # Assert
        key = mock_client.put_object.call_args[1]["Key"]
        assert key.startswith("lambda-audit/")
        assert DOC_ID in key

    def test_audit_body_excludes_pii_data(self, settings, full_classification) -> None:
        # Arrange
        mock_client = MagicMock()
        # Act
        write_audit(
            DOC_ID,
            VERSION,
            SOURCE_KEY_HASH,
            SOURCE_BUCKET,
            full_classification,
            EXPIRES_AT,
            START_MS,
            settings,
            client=mock_client,
        )
        # Assert
        body = json.loads(mock_client.put_object.call_args[1]["Body"].decode())
        assert "pii_data" not in body
        assert "pii_counts" in body
        assert "source_key_hash" in body
