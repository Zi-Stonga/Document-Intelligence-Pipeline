"""Unit tests for src/services/vault.py"""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from src.models.pii_result import PiiClassification
from src.services.vault import write_vault_record
from src.utils.exceptions import VaultWriteError

SOURCE_KEY = "incoming/report.pdf"
SOURCE_BUCKET = "pii-pipeline-input-test"
START_MS = 1_700_000_000_000


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "PutItem")


class TestWriteVaultRecord:
    def test_returns_true_on_success(self, settings, empty_classification) -> None:
        # Arrange
        mock_client = MagicMock()
        # Act
        result = write_vault_record(
            SOURCE_KEY, SOURCE_BUCKET, empty_classification, START_MS, settings, client=mock_client
        )
        # Assert
        assert result is True

    def test_uses_and_condition_expression(self, settings, empty_classification) -> None:
        # Arrange
        mock_client = MagicMock()
        # Act
        write_vault_record(
            SOURCE_KEY, SOURCE_BUCKET, empty_classification, START_MS, settings, client=mock_client
        )
        # Assert
        condition = mock_client.put_item.call_args[1]["ConditionExpression"]
        assert " AND " in condition
        assert " OR " not in condition

    def test_returns_false_on_conditional_check_failed(
        self, settings, empty_classification
    ) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.put_item.side_effect = _client_error("ConditionalCheckFailedException")
        # Act
        result = write_vault_record(
            SOURCE_KEY, SOURCE_BUCKET, empty_classification, START_MS, settings, client=mock_client
        )
        # Assert
        assert result is False

    def test_retries_on_throughput_exceeded(self, settings, empty_classification) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.put_item.side_effect = [
            _client_error("ProvisionedThroughputExceededException"),
            {},
        ]
        # Act
        result = write_vault_record(
            SOURCE_KEY, SOURCE_BUCKET, empty_classification, START_MS, settings, client=mock_client
        )
        # Assert
        assert result is True
        assert mock_client.put_item.call_count == 2

    def test_raises_vault_write_error_after_retries_exhausted(
        self, settings, empty_classification
    ) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.put_item.side_effect = _client_error("ThrottlingException")
        # Act
        with pytest.raises(VaultWriteError):
            write_vault_record(
                SOURCE_KEY,
                SOURCE_BUCKET,
                empty_classification,
                START_MS,
                settings,
                client=mock_client,
            )
        # Assert
        assert mock_client.put_item.call_count == settings.max_retry_attempts

    def test_truncates_oversized_pii_data(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        large = PiiClassification(names=["X" * 1000] * 400)
        # Act
        write_vault_record(SOURCE_KEY, SOURCE_BUCKET, large, START_MS, settings, client=mock_client)
        # Assert
        written = mock_client.put_item.call_args[1]["Item"]
        assert "TRUNCATED" in written["pii_data"]["S"]
