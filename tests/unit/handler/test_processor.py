"""Unit tests for src/handler/processor.py"""

import json
import os
import urllib.parse
from unittest.mock import patch

import pytest

# Set required env vars before processor.py is imported.
# processor.py calls get_settings() at module level on import.
# These must be set before the first import of the module.
os.environ.setdefault("DYNAMODB_TABLE", "pii-vault-test")
os.environ.setdefault("OUTPUT_BUCKET", "pii-pipeline-output-test")
os.environ.setdefault("AUDIT_BUCKET", "pii-pipeline-audit-test")
os.environ.setdefault("INPUT_BUCKET", "pii-pipeline-input-test")
os.environ.setdefault("ANTHROPIC_SECRET_NAME", "pii-pipeline/anthropic-api-key")
os.environ.setdefault("KMS_KEY_ARN", "arn:aws:kms:us-east-1:123456789012:key/test-key-id")

from src.utils.exceptions import ValidationError

VALID_BUCKET = "pii-pipeline-input-123456789012"
VALID_KEY = "incoming/report.pdf"


def _s3_record(bucket: str, key: str, message_id: str = "msg-1") -> dict:
    body = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": bucket},
                    "object": {"key": urllib.parse.quote_plus(key)},
                }
            }
        ]
    }
    return {"messageId": message_id, "body": json.dumps(body)}


def _direct_record(bucket: str, key: str, message_id: str = "msg-1") -> dict:
    return {"messageId": message_id, "body": json.dumps({"bucket": bucket, "key": key})}


class TestParseS3Event:
    def test_parses_standard_s3_event(self) -> None:
        from src.handler import processor

        bucket, key = processor._parse_s3_event(_s3_record(VALID_BUCKET, VALID_KEY))
        assert bucket == VALID_BUCKET
        assert key == VALID_KEY

    def test_url_decodes_s3_key(self) -> None:
        from src.handler import processor

        key_with_space = "incoming/my report.pdf"
        _, key = processor._parse_s3_event(_s3_record(VALID_BUCKET, key_with_space))
        assert key == key_with_space

    def test_parses_direct_injection_format(self) -> None:
        from src.handler import processor

        bucket, key = processor._parse_s3_event(_direct_record(VALID_BUCKET, VALID_KEY))
        assert bucket == VALID_BUCKET
        assert key == VALID_KEY

    def test_raises_on_invalid_json_body(self) -> None:
        from src.handler import processor

        with pytest.raises(ValidationError) as exc_info:
            processor._parse_s3_event({"messageId": "msg-1", "body": "not-json"})
        assert "json" in str(exc_info.value).lower()

    def test_raises_on_unrecognised_format(self) -> None:
        from src.handler import processor

        with pytest.raises(ValidationError):
            processor._parse_s3_event(
                {"messageId": "msg-1", "body": json.dumps({"unexpected": "format"})}
            )


@patch("src.handler.processor._settings")
class TestHandler:
    @patch("src.handler.processor.write_audit")
    @patch("src.handler.processor.write_output")
    @patch("src.handler.processor.write_vault_record")
    @patch("src.handler.processor.mask_ssns")
    @patch("src.handler.processor.classify_pii")
    @patch("src.handler.processor.get_api_key")
    @patch("src.handler.processor.extract_text")
    @patch("src.handler.processor.validate_inputs")
    def test_returns_empty_failures_on_success(
        self,
        mock_validate,
        mock_extract,
        mock_api_key,
        mock_classify,
        mock_mask,
        mock_vault,
        mock_output,
        mock_audit,
        mock_settings,
    ) -> None:
        """
        All service functions mocked so no real AWS or HTTP calls are made.
        validate_inputs, extract_text, get_api_key, classify_pii, mask_ssns,
        write_vault_record, write_output, write_audit all stand in for real services.
        """
        # Arrange
        from src.handler import processor
        from src.models.pii_result import PiiClassification

        mock_extract.return_value = "some extracted text"
        mock_api_key.return_value = "test-api-key-fake"
        mock_classify.return_value = PiiClassification(names=["Jane"])
        mock_mask.return_value = PiiClassification(names=["Jane"])
        mock_vault.return_value = True
        event = {"Records": [_direct_record(VALID_BUCKET, VALID_KEY)]}
        # Act
        result = processor.handler(event, context=None)
        # Assert
        assert result == {"batchItemFailures": []}

    @patch("src.handler.processor.extract_text")
    @patch("src.handler.processor.validate_inputs")
    def test_adds_failed_record_to_failures(
        self,
        mock_validate,
        mock_extract,
        mock_settings,
    ) -> None:
        """extract_text mocked to raise TextractError without real AWS calls."""
        # Arrange
        from src.handler import processor
        from src.utils.exceptions import TextractError

        mock_extract.side_effect = TextractError("Textract unavailable")
        event = {"Records": [_direct_record(VALID_BUCKET, VALID_KEY, message_id="fail-msg")]}
        # Act
        result = processor.handler(event, context=None)
        # Assert
        assert len(result["batchItemFailures"]) == 1
        assert result["batchItemFailures"][0]["itemIdentifier"] == "fail-msg"

    @patch("src.handler.processor.write_audit")
    @patch("src.handler.processor.write_output")
    @patch("src.handler.processor.write_vault_record")
    @patch("src.handler.processor.mask_ssns")
    @patch("src.handler.processor.classify_pii")
    @patch("src.handler.processor.get_api_key")
    @patch("src.handler.processor.extract_text")
    @patch("src.handler.processor.validate_inputs")
    def test_partial_batch_only_fails_failed_record(
        self,
        mock_validate,
        mock_extract,
        mock_api_key,
        mock_classify,
        mock_mask,
        mock_vault,
        mock_output,
        mock_audit,
        mock_settings,
    ) -> None:
        """extract_text raises on second call only to simulate partial batch failure."""
        # Arrange
        from src.handler import processor
        from src.models.pii_result import PiiClassification
        from src.utils.exceptions import TextractError

        mock_extract.side_effect = ["extracted text", TextractError("failed")]
        mock_api_key.return_value = "test-api-key-fake"
        mock_classify.return_value = PiiClassification()
        mock_mask.return_value = PiiClassification()
        mock_vault.return_value = True
        event = {
            "Records": [
                _direct_record(VALID_BUCKET, VALID_KEY, message_id="ok-msg"),
                _direct_record(VALID_BUCKET, VALID_KEY, message_id="fail-msg"),
            ]
        }
        # Act
        result = processor.handler(event, context=None)
        # Assert
        assert len(result["batchItemFailures"]) == 1
        assert result["batchItemFailures"][0]["itemIdentifier"] == "fail-msg"
