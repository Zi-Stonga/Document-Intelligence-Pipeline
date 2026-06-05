"""Unit tests for src/services/textract.py"""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from src.services.textract import extract_text
from src.utils.exceptions import TextractError

BUCKET = "pii-pipeline-input-test"
KEY = "incoming/report.pdf"


def _textract_response(*lines: str) -> dict:
    return {"Blocks": [{"BlockType": "LINE", "Text": line} for line in lines]}


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "DetectDocumentText")


class TestExtractText:
    def test_returns_joined_lines_on_success(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.detect_document_text.return_value = _textract_response("Line 1", "Line 2")
        # Act
        result = extract_text(BUCKET, KEY, settings, client=mock_client)
        # Assert
        assert result == "Line 1\nLine 2"

    def test_returns_empty_string_for_no_blocks(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.detect_document_text.return_value = {"Blocks": []}
        # Act / Assert
        assert extract_text(BUCKET, KEY, settings, client=mock_client) == ""

    def test_filters_non_line_block_types(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.detect_document_text.return_value = {
            "Blocks": [
                {"BlockType": "PAGE", "Text": "ignored"},
                {"BlockType": "LINE", "Text": "kept"},
            ]
        }
        # Act
        result = extract_text(BUCKET, KEY, settings, client=mock_client)
        # Assert
        assert result == "kept"

    def test_retries_on_throttling_exception(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.detect_document_text.side_effect = [
            _client_error("ThrottlingException"),
            _textract_response("After retry"),
        ]
        # Act
        result = extract_text(BUCKET, KEY, settings, client=mock_client)
        # Assert
        assert result == "After retry"
        assert mock_client.detect_document_text.call_count == 2

    def test_raises_textract_error_after_all_retries(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.detect_document_text.side_effect = _client_error("ThrottlingException")
        # Act
        with pytest.raises(TextractError):
            extract_text(BUCKET, KEY, settings, client=mock_client)
        # Assert
        assert mock_client.detect_document_text.call_count == settings.max_retry_attempts

    def test_raises_immediately_on_non_retryable_error(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.detect_document_text.side_effect = _client_error("AccessDeniedException")
        # Act
        with pytest.raises(TextractError):
            extract_text(BUCKET, KEY, settings, client=mock_client)
        # Assert
        assert mock_client.detect_document_text.call_count == 1
