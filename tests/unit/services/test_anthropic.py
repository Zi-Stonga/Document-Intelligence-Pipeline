"""Unit tests for src/services/anthropic.py"""

import json
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from src.models.pii_result import PiiClassification
from src.services.anthropic import classify_pii
from src.utils.exceptions import ClassificationError

TEXT = "Name: Jane Smith. SSN: 123-45-6789."
API_KEY = "sk-ant-test-key"

VALID_RESPONSE = {
    "content": [
        {
            "type": "text",
            "text": json.dumps(
                {
                    "names": ["Jane Smith"],
                    "emails": [],
                    "phones": [],
                    "ssns": ["123-45-6789"],
                    "addresses": [],
                    "dates_of_birth": [],
                    "other_pii": [],
                }
            ),
        }
    ]
}


def _make_mock_response(body: dict) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(body).encode("utf-8")
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _http_error(code: int) -> HTTPError:
    return HTTPError(url="https://api.anthropic.com", code=code, msg=str(code), hdrs=None, fp=None)


class TestClassifyPii:
    @patch("src.services.anthropic.request.urlopen")
    def test_returns_classification_on_success(self, mock_urlopen, settings) -> None:
        # Arrange
        mock_urlopen.return_value = _make_mock_response(VALID_RESPONSE)
        # Act
        result = classify_pii(TEXT, API_KEY, settings)
        # Assert
        assert isinstance(result, PiiClassification)
        assert result.names == ["Jane Smith"]
        assert result.parse_error is False

    @patch("src.services.anthropic.request.urlopen")
    def test_strips_markdown_fences(self, mock_urlopen, settings) -> None:
        # Arrange
        fenced = {
            "content": [
                {
                    "type": "text",
                    "text": "```json\n"
                    + json.dumps(
                        {
                            "names": ["Bob"],
                            "emails": [],
                            "phones": [],
                            "ssns": [],
                            "addresses": [],
                            "dates_of_birth": [],
                            "other_pii": [],
                        }
                    )
                    + "\n```",
                }
            ]
        }
        mock_urlopen.return_value = _make_mock_response(fenced)
        # Act
        result = classify_pii(TEXT, API_KEY, settings)
        # Assert
        assert result.names == ["Bob"]

    @patch("src.services.anthropic.request.urlopen")
    def test_returns_parse_error_on_non_json(self, mock_urlopen, settings) -> None:
        # Arrange
        mock_urlopen.return_value = _make_mock_response(
            {"content": [{"type": "text", "text": "I cannot process this."}]}
        )
        # Act
        result = classify_pii(TEXT, API_KEY, settings)
        # Assert
        assert result.parse_error is True

    @patch("src.services.anthropic.request.urlopen")
    def test_retries_on_http_429(self, mock_urlopen, settings) -> None:
        # Arrange
        mock_urlopen.side_effect = [
            _http_error(429),
            _make_mock_response(VALID_RESPONSE),
        ]
        # Act
        result = classify_pii(TEXT, API_KEY, settings)
        # Assert
        assert result.names == ["Jane Smith"]
        assert mock_urlopen.call_count == 2

    @patch("src.services.anthropic.request.urlopen")
    def test_raises_classification_error_after_all_retries(self, mock_urlopen, settings) -> None:
        # Arrange
        mock_urlopen.side_effect = _http_error(429)
        # Act
        with pytest.raises(ClassificationError):
            classify_pii(TEXT, API_KEY, settings)
        # Assert
        assert mock_urlopen.call_count == settings.max_retry_attempts

    @patch("src.services.anthropic.request.urlopen")
    def test_raises_immediately_on_http_401(self, mock_urlopen, settings) -> None:
        # Arrange
        mock_urlopen.side_effect = _http_error(401)
        # Act
        with pytest.raises(ClassificationError):
            classify_pii(TEXT, API_KEY, settings)
        # Assert
        assert mock_urlopen.call_count == 1

    @patch("src.services.anthropic.request.urlopen")
    def test_truncates_text_before_sending(self, mock_urlopen, settings) -> None:
        # Arrange
        mock_urlopen.return_value = _make_mock_response(VALID_RESPONSE)
        long_text = "A" * (settings.max_text_chars + 1000)
        # Act
        classify_pii(long_text, API_KEY, settings)
        # Assert
        body = json.loads(mock_urlopen.call_args[0][0].data.decode())
        assert "[TEXT TRUNCATED]" in body["messages"][0]["content"]
