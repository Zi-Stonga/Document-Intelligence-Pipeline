"""Unit tests for src/services/secrets.py"""

import json
import time
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from src.services import secrets as secrets_module
from src.utils.exceptions import SecretRetrievalError


def _sm_response(api_key: str) -> dict:
    return {"SecretString": json.dumps({"api_key": api_key})}


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "GetSecretValue")


class TestGetApiKey:
    def setup_method(self) -> None:
        secrets_module._cache = None

    def test_returns_key_on_cache_miss(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = _sm_response("sk-ant-test-key")
        # Act
        result = secrets_module.get_api_key(settings, client=mock_client)
        # Assert
        assert result == "sk-ant-test-key"
        mock_client.get_secret_value.assert_called_once()

    def test_returns_cached_value_on_cache_hit(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = _sm_response("sk-ant-cached")
        # Act
        first = secrets_module.get_api_key(settings, client=mock_client)
        second = secrets_module.get_api_key(settings, client=mock_client)
        # Assert
        assert first == second == "sk-ant-cached"
        assert mock_client.get_secret_value.call_count == 1

    def test_refreshes_after_ttl_expires(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = _sm_response("sk-ant-new")
        secrets_module._cache = secrets_module._CacheEntry(
            value="sk-ant-old",
            fetched_at=time.monotonic() - (settings.secret_cache_ttl_seconds + 1),
        )
        # Act
        result = secrets_module.get_api_key(settings, client=mock_client)
        # Assert
        assert result == "sk-ant-new"

    def test_raises_on_placeholder_value(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = _sm_response("REPLACE_BEFORE_USE")
        # Act
        with pytest.raises(SecretRetrievalError) as exc_info:
            secrets_module.get_api_key(settings, client=mock_client)
        # Assert
        assert "placeholder" in str(exc_info.value).lower()

    def test_raises_on_invalid_json(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {"SecretString": "not-json"}
        # Act
        with pytest.raises(SecretRetrievalError) as exc_info:
            secrets_module.get_api_key(settings, client=mock_client)
        # Assert
        assert "json" in str(exc_info.value).lower()

    def test_raises_on_aws_client_error(self, settings) -> None:
        # Arrange
        mock_client = MagicMock()
        mock_client.get_secret_value.side_effect = _client_error("ResourceNotFoundException")
        # Act
        with pytest.raises(SecretRetrievalError) as exc_info:
            secrets_module.get_api_key(settings, client=mock_client)
        # Assert
        assert "ResourceNotFoundException" in str(exc_info.value)
