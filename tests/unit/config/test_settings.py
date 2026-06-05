"""Unit tests for src/config/settings.py"""

import pytest
from pydantic import ValidationError

from src.config.settings import Settings, get_settings
from src.utils.exceptions import ConfigurationError

REQUIRED_VARS: dict[str, str] = {
    "DYNAMODB_TABLE": "pii-vault-test",
    "OUTPUT_BUCKET": "pii-pipeline-output-test",
    "AUDIT_BUCKET": "pii-pipeline-audit-test",
    "INPUT_BUCKET": "pii-pipeline-input-test",
    "ANTHROPIC_SECRET_NAME": "pii-pipeline/anthropic-api-key",
    "KMS_KEY_ARN": "arn:aws:kms:us-east-1:123456789012:key/test",
}


def _set_all(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in REQUIRED_VARS.items():
        monkeypatch.setenv(key, value)


class TestSettings:
    def test_succeeds_when_all_required_vars_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_all(monkeypatch)
        result = Settings()
        assert result.DYNAMODB_TABLE == "pii-vault-test"

    def test_raises_on_missing_required_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_all(monkeypatch)
        monkeypatch.delenv("DYNAMODB_TABLE")
        with pytest.raises(ValidationError):
            Settings()

    def test_raises_on_empty_required_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_all(monkeypatch)
        monkeypatch.setenv("DYNAMODB_TABLE", "")
        with pytest.raises(ValidationError):
            Settings()

    def test_raises_on_invalid_kms_arn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_all(monkeypatch)
        monkeypatch.setenv("KMS_KEY_ARN", "not-an-arn")
        with pytest.raises(ValidationError):
            Settings()

    def test_default_lambda_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_all(monkeypatch)
        monkeypatch.delenv("LAMBDA_TIMEOUT_MS", raising=False)
        assert Settings().LAMBDA_TIMEOUT_MS == 120_000

    def test_snake_case_aliases(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_all(monkeypatch)
        result = Settings()
        assert result.dynamodb_table == result.DYNAMODB_TABLE
        assert result.kms_key_arn == result.KMS_KEY_ARN


class TestPerDocumentTimeout:
    def test_is_75_percent_of_lambda_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_all(monkeypatch)
        monkeypatch.setenv("LAMBDA_TIMEOUT_MS", "120000")
        assert Settings().per_document_timeout_ms == 90_000

    def test_is_less_than_lambda_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_all(monkeypatch)
        result = Settings()
        assert result.per_document_timeout_ms < result.LAMBDA_TIMEOUT_MS


class TestGetSettings:
    def test_raises_configuration_error_on_invalid_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        get_settings.cache_clear()
        monkeypatch.delenv("DYNAMODB_TABLE", raising=False)
        monkeypatch.delenv("OUTPUT_BUCKET", raising=False)
        with pytest.raises(ConfigurationError):
            get_settings()
        get_settings.cache_clear()
