"""
Shared pytest fixtures for the PII processing pipeline test suite.

Fixtures defined here are available to all test modules without import.
Each fixture has a docstring explaining what it provides and why.
"""

import pytest

from src.config.settings import Settings, get_settings
from src.models.pii_result import OtherPiiItem, PiiClassification

REQUIRED_ENV: dict[str, str] = {
    "DYNAMODB_TABLE": "pii-vault-test",
    "OUTPUT_BUCKET": "pii-pipeline-output-test",
    "AUDIT_BUCKET": "pii-pipeline-audit-test",
    "INPUT_BUCKET": "pii-pipeline-input-test",
    "ANTHROPIC_SECRET_NAME": "pii-pipeline/anthropic-api-key",
    "KMS_KEY_ARN": "arn:aws:kms:us-east-1:123456789012:key/test-key-id",
    "AWS_REGION": "us-east-1",
    "LAMBDA_TIMEOUT_MS": "120000",
    "ANTHROPIC_MODEL": "claude-opus-4-5",
}


@pytest.fixture(autouse=True)
def clear_settings_cache() -> None:
    """
    Clear the get_settings lru_cache before every test.

    get_settings uses lru_cache so it only reads the environment once per
    process. Without clearing the cache between tests, monkeypatched env
    vars have no effect on tests that run after the first Settings instance
    is created. This fixture runs automatically for every test.
    """
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """
    Provide a fully configured Settings instance for unit tests.

    All required environment variables are set to safe test values.
    Automatically restored after each test.

    Returns:
        Settings instance populated with test values.
    """
    for key, value in REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)
    return Settings()


@pytest.fixture
def empty_classification() -> PiiClassification:
    """
    Provide a PiiClassification with no PII found and no error.

    Returns:
        PiiClassification with all fields empty.
    """
    return PiiClassification()


@pytest.fixture
def full_classification() -> PiiClassification:
    """
    Provide a PiiClassification with one item in every category.

    SSNs are in masked format as they would be after mask_ssns().

    Returns:
        PiiClassification with one item per category.
    """
    return PiiClassification(
        names=["Jane Smith"],
        emails=["jane@example.com"],
        phones=["+1-555-555-5555"],
        ssns=["XXX-XX-6789"],
        addresses=["123 Main St, Springfield, IL 62701"],
        dates_of_birth=["01/15/1980"],
        other_pii=[OtherPiiItem(type="ACCOUNT_NUMBER", value="4111-1111-1111-1111")],
    )


@pytest.fixture
def raw_classification() -> PiiClassification:
    """
    Provide a PiiClassification with a raw unmasked SSN value.

    Use for tests that verify masking is applied before storage.

    Returns:
        PiiClassification with raw SSN value 123-45-6789.
    """
    return PiiClassification(names=["Jane Smith"], ssns=["123-45-6789"])


@pytest.fixture
def parse_error_classification() -> PiiClassification:
    """
    Provide a PiiClassification representing a model parse failure.

    Returns:
        PiiClassification with parse_error=True and all arrays empty.
    """
    return PiiClassification.parse_error_result()
