"""
Application configuration loaded from environment variables via pydantic-settings.

Settings is instantiated once at Lambda cold start. All required variables are
validated immediately by pydantic. If any required variable is missing, Lambda
fails with a descriptive error before processing any message.

This module is the single source of truth for environment variable names.
No other module should call os.environ or os.getenv directly.
"""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.utils.exceptions import ConfigurationError

DEFAULT_LAMBDA_TIMEOUT_MS: int = 120_000
DEFAULT_ANTHROPIC_MODEL: str = "claude-opus-4-5"
DEFAULT_PII_TTL_DAYS: int = 365
DEFAULT_MAX_TEXT_CHARS: int = 180_000
DEFAULT_MAX_PII_BYTES: int = 350_000
DEFAULT_FETCH_TIMEOUT_SECONDS: int = 45
DEFAULT_SECRET_CACHE_TTL_SECONDS: int = 900
DEFAULT_MAX_RETRY_ATTEMPTS: int = 3
DEFAULT_RETRY_BASE_DELAY_MS: int = 500


class Settings(BaseSettings):
    """
    Validated application configuration backed by environment variables.

    Pydantic-settings reads field values from the process environment.
    Required fields raise ValidationError at startup if absent or empty.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    DYNAMODB_TABLE: str = Field(description="DynamoDB table name.")
    OUTPUT_BUCKET: str = Field(description="S3 bucket for processed output.")
    AUDIT_BUCKET: str = Field(description="S3 bucket for audit records.")
    INPUT_BUCKET: str = Field(description="S3 input bucket for source validation.")
    ANTHROPIC_SECRET_NAME: str = Field(description="Secrets Manager secret name.")
    KMS_KEY_ARN: str = Field(description="Full ARN of the KMS CMK.")
    AWS_REGION: str = Field(default="us-east-1", description="AWS region.")
    LAMBDA_TIMEOUT_MS: int = Field(
        default=DEFAULT_LAMBDA_TIMEOUT_MS,
        description="Lambda timeout in ms.",
    )
    ANTHROPIC_MODEL: str = Field(
        default=DEFAULT_ANTHROPIC_MODEL,
        description="Anthropic model identifier.",
    )

    pii_ttl_days: int = Field(default=DEFAULT_PII_TTL_DAYS)
    max_text_chars: int = Field(default=DEFAULT_MAX_TEXT_CHARS)
    max_pii_bytes: int = Field(default=DEFAULT_MAX_PII_BYTES)
    fetch_timeout_seconds: int = Field(default=DEFAULT_FETCH_TIMEOUT_SECONDS)
    secret_cache_ttl_seconds: int = Field(default=DEFAULT_SECRET_CACHE_TTL_SECONDS)
    max_retry_attempts: int = Field(default=DEFAULT_MAX_RETRY_ATTEMPTS)
    retry_base_delay_ms: int = Field(default=DEFAULT_RETRY_BASE_DELAY_MS)

    @field_validator(
        "DYNAMODB_TABLE",
        "OUTPUT_BUCKET",
        "AUDIT_BUCKET",
        "INPUT_BUCKET",
        "ANTHROPIC_SECRET_NAME",
        "KMS_KEY_ARN",
        mode="before",
    )
    @classmethod
    def must_not_be_empty(cls, value: str) -> str:
        """
        Reject empty string values for required fields.

        Args:
            value: Field value from the environment.

        Returns:
            Original value if non-empty.

        Raises:
            ValueError: If value is empty or whitespace-only.
        """
        if not value or not value.strip():
            raise ValueError("Required configuration value must not be empty.")
        return value

    @field_validator("KMS_KEY_ARN", mode="before")
    @classmethod
    def must_be_valid_arn(cls, value: str) -> str:
        """
        Reject KMS_KEY_ARN values that do not look like valid ARNs.

        Args:
            value: Field value from the environment.

        Returns:
            Original value if it starts with arn:.

        Raises:
            ValueError: If value does not start with arn:.
        """
        if value and not value.startswith("arn:"):
            raise ValueError(
                f"KMS_KEY_ARN '{value}' is not a valid ARN. "
                "Expected: arn:aws:kms:region:account:key/key-id"
            )
        return value

    @property
    def per_document_timeout_ms(self) -> int:
        """
        Per-document processing timeout in milliseconds.

        Set to 75 percent of the Lambda timeout.

        Returns:
            Integer milliseconds, always less than LAMBDA_TIMEOUT_MS.
        """
        return int(self.LAMBDA_TIMEOUT_MS * 0.75)

    @property
    def dynamodb_table(self) -> str:
        """snake_case alias for DYNAMODB_TABLE."""
        return self.DYNAMODB_TABLE

    @property
    def output_bucket(self) -> str:
        """snake_case alias for OUTPUT_BUCKET."""
        return self.OUTPUT_BUCKET

    @property
    def audit_bucket(self) -> str:
        """snake_case alias for AUDIT_BUCKET."""
        return self.AUDIT_BUCKET

    @property
    def input_bucket(self) -> str:
        """snake_case alias for INPUT_BUCKET."""
        return self.INPUT_BUCKET

    @property
    def anthropic_secret_name(self) -> str:
        """snake_case alias for ANTHROPIC_SECRET_NAME."""
        return self.ANTHROPIC_SECRET_NAME

    @property
    def kms_key_arn(self) -> str:
        """snake_case alias for KMS_KEY_ARN."""
        return self.KMS_KEY_ARN

    @property
    def anthropic_model(self) -> str:
        """snake_case alias for ANTHROPIC_MODEL."""
        return self.ANTHROPIC_MODEL

    @property
    def lambda_timeout_ms(self) -> int:
        """snake_case alias for LAMBDA_TIMEOUT_MS."""
        return self.LAMBDA_TIMEOUT_MS


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the singleton Settings instance, constructing it on first call.

    Cached via lru_cache so environment is read and validated exactly once
    per process lifetime.

    Returns:
        Validated Settings instance.

    Raises:
        ConfigurationError: If any required environment variable is missing
            or invalid.
    """
    try:
        return Settings()  # type: ignore[call-arg]
    except Exception as exc:
        raise ConfigurationError(
            f"Configuration validation failed at startup: {exc}. "
            "Verify all required environment variables are set in the "
            "Lambda function configuration."
        ) from exc
