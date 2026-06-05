"""
Secrets Manager service for retrieving the Anthropic API key.

Implements a module-level TTL cache to avoid a Secrets Manager API call on
every Lambda invocation. The cache is shared across warm invocations of the
same Lambda instance and invalidated after secret_cache_ttl_seconds.
"""

import json
import time
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError

from src.config.settings import Settings
from src.utils.exceptions import SecretRetrievalError
from src.utils.logger import log_debug, log_info


@dataclass
class _CacheEntry:
    """In-memory cache entry for the Anthropic API key."""

    value: str
    fetched_at: float


_cache: _CacheEntry | None = None


def get_api_key(settings: Settings, client: Any = None) -> str:
    """
    Retrieve the Anthropic API key from Secrets Manager with TTL caching.

    Args:
        settings: Application settings containing secret name and cache TTL.
        client: boto3 Secrets Manager client. Injected for testability.

    Returns:
        Anthropic API key string.

    Raises:
        SecretRetrievalError: If the key cannot be retrieved or is invalid.
    """
    global _cache

    now = time.monotonic()
    if _is_cache_valid(now, settings.secret_cache_ttl_seconds):
        log_debug("api_key_cache_hit")
        return _cache.value  # type: ignore[union-attr]

    log_info("api_key_cache_miss", reason="expired_or_cold_start")
    api_key = _fetch_from_secrets_manager(settings, client or _default_client())
    _cache = _CacheEntry(value=api_key, fetched_at=now)
    return api_key


def _is_cache_valid(now: float, ttl_seconds: int) -> bool:
    """
    Check whether the module-level cache holds a valid non-expired entry.

    Args:
        now: Current monotonic time in seconds.
        ttl_seconds: Cache TTL in seconds from Settings.

    Returns:
        True if a cache entry exists and has not exceeded its TTL.
    """
    return _cache is not None and (now - _cache.fetched_at) < ttl_seconds


def _fetch_from_secrets_manager(settings: Settings, client: Any) -> str:
    """
    Retrieve and validate the API key from Secrets Manager.

    Args:
        settings: Application settings.
        client: boto3 Secrets Manager client.

    Returns:
        Validated Anthropic API key string.

    Raises:
        SecretRetrievalError: If the AWS call fails or the key is invalid.
    """
    try:
        response = client.get_secret_value(SecretId=settings.anthropic_secret_name)
    except ClientError as exc:
        raise SecretRetrievalError(
            f"Failed to retrieve secret '{settings.anthropic_secret_name}' "
            f"from Secrets Manager: {exc.response['Error']['Code']}. "
            "Verify the secret name, the Lambda IAM role has GetSecretValue on "
            "the exact secret ARN, and the CMK key policy allows Secrets Manager."
        ) from exc

    try:
        secret_dict = json.loads(response["SecretString"])
        api_key = secret_dict["api_key"]
    except (KeyError, json.JSONDecodeError) as exc:
        raise SecretRetrievalError(
            f"Secret '{settings.anthropic_secret_name}' does not contain an "
            "api_key field or is not valid JSON. "
            'Update the secret value to: {"api_key": "sk-ant-YOUR-KEY"}'
        ) from exc

    if not api_key or api_key.startswith("REPLACE_"):
        raise SecretRetrievalError(
            f"Secret '{settings.anthropic_secret_name}' contains the placeholder "
            "value. Update the secret with your real Anthropic API key."
        )

    return str(api_key)


def _default_client() -> Any:
    """
    Create a boto3 Secrets Manager client using the Lambda execution role.

    Returns:
        boto3 Secrets Manager client.
    """
    return boto3.client("secretsmanager")
