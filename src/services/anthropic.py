"""
Anthropic Claude API service for PII classification.

System prompt and user content are strictly separated in message roles.
The system prompt is hardcoded and never interpolated at runtime, preventing
prompt injection via document content.
"""

import json
import re
import time
from urllib import error as urllib_error
from urllib import request
from urllib.error import URLError

from src.config.settings import Settings
from src.models.pii_result import PiiClassification
from src.utils.exceptions import ClassificationError
from src.utils.logger import log_warn

_ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION_HEADER = "2023-06-01"
_MAX_TOKENS = 1024
_RETRYABLE_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})

_SYSTEM_PROMPT = (
    "You are a PII extraction engine. "
    "Respond only with a valid JSON object. "
    "No markdown fences. No explanation. "
    "JSON keys: names, emails, phones, ssns, addresses, dates_of_birth, "
    "other_pii (array of objects with type and value fields)."
)

_MARKDOWN_FENCE_PATTERN = re.compile(r"^```(?:json)?\s*", re.IGNORECASE)
_TRAILING_FENCE_PATTERN = re.compile(r"\s*```\s*$")


def classify_pii(
    text: str,
    api_key: str,
    settings: Settings,
) -> PiiClassification:
    """
    Call the Anthropic Claude API to classify PII in extracted document text.

    Truncates text to settings.max_text_chars before sending.
    On non-JSON model output, returns PiiClassification.parse_error_result()
    rather than raising, storing a recoverable record in DynamoDB.

    Note: SSNs in the returned object are raw. Call mask_ssns() before storage.

    Args:
        text: Extracted document text from Textract.
        api_key: Anthropic API key from Secrets Manager.
        settings: Application settings.

    Returns:
        PiiClassification with fields populated from the model response.

    Raises:
        ClassificationError: If all retry attempts fail.
    """
    truncated_text = _truncate_text(text, settings.max_text_chars)

    for attempt in range(1, settings.max_retry_attempts + 1):
        try:
            raw_response = _call_api(truncated_text, api_key, settings)
            return _parse_response(raw_response)
        except _RetryableApiError as exc:
            if attempt == settings.max_retry_attempts:
                raise ClassificationError(
                    f"Anthropic API failed after {attempt} attempt(s): {exc}. "
                    "Check status.anthropic.com and verify the API key is valid."
                ) from exc
            delay_ms = _calculate_delay_ms(attempt, settings.retry_base_delay_ms)
            log_warn("anthropic_retry", attempt=attempt, error=str(exc), delay_ms=delay_ms)
            time.sleep(delay_ms / 1000)

    raise ClassificationError("Anthropic classification exhausted all retry attempts.")


def _call_api(text: str, api_key: str, settings: Settings) -> str:
    """
    Make a single HTTP request to the Anthropic messages API.

    Args:
        text: Truncated document text to classify.
        api_key: Anthropic API key.
        settings: Application settings for model and timeout.

    Returns:
        Raw text content from the first content block.

    Raises:
        _RetryableApiError: On HTTP 429 or 5xx responses.
        ClassificationError: On non-retryable HTTP errors.
    """
    payload = json.dumps(
        {
            "model": settings.anthropic_model,
            "max_tokens": _MAX_TOKENS,
            "system": _SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": f"Extract all PII:\n\n{text}"}],
        }
    ).encode("utf-8")

    req = request.Request(
        _ANTHROPIC_MESSAGES_URL,
        data=payload,
        method="POST",
        headers={
            "x-api-key": api_key,
            "anthropic-version": _ANTHROPIC_VERSION_HEADER,
            "content-type": "application/json",
        },
    )

    try:
        with request.urlopen(req, timeout=settings.fetch_timeout_seconds) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return str(body["content"][0]["text"])
    except urllib_error.HTTPError as exc:
        if exc.code in _RETRYABLE_HTTP_STATUSES:
            raise _RetryableApiError(f"HTTP {exc.code}") from exc
        raise ClassificationError(
            f"Anthropic API returned non-retryable HTTP {exc.code}. "
            "Verify the API key is valid and has not expired."
        ) from exc
    except (URLError, TimeoutError, KeyError, IndexError) as exc:
        raise _RetryableApiError(f"Network or response error: {exc}") from exc


def _parse_response(raw_text: str) -> PiiClassification:
    """
    Parse the model response text into a PiiClassification.

    Args:
        raw_text: Raw text from the model response content block.

    Returns:
        Populated PiiClassification, or parse_error_result on JSON failure.
    """
    cleaned = _TRAILING_FENCE_PATTERN.sub("", _MARKDOWN_FENCE_PATTERN.sub("", raw_text)).strip()

    try:
        data = json.loads(cleaned)
        return PiiClassification.from_dict(data)
    except (json.JSONDecodeError, TypeError):
        log_warn("anthropic_parse_error", raw_length=len(raw_text))
        return PiiClassification.parse_error_result()


def _truncate_text(text: str, max_chars: int) -> str:
    """
    Truncate text to max_chars and append a marker if needed.

    Args:
        text: Full extracted document text.
        max_chars: Maximum characters to send to the API.

    Returns:
        Original text if within limit, or truncated text with marker.
    """
    if len(text) <= max_chars:
        return text
    log_warn("text_truncated", original_length=len(text), max_chars=max_chars)
    return text[:max_chars] + "\n[TEXT TRUNCATED]"


def _calculate_delay_ms(attempt: int, base_delay_ms: int) -> int:
    """
    Calculate exponential backoff delay.

    Args:
        attempt: Current attempt number (1-indexed).
        base_delay_ms: Base delay in milliseconds.

    Returns:
        Delay in milliseconds.
    """
    return base_delay_ms * (2 ** (attempt - 1))


class _RetryableApiError(Exception):
    """Internal exception for transient Anthropic API errors eligible for retry."""
