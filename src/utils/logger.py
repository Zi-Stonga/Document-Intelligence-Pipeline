"""
Structured JSON logger for the PII processing pipeline.

Emits log events as JSON objects parseable by CloudWatch Metric Filters
and Athena queries. No raw PII values are ever included in log output.

Uses the standard logging module with a module-level logger.
No print() calls anywhere in production code.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _build_log_record(level: str, message: str, **context: Any) -> str:
    """
    Assemble a structured JSON log record.

    Args:
        level: Log level string (INFO, WARN, ERROR, DEBUG).
        message: Human-readable event description. Must not contain PII.
        **context: Additional structured fields. Must not contain PII values.

    Returns:
        JSON string suitable for CloudWatch Logs structured queries.
    """
    record: dict[str, Any] = {
        "level": level,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "message": message,
    }
    record.update(context)
    return json.dumps(record)


def log_info(message: str, **context: Any) -> None:
    """
    Emit an INFO-level structured log event.

    Args:
        message: Event description. Must not contain PII.
        **context: Additional structured fields. Must not contain PII.
    """
    logger.info(_build_log_record("INFO", message, **context))


def log_warn(message: str, **context: Any) -> None:
    """
    Emit a WARN-level structured log event.

    Args:
        message: Warning description. Must not contain PII.
        **context: Additional structured fields. Must not contain PII.
    """
    logger.warning(_build_log_record("WARN", message, **context))


def log_error(message: str, **context: Any) -> None:
    """
    Emit an ERROR-level structured log event.

    Args:
        message: Error description. Must not contain PII.
        **context: Additional structured fields. Must not contain PII.
    """
    logger.error(_build_log_record("ERROR", message, **context))


def log_debug(message: str, **context: Any) -> None:
    """
    Emit a DEBUG-level structured log event.

    Args:
        message: Trace description. Must not contain PII.
        **context: Additional structured fields. Must not contain PII.
    """
    logger.debug(_build_log_record("DEBUG", message, **context))
