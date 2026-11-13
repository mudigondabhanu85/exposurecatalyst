"""Structured logging with secret redaction. Secrets must never reach logs or audit details."""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog

_SENSITIVE = re.compile(
    r"pass(word)?|secret|token|api[_-]?key|authorization|cookie|totp|credential|private[_-]?key|session",
    re.IGNORECASE,
)
REDACTED = "***REDACTED***"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (REDACTED if _SENSITIVE.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value


def _redact_processor(_logger, _name, event_dict):
    return redact(event_dict)


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level.upper(), force=True)
    renderer = structlog.processors.JSONRenderer() if json_logs else structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact_processor,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        cache_logger_on_first_use=True,
    )
