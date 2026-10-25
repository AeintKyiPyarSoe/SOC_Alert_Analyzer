"""
app/security/logging_filter.py
Security Access Log Redaction Filter & Configuration

Provides centralized sanitization for Uvicorn, FastAPI, and standard Python loggers:
  1. Redacts sensitive authentication tickets (?ticket=wst_...) from WebSocket access logs.
  2. Redacts API keys, bearer tokens, passwords, secrets, and session cookies from HTTP access logs.
  3. Preserves useful non-sensitive operational telemetry: timestamp, client IP, path, status, and duration.
"""

import copy
import logging
import logging.config
import re
from typing import Any, Dict, Optional, Tuple, Union

# Regex patterns for redacting credentials in query strings, headers, and log messages
SENSITIVE_PARAM_REGEX = re.compile(
    r"([?&](?:ticket|token|api_key|password|secret|key|soc_session)=)([^&\s\"'`)]*)",
    re.IGNORECASE
)

BEARER_TOKEN_REGEX = re.compile(
    r"((?:Bearer|Token)\s+)[a-zA-Z0-9_\-\.]{8,}",
    re.IGNORECASE
)

STANDALONE_WS_TICKET_REGEX = re.compile(
    r"\bwst_[a-fA-F0-9]{24,}\b"
)

COOKIE_SESSION_REGEX = re.compile(
    r"(soc_session=)[a-zA-Z0-9_\-\.]{8,}",
    re.IGNORECASE
)


def redact_sensitive_string(text: str) -> str:
    """
    Sanitizes credentials from a string while preserving diagnostic context.
    Safely redacts:
      - Query params: ?ticket=wst_... -> ?ticket=[REDACTED]
      - Bearer tokens: Bearer ey... -> Bearer [REDACTED]
      - Standalone WebSocket tickets: wst_... -> wst_[REDACTED]
      - Session cookie fragments: soc_session=... -> soc_session=[REDACTED]
    """
    if not isinstance(text, str):
        return text

    # 1. Query parameters
    text = SENSITIVE_PARAM_REGEX.sub(r"\1[REDACTED]", text)

    # 2. Bearer / Token headers in logs
    text = BEARER_TOKEN_REGEX.sub(r"\1[REDACTED]", text)

    # 3. Standalone WebSocket tickets (e.g. wst_32_hex_chars)
    text = STANDALONE_WS_TICKET_REGEX.sub("wst_[REDACTED]", text)

    # 4. Session cookie tokens
    text = COOKIE_SESSION_REGEX.sub(r"\1[REDACTED]", text)

    return text


def sanitize_log_arg(arg: Any) -> Any:
    """Recursively sanitizes an argument passed to a logging call."""
    if isinstance(arg, str):
        return redact_sensitive_string(arg)
    elif isinstance(arg, tuple):
        return tuple(sanitize_log_arg(item) for item in arg)
    elif isinstance(arg, list):
        return [sanitize_log_arg(item) for item in arg]
    elif isinstance(arg, dict):
        return {k: sanitize_log_arg(v) for k, v in arg.items()}
    return arg


class SensitiveDataRedactionFilter(logging.Filter):
    """
    Logging filter that sanitizes sensitive authentication credentials
    from LogRecord message strings, argument tuples, and formatted strings.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Sanitize arguments tuple/dict
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(sanitize_log_arg(arg) for arg in record.args)
            elif isinstance(record.args, dict):
                record.args = {k: sanitize_log_arg(v) for k, v in record.args.items()}

        # Sanitize primary message format string
        if isinstance(record.msg, str):
            record.msg = redact_sensitive_string(record.msg)

        return True


def setup_security_logging():
    """
    Configures and attaches the SensitiveDataRedactionFilter to all critical
    server and application loggers and their handlers.
    Target loggers:
      - root logger
      - 'uvicorn'
      - 'uvicorn.error' (used for WebSocket '%s - "WebSocket %s" [accepted]' access logs)
      - 'uvicorn.access' (used for HTTP access logs)
      - 'app'
    """
    redaction_filter = SensitiveDataRedactionFilter()

    target_loggers = [
        logging.getLogger(),
        logging.getLogger("uvicorn"),
        logging.getLogger("uvicorn.error"),
        logging.getLogger("uvicorn.access"),
        logging.getLogger("app"),
    ]

    for log in target_loggers:
        # Attach filter to the logger itself
        if not any(isinstance(f, SensitiveDataRedactionFilter) for f in log.filters):
            log.addFilter(redaction_filter)

        # Attach filter to all existing handlers on the logger
        for handler in log.handlers:
            if not any(isinstance(f, SensitiveDataRedactionFilter) for f in handler.filters):
                handler.addFilter(redaction_filter)


def get_secure_uvicorn_log_config(log_level: str = "info") -> Dict[str, Any]:
    """
    Returns a hardened Uvicorn logging configuration dictionary with
    SensitiveDataRedactionFilter registered and attached to access and default handlers.
    """
    import uvicorn.config

    cfg = copy.deepcopy(uvicorn.config.LOGGING_CONFIG)

    # Register redaction filter in logging config dict
    cfg.setdefault("filters", {})
    cfg["filters"]["security_redaction"] = {
        "()": "app.security.logging_filter.SensitiveDataRedactionFilter",
    }

    # Attach filter to handlers
    for handler_name in ("default", "access"):
        if handler_name in cfg.get("handlers", {}):
            handler_cfg = cfg["handlers"][handler_name]
            handler_filters = handler_cfg.setdefault("filters", [])
            if "security_redaction" not in handler_filters:
                handler_filters.append("security_redaction")

    # Attach filter to loggers
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        if logger_name in cfg.get("loggers", {}):
            logger_cfg = cfg["loggers"][logger_name]
            logger_filters = logger_cfg.setdefault("filters", [])
            if "security_redaction" not in logger_filters:
                logger_filters.append("security_redaction")

    return cfg
