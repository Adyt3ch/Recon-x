"""Logging configuration and secret redaction filter for RECON-X."""

from __future__ import annotations

import logging
import re
from pathlib import Path

# Sensitive pattern regexes for redacting secrets from logs and reports
REDACTION_PATTERNS = [
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]+"),
    re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+"),
    re.compile(r"(?i)(token|api[_-]?key|auth[_-]?token|secret|password)=([^\s&]+)"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{35}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]


def redact_secrets(text: str) -> str:
    """Mask known secret patterns in a string."""
    if not isinstance(text, str):
        return text

    redacted = text
    for pattern in REDACTION_PATTERNS:
        # If pattern has groups (e.g. key=value)
        if pattern.groups > 0:
            redacted = pattern.sub(r"\1=[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


class SecretRedactingFilter(logging.Filter):
    """Logging filter that redacts credentials and API secrets from all records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact_secrets(v) if isinstance(v, str) else v for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(redact_secrets(v) if isinstance(v, str) else v for v in record.args)
        return True


def setup_logging(
    log_file: Path | str | None = None,
    log_level: int = logging.INFO,
) -> logging.Logger:
    """Configure root reconx logger with redaction filter and file/console handlers."""
    logger = logging.getLogger("reconx")
    logger.setLevel(log_level)

    # Avoid duplicate handlers on re-initialization
    if not logger.handlers:
        redaction_filter = SecretRedactingFilter()

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(log_level)
        ch.addFilter(redaction_filter)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        # File handler
        if log_file:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(str(path), encoding="utf-8")
            fh.setLevel(log_level)
            fh.addFilter(redaction_filter)
            fh.setFormatter(formatter)
            logger.addHandler(fh)

    return logger
