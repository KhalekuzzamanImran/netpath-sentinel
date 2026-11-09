"""Small, rotating JSON diagnostic log with no packet-payload fields."""

from __future__ import annotations

import json
import logging
import os
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from netpath_sentinel.configuration.paths import app_data_dir


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        document: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(record, "event", record.getMessage()),
            "message": record.getMessage(),
        }
        details = getattr(record, "diagnostics", None)
        if isinstance(details, dict):
            document["diagnostics"] = details
        if record.exc_info:
            document["exception"] = "".join(traceback.format_exception(*record.exc_info))
        return json.dumps(document, ensure_ascii=True, default=str)


def diagnostic_log_path() -> Path:
    log_directory = app_data_dir() / "logs"
    log_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        log_directory.chmod(0o700)
    return log_directory / "netpath-sentinel.log"


def log_exception(
    event: str, error: BaseException, diagnostics: dict[str, Any]
) -> Path | None:
    """Append a structured exception without serializing packet contents."""
    try:
        path = diagnostic_log_path()
        logger = logging.getLogger("netpath_sentinel.diagnostics")
        logger.setLevel(logging.ERROR)
        logger.propagate = False
        for existing in list(logger.handlers):
            if getattr(existing, "baseFilename", None) != str(path):
                logger.removeHandler(existing)
                existing.close()
        if not any(getattr(handler, "baseFilename", None) == str(path) for handler in logger.handlers):
            handler = RotatingFileHandler(
                path, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
            )
            handler.setFormatter(_JsonFormatter())
            logger.addHandler(handler)
        logger.error(
            str(error),
            exc_info=(type(error), error, error.__traceback__),
            extra={"event": event, "diagnostics": diagnostics},
        )
        if os.name != "nt":
            path.chmod(0o600)
        return path
    except OSError:
        return None
