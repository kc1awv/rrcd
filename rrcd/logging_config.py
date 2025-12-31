from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from .config import HubRuntimeConfig


def _parse_level(value: Any, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip().upper()
    if not text:
        return default

    mapping: dict[str, int] = {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARN": logging.WARNING,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
        "NOTSET": logging.NOTSET,
    }
    if text in mapping:
        return mapping[text]

    try:
        return int(text)
    except Exception:
        return default


def _clean_optional_path(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value)
    if not s.strip():
        return None
    return s


def configure_logging(
    cfg: HubRuntimeConfig,
    *,
    override_level: str | None = None,
    override_file: str | None = None,
) -> None:
    """Configure Python logging for rrcd.

    Intended to be safe to call multiple times (e.g., on /reload).
    """

    level = _parse_level(override_level or cfg.log_level, logging.INFO)
    rns_level = _parse_level(cfg.log_rns_level, logging.WARNING)

    handlers: list[logging.Handler] = []

    if bool(cfg.log_console):
        handlers.append(logging.StreamHandler())

    log_file = _clean_optional_path(override_file) if override_file is not None else None
    if log_file is None:
        log_file = _clean_optional_path(cfg.log_file)

    if log_file:
        p = Path(os.path.expanduser(log_file))
        if p.parent:
            p.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(p, encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except Exception:
            pass
        handlers.append(file_handler)

    fmt = str(cfg.log_format).strip() if str(cfg.log_format).strip() else None
    if not fmt:
        fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"

    datefmt = _clean_optional_path(cfg.log_datefmt)

    formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)
    for h in handlers:
        h.setFormatter(formatter)

    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    for h in handlers:
        root.addHandler(h)

    root.setLevel(level)

    # Library loggers
    logging.getLogger("RNS").setLevel(rns_level)

    logging.captureWarnings(True)
