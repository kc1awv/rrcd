from __future__ import annotations

import os

from .constants import NICK_MAX_CHARS


def expand_path(p: str) -> str:
    return os.path.expanduser(os.path.expandvars(p))


def normalize_nick(value) -> str | None:
    if not isinstance(value, str):
        return None

    s = value.strip()
    if not s:
        return None

    if len(s) > int(NICK_MAX_CHARS):
        return None

    # Keep this conservative: avoid embedded newlines or NUL, which frequently
    # cause UI/log formatting issues.
    if "\n" in s or "\r" in s or "\x00" in s:
        return None

    try:
        s.encode("utf-8", "strict")
    except UnicodeError:
        return None

    return s
