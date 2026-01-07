from __future__ import annotations

import os

_DEFAULT_NICK_MAX_CHARS = 32


def expand_path(p: str) -> str:
    return os.path.expanduser(os.path.expandvars(p))


def normalize_nick(value, *, max_chars: int = _DEFAULT_NICK_MAX_CHARS) -> str | None:
    if not isinstance(value, str):
        return None

    s = value.strip()
    if not s:
        return None

    try:
        limit = int(max_chars)
    except Exception:
        limit = int(_DEFAULT_NICK_MAX_CHARS)

    if limit > 0 and len(s) > limit:
        return None

    if "\n" in s or "\r" in s or "\x00" in s:
        return None

    try:
        s.encode("utf-8", "strict")
    except UnicodeError:
        return None

    return s
