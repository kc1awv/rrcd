from __future__ import annotations

import os

_DEFAULT_NICK_MAX_BYTES = 32


def expand_path(p: str) -> str:
    return os.path.expanduser(os.path.expandvars(p))


def normalize_nick(value, *, max_bytes: int = _DEFAULT_NICK_MAX_BYTES) -> str | None:
    if not isinstance(value, str):
        return None

    s = value.strip()
    if not s:
        return None

    try:
        limit = int(max_bytes)
    except Exception:
        limit = int(_DEFAULT_NICK_MAX_BYTES)

    # Check UTF-8 byte length
    try:
        encoded = s.encode("utf-8", "strict")
    except UnicodeError:
        return None

    if limit > 0 and len(encoded) > limit:
        return None

    if "\n" in s or "\r" in s or "\x00" in s:
        return None

    return s
