from __future__ import annotations

import os
import time

from .constants import K_BODY, K_ID, K_NICK, K_ROOM, K_SRC, K_T, K_TS, K_V, RRC_VERSION
from .util import normalize_nick


def now_ms() -> int:
    return int(time.time() * 1000)


def msg_id() -> bytes:
    return os.urandom(8)


def make_envelope(
    msg_type: int,
    *,
    src: bytes,
    room: str | None = None,
    body=None,
    nick: str | None = None,
    mid: bytes | None = None,
    ts: int | None = None,
) -> dict:
    env: dict[int, object] = {
        K_V: RRC_VERSION,
        K_T: int(msg_type),
        K_ID: mid or msg_id(),
        K_TS: ts or now_ms(),
        K_SRC: src,
    }
    if room is not None:
        env[K_ROOM] = room
    if body is not None:
        env[K_BODY] = body
    if nick is not None:
        n = normalize_nick(nick)
        if n is not None:
            env[K_NICK] = n
    return env


def validate_envelope(env: dict) -> None:
    if not isinstance(env, dict):
        raise TypeError("envelope must be a CBOR map (dict)")

    for k in env.keys():
        if not isinstance(k, int):
            raise TypeError("envelope keys must be integers")
        if k < 0:
            raise ValueError("envelope keys must be unsigned integers")

    for k in (K_V, K_T, K_ID, K_TS, K_SRC):
        if k not in env:
            raise ValueError(f"missing envelope key {k}")

    v = env[K_V]
    if not isinstance(v, int):
        raise TypeError("protocol version must be an integer")
    if v != RRC_VERSION:
        raise ValueError(f"unsupported version {v}")

    t = env[K_T]
    if not isinstance(t, int):
        raise TypeError("message type must be an integer")

    mid = env[K_ID]
    if not isinstance(mid, (bytes, bytearray)):
        raise TypeError("message id must be bytes")

    ts = env[K_TS]
    if not isinstance(ts, int):
        raise TypeError("timestamp must be an integer")
    if ts < 0:
        raise ValueError("timestamp must be unsigned")

    src = env[K_SRC]
    if not isinstance(src, (bytes, bytearray)):
        raise TypeError("sender identity must be bytes")

    if K_ROOM in env:
        room = env[K_ROOM]
        if not isinstance(room, str):
            raise TypeError("room name must be a string")
        # Per RRC spec, room field may be empty (e.g., for hub commands)

    if K_NICK in env:
        nick = env[K_NICK]
        if not isinstance(nick, str):
            raise TypeError("nickname must be a string")
        # Per spec, nicknames are advisory and may be empty or "ridiculous".
        # Type-check only; implementations may sanitize/ignore for display.
