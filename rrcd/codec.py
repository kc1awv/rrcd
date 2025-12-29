from __future__ import annotations

import cbor2


def encode(obj) -> bytes:
    return cbor2.dumps(obj)


def decode(b: bytes):
    return cbor2.loads(b)
