import pytest

from rrcd.constants import (
    B_HELLO_NICK,
    K_BODY,
    K_ID,
    K_SRC,
    K_T,
    K_TS,
    K_V,
    RRC_VERSION,
    T_HELLO,
)
from rrcd.envelope import make_envelope, validate_envelope


def test_validate_accepts_make_envelope() -> None:
    env = make_envelope(T_HELLO, src=b"peer", body={B_HELLO_NICK: "alice"})
    validate_envelope(env)


def test_validate_rejects_missing_required_key() -> None:
    env = make_envelope(T_HELLO, src=b"peer", body=None)
    env.pop(K_TS)
    with pytest.raises(ValueError):
        validate_envelope(env)


def test_validate_rejects_wrong_version() -> None:
    env = make_envelope(T_HELLO, src=b"peer", body=None)
    env[K_V] = RRC_VERSION + 1
    with pytest.raises(ValueError):
        validate_envelope(env)


def test_validate_rejects_non_integer_keys() -> None:
    env = make_envelope(T_HELLO, src=b"peer", body=None)
    env["1"] = env.pop(K_T)
    with pytest.raises(TypeError):
        validate_envelope(env)


def test_validate_allows_unknown_extension_keys() -> None:
    env = make_envelope(T_HELLO, src=b"peer", body=None)
    env[64] = {"future": True}
    validate_envelope(env)


def test_validate_allows_omitted_body() -> None:
    env = make_envelope(T_HELLO, src=b"peer", body=None)
    assert K_BODY not in env
    validate_envelope(env)


def test_validate_rejects_wrong_field_types() -> None:
    env = make_envelope(T_HELLO, src=b"peer", body=None)
    env[K_ID] = "not-bytes"
    with pytest.raises(TypeError):
        validate_envelope(env)

    env = make_envelope(T_HELLO, src=b"peer", body=None)
    env[K_SRC] = "not-bytes"
    with pytest.raises(TypeError):
        validate_envelope(env)

    env = make_envelope(T_HELLO, src=b"peer", body=None)
    env[K_TS] = "not-int"
    with pytest.raises(TypeError):
        validate_envelope(env)
