from rrcd.codec import decode, encode
from rrcd.constants import T_MSG
from rrcd.envelope import make_envelope, validate_envelope


def test_codec_round_trip() -> None:
    env = make_envelope(T_MSG, src=b"peer", room="#general", body="hello")
    data = encode(env)
    decoded = decode(data)
    assert decoded == env
    validate_envelope(decoded)
