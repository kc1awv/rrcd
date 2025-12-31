"""Tests for resource transfer functionality."""
import hashlib
import os

from rrcd.codec import decode, encode
from rrcd.constants import (
    B_RES_ENCODING,
    B_RES_ID,
    B_RES_KIND,
    B_RES_SHA256,
    B_RES_SIZE,
    K_BODY,
    K_SRC,
    K_T,
    RES_KIND_NOTICE,
    T_RESOURCE_ENVELOPE,
)
from rrcd.envelope import make_envelope


def test_resource_envelope_serialization():
    """Test that resource envelopes can be created and serialized."""
    src = os.urandom(16)
    rid = os.urandom(8)
    payload = b"This is a test payload that is larger than typical MDU"
    sha256 = hashlib.sha256(payload).digest()
    
    body = {
        B_RES_ID: rid,
        B_RES_KIND: RES_KIND_NOTICE,
        B_RES_SIZE: len(payload),
        B_RES_SHA256: sha256,
        B_RES_ENCODING: "utf-8",
    }
    
    envelope = make_envelope(
        T_RESOURCE_ENVELOPE,
        src=src,
        room="test",
        body=body,
    )
    
    # Serialize and deserialize
    encoded = encode(envelope)
    decoded = decode(encoded)
    
    assert decoded[K_T] == T_RESOURCE_ENVELOPE
    assert decoded[K_SRC] == src
    
    decoded_body = decoded[K_BODY]
    assert decoded_body[B_RES_ID] == rid
    assert decoded_body[B_RES_KIND] == RES_KIND_NOTICE
    assert decoded_body[B_RES_SIZE] == len(payload)
    assert decoded_body[B_RES_SHA256] == sha256
    assert decoded_body[B_RES_ENCODING] == "utf-8"


def test_resource_envelope_minimal():
    """Test resource envelope with minimal required fields."""
    src = os.urandom(16)
    rid = os.urandom(8)
    
    body = {
        B_RES_ID: rid,
        B_RES_KIND: "blob",
        B_RES_SIZE: 1024,
    }
    
    envelope = make_envelope(
        T_RESOURCE_ENVELOPE,
        src=src,
        body=body,
    )
    
    encoded = encode(envelope)
    decoded = decode(encoded)
    
    decoded_body = decoded[K_BODY]
    assert B_RES_SHA256 not in decoded_body
    assert B_RES_ENCODING not in decoded_body
    assert decoded_body[B_RES_SIZE] == 1024


def test_sha256_verification():
    """Test SHA256 hash computation for payload verification."""
    payload = b"Test payload for SHA256 verification"
    expected = hashlib.sha256(payload).digest()
    
    # Verify we can compute and compare hashes correctly
    computed = hashlib.sha256(payload).digest()
    assert computed == expected
    assert len(computed) == 32
    
    # Verify mismatch detection
    wrong_payload = b"Different payload"
    wrong_hash = hashlib.sha256(wrong_payload).digest()
    assert wrong_hash != expected
