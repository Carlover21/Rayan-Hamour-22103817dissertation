"""Unit tests for the simplified SecOC authentication module."""

from __future__ import annotations

from carnet.security.secoc import SecOCContext, derive_id_key


def test_protected_frame_verifies():
    ctx = SecOCContext(b"test-master-key")
    frame = ctx.protect(0x100, b"\x01\x02\x03\x04")
    ok, reason = ctx.verify(0x100, frame)
    assert ok
    assert reason == "ok"


def test_tampered_payload_fails_verification():
    ctx = SecOCContext(b"test-master-key")
    frame = bytearray(ctx.protect(0x100, b"\x01\x02\x03\x04"))
    frame[0] ^= 0xFF  # flip a payload bit after the MAC was computed
    ok, reason = ctx.verify(0x100, bytes(frame))
    assert not ok
    assert reason == "mac_invalid"


def test_forged_frame_without_key_fails():
    ctx = SecOCContext(b"test-master-key")
    # an attacker without the key can only guess a truncated 3-byte MAC
    forged = b"\xff\xff\xff\xff\x00\xaa\xbb\xcc"
    ok, reason = ctx.verify(0x100, forged)
    assert not ok
    assert reason == "mac_invalid"


def test_replayed_frame_fails_freshness():
    ctx = SecOCContext(b"test-master-key")
    frame = ctx.protect(0x200, b"\x00\x00\x00\x00")
    ok1, _ = ctx.verify(0x200, frame)
    ok2, reason2 = ctx.verify(0x200, frame)  # exact same frame replayed
    assert ok1
    assert not ok2
    assert reason2 == "replay_counter"


def test_sequential_frames_all_verify():
    ctx = SecOCContext(b"test-master-key")
    for i in range(10):
        frame = ctx.protect(0x300, bytes([i, 0, 0, 0]))
        ok, reason = ctx.verify(0x300, frame)
        assert ok, f"frame {i} failed: {reason}"


def test_different_ids_derive_different_keys():
    key_a = derive_id_key(b"master", 0x100)
    key_b = derive_id_key(b"master", 0x200)
    assert key_a != key_b


def test_gateway_without_key_cannot_forge_valid_frame():
    # models a compromised/abused DoIP gateway that never held the master
    # key: it can craft a plausible-looking frame, but not a valid MAC.
    ctx = SecOCContext(b"real-vehicle-master-key")
    gateway_forged = b"\x2a\x00\x00\x00\x05\x11\x22\x33"
    ok, reason = ctx.verify(0x300, gateway_forged)
    assert not ok
    assert reason == "mac_invalid"
