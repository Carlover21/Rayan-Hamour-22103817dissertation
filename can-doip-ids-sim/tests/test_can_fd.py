# Author: Rayan Hamour (22103817)
"""Unit tests for CAN-FD support: larger-than-8-byte frames from a
configured ECU, and SecOC authentication scaling to those frame sizes."""

from __future__ import annotations

import time

from carnet.can.bus import create_bus, create_notifier
from carnet.can.logger import CANLogger
from carnet.can.traffic import TrafficGenerator
from carnet.security.secoc import SecOCContext


def test_fd_ecu_sends_larger_than_8_byte_frames():
    bus = create_bus()
    tap_bus = create_bus()
    logger = CANLogger()
    notifier = create_notifier(tap_bus, [logger])
    traffic = TrafficGenerator(bus)
    try:
        traffic.start()
        time.sleep(0.5)
    finally:
        traffic.stop()
        notifier.stop()
        bus.shutdown()
        tap_bus.shutdown()

    fd_records = [r for r in logger.records if r.arbitration_id == 0x600]
    assert len(fd_records) > 0
    assert all(r.dlc == 32 for r in fd_records)


def test_secoc_protects_fd_frame_length():
    ctx = SecOCContext(b"fd-test-key")
    payload = bytes(range(28))  # more than fits in a classic 4-byte payload portion
    frame = ctx.protect(0x600, payload, frame_len=32)
    assert len(frame) == 32
    ok, reason = ctx.verify(0x600, frame)
    assert ok, reason


def test_secoc_fd_frame_still_rejects_tampering():
    ctx = SecOCContext(b"fd-test-key")
    frame = bytearray(ctx.protect(0x600, bytes(range(28)), frame_len=32))
    frame[0] ^= 0xFF
    ok, reason = ctx.verify(0x600, bytes(frame))
    assert not ok
    assert reason == "mac_invalid"


def test_secoc_default_frame_len_unchanged_for_classic_can():
    ctx = SecOCContext(b"classic-test-key")
    frame = ctx.protect(0x100, b"\x01\x02\x03\x04")
    assert len(frame) == 8  # unchanged default behaviour
    ok, _ = ctx.verify(0x100, frame)
    assert ok


def test_fd_traffic_with_secoc_enabled_verifies():
    secoc = SecOCContext(b"integration-test-key")
    bus = create_bus()
    tap_bus = create_bus()
    logger = CANLogger()
    notifier = create_notifier(tap_bus, [logger])
    traffic = TrafficGenerator(bus, secoc=secoc)
    try:
        traffic.start()
        time.sleep(0.3)
    finally:
        traffic.stop()
        notifier.stop()
        bus.shutdown()
        tap_bus.shutdown()

    fd_records = [r for r in logger.records if r.arbitration_id == 0x600]
    assert len(fd_records) > 0
    verifier = SecOCContext(b"integration-test-key")
    ok_count = 0
    for r in fd_records[:5]:
        ok, _ = verifier.verify(0x600, bytes.fromhex(r.data_hex))
        if ok:
            ok_count += 1
    assert ok_count > 0
