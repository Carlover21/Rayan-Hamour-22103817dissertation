# Author: Rayan Hamour (22103817)
"""
Infotainment-pivot attack: models an attacker who never touches the DoIP
diagnostic path at all, and instead compromises the infotainment/telematics
unit over its normal external interfaces (Bluetooth, Wi-Fi, cellular) - the
IVI-to-CAN bridge used by real production attack chains such as the 2015
Jeep Cherokee remote-exploit (Miller & Valasek), where the entry point was
the cellular-connected head unit, not the OBD port.

Unlike the DoIP gateway modelled elsewhere in this project, a compromised
infotainment unit is not gated by any routing-activation/authorization
step in this simulation - once compromised, the attacker already has
whatever bridge access the IVI unit itself has, which is the point: this
path has no equivalent of the DoIP authorization control we rely on
elsewhere, so it is entirely down to the CAN-layer defences (the rule-based
IDS, and SecOC authentication if enabled) whether it gets caught at all.
"""

from __future__ import annotations

import random
import time

import can


def run_infotainment_pivot_attack(
    bus: can.Bus,
    target_id: int,
    duration_s: float,
    rate_hz: float,
    payload: bytes | None = None,
) -> int:
    interval = 1.0 / rate_hz if rate_hz > 0 else 0.0
    end_time = time.monotonic() + duration_s
    sent = 0
    while time.monotonic() < end_time:
        data = payload if payload is not None else bytes(random.randint(0, 255) for _ in range(8))
        msg = can.Message(arbitration_id=target_id, data=data[:8].ljust(8, b"\x00"), is_extended_id=False)
        try:
            bus.send(msg)
            sent += 1
        except can.CanError:
            pass
        if interval > 0:
            time.sleep(interval)
    return sent
