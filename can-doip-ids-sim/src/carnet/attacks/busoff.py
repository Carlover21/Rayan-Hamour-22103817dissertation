"""
Bus-off attack: exploits CAN's own error-handling state machine rather than
sending an implausible volume of traffic. A real CAN controller keeps a
transmit error counter (TEC, ISO 11898-1) and goes "bus-off" - stops
transmitting entirely - once that counter passes 255. An attacker who wins
arbitration against a victim ID repeatedly (or otherwise forces bit/stuff
errors on the victim's frames) can deliberately drive the victim's TEC past
that threshold and silence it, a documented real vulnerability (Cho & Shin,
"Error Handling of In-Vehicle Networks Makes Them Vulnerable", CCS 2016).

This is modelled at the outcome level rather than the CAN bit level (the
virtual bus underneath has no real arbitration/error-frame physics): each
attack transmission is treated as one successful error-inducing collision
against the victim, incrementing a simulated TEC by a fixed amount. Once the
threshold is crossed, the victim's arbitration ID is added to `silenced_ids`
- a set shared with the TrafficGenerator, whose ECUs check it before every
send - so the legitimate ECU actually stops appearing on the bus, exactly
like a real bus-off victim would.
"""

from __future__ import annotations

import random
import time

import can

from carnet.config import BUS_OFF_TEC_INCREMENT, BUS_OFF_TEC_THRESHOLD


def run_busoff_attack(
    bus: can.Bus,
    target_id: int,
    duration_s: float,
    rate_hz: float,
    silenced_ids: set[int],
) -> dict:
    interval = 1.0 / rate_hz if rate_hz > 0 else 0.0
    end_time = time.monotonic() + duration_s
    sent = 0
    tec = 0
    time_to_bus_off_s: float | None = None
    attack_start = time.monotonic()

    while time.monotonic() < end_time:
        msg = can.Message(
            arbitration_id=target_id,
            data=bytes(random.randint(0, 255) for _ in range(8)),
            is_extended_id=False,
        )
        try:
            bus.send(msg)
            sent += 1
        except can.CanError:
            pass

        if target_id not in silenced_ids:
            tec = min(tec + BUS_OFF_TEC_INCREMENT, BUS_OFF_TEC_THRESHOLD)
            if tec >= BUS_OFF_TEC_THRESHOLD:
                silenced_ids.add(target_id)
                if time_to_bus_off_s is None:
                    time_to_bus_off_s = time.monotonic() - attack_start

        if interval > 0:
            time.sleep(interval)

    return {
        "sent": sent,
        "final_tec": tec,
        "bus_off_achieved": target_id in silenced_ids,
        "time_to_bus_off_s": time_to_bus_off_s,
    }
