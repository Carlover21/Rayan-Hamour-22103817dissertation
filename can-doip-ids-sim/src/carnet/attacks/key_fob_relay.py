"""
Key-fob relay attack: models the CAN-visible consequence of a passive
keyless entry (PKE) relay attack - two attacker devices extend the range
between a key fob left near a house and the parked car, tricking the car
into unlocking as if the fob were nearby. Real relay attacks operate below
the CAN layer entirely (RF signal timing) and, critically, are NOT stopped
by rolling codes or freshness counters: unlike replay, a relay forwards the
key's genuinely current, valid signal in real time rather than reusing a
captured old one, so SecOC-style counter freshness checks (which this
project's `security.secoc` module models) do not address them - defeating
relay requires distance-bounding/timing protocols, out of scope here.

This module only reproduces what a relay attack looks like once it reaches
the CAN bus: a single, low-frequency "doors unlocked" state change with no
corresponding legitimate cause, sent once or a few times rather than as a
flood. It is a deliberately honest test of whether a rate/pattern-based CAN
IDS - tuned to catch high-frequency floods and periodic-timing deviations -
can catch a rare, single-shot malicious event at all.
"""

from __future__ import annotations

import time

import can

UNLOCK_PAYLOAD = bytes([0x01, 0x00, 0x00, 0x00]) + bytes(4)


def run_key_fob_relay_attack(
    bus: can.Bus,
    target_id: int,
    num_events: int = 1,
    spacing_s: float = 0.5,
) -> int:
    sent = 0
    for _ in range(max(1, num_events)):
        msg = can.Message(arbitration_id=target_id, data=UNLOCK_PAYLOAD, is_extended_id=False)
        try:
            bus.send(msg)
            sent += 1
        except can.CanError:
            pass
        time.sleep(spacing_s)
    return sent
