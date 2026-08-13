# Author: Rayan Hamour (22103817)
"""
Rule-based IDS for the live dashboard: same three rules as
carnet.ids.detector.RuleBasedIDS (unknown ID, rate threshold, timing
deviation), but driven by explicit virtual-clock timestamps supplied by the
simulation engine instead of wall-clock time, so pausing/slowing the
simulation pauses/slows detection timing too, instead of the two drifting
apart.
"""

from __future__ import annotations

from collections import defaultdict, deque

from carnet.config import ECU_PROFILE, IDS_CONFIG, KNOWN_IDS


class TickIDS:
    def __init__(self):
        self.alerts: list[dict] = []
        self._recent_timestamps: dict[int, deque] = defaultdict(deque)
        self._last_seen: dict[int, float] = {}
        self._window_s = IDS_CONFIG["window_s"]
        self._max_per_window = IDS_CONFIG["max_msgs_per_window"]
        self._default_max = IDS_CONFIG["default_max_msgs_per_window"]
        self._deviation_ratio = IDS_CONFIG["timing_deviation_ratio"]
        self._next_seq = 1

    def _raise(self, now: float, arb_id: int, rule: str, detail: str) -> None:
        self.alerts.append(
            {
                "seq": self._next_seq,
                "timestamp": round(now, 3),
                "arbitration_id": arb_id,
                "arbitration_id_hex": f"0x{arb_id:X}",
                "rule": rule,
                "detail": detail,
            }
        )
        self._next_seq += 1

    def on_message(self, now: float, arb_id: int) -> None:
        if arb_id not in KNOWN_IDS:
            self._raise(now, arb_id, "unknown_id", f"arbitration ID 0x{arb_id:X} not in whitelist")
        self._check_rate(now, arb_id)
        self._check_timing(now, arb_id)

    def _check_rate(self, now: float, arb_id: int) -> None:
        dq = self._recent_timestamps[arb_id]
        dq.append(now)
        while dq and now - dq[0] > self._window_s:
            dq.popleft()
        limit = self._max_per_window.get(arb_id, self._default_max)
        if len(dq) > limit:
            self._raise(
                now, arb_id, "rate_threshold", f"{len(dq)} msgs in last {self._window_s}s exceeds limit {limit}"
            )

    def _check_timing(self, now: float, arb_id: int) -> None:
        profile = ECU_PROFILE.get(arb_id)
        last = self._last_seen.get(arb_id)
        self._last_seen[arb_id] = now
        if profile is None or profile["period_s"] is None or last is None:
            return
        delta = now - last
        nominal = profile["period_s"]
        if delta < nominal / self._deviation_ratio:
            self._raise(
                now,
                arb_id,
                "timing_deviation",
                f"inter-arrival {delta * 1000:.1f}ms far below nominal {nominal * 1000:.1f}ms",
            )

    def reset(self) -> None:
        self.alerts.clear()
        self._recent_timestamps.clear()
        self._last_seen.clear()
        self._next_seq = 1
