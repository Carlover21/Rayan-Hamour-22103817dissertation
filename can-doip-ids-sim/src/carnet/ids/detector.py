# Author: Rayan Hamour (22103817)
"""
Rule-based intrusion detection for the simulated CAN bus.

Five independent rules, each able to fire on its own:

1. Unknown ID       - arbitration ID not in the ECU whitelist at all.
2. Rate threshold   - too many messages for a given ID within a sliding
                      time window (catches flooding/DoS).
3. Timing deviation - inter-arrival time for a periodic ID is far shorter
                      than its nominal period (catches spoofing/injection
                      that isn''t fast enough to trip the rate rule but
                      still doesn''t match the legitimate ECU''s cadence).
4. Auth invalid     - (only when a SecOCContext is supplied) the frame''s
                      MAC/freshness counter doesn''t verify against the
                      per-ID key. Catches spoofing, replay, and
                      gateway-forwarded injection regardless of rate or
                      timing, because the attacker never holds the key.
5. Silence          - a periodic ID has gone quiet far longer than its
                      nominal period, e.g. after a bus-off attack silences
                      its legitimate sender. Complements rule 2: that one
                      catches too much traffic, this one catches too little.

Deliberately simple/interpretable (thresholds from config, no ML) per the
proposal''s "rule-based" IDS scope; the evaluation harness records what it
misses as a known limitation, and carnet.ids.anomaly provides an ML-based
detector for direct comparison.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

import can

from carnet.config import ECU_PROFILE, IDS_CONFIG, KNOWN_IDS, SILENCE_RATIO
from carnet.ids.alert import IDSAlert
from carnet.security.secoc import SecOCContext


class RuleBasedIDS(can.Listener):
    def __init__(self, start_time: float | None = None, secoc: SecOCContext | None = None):
        self.start_time = start_time if start_time is not None else time.monotonic()
        self._lock = threading.Lock()
        self.alerts: list[IDSAlert] = []
        self._recent_timestamps: dict[int, deque] = defaultdict(deque)
        self._last_seen: dict[int, float] = {}
        self._window_s = IDS_CONFIG["window_s"]
        self._max_per_window = IDS_CONFIG["max_msgs_per_window"]
        self._default_max = IDS_CONFIG["default_max_msgs_per_window"]
        self._deviation_ratio = IDS_CONFIG["timing_deviation_ratio"]
        self.secoc = secoc
        self._silence_flagged: set[int] = set()
        self._stop_event = threading.Event()
        self._silence_thread = threading.Thread(target=self._silence_loop, name="ids-silence-monitor", daemon=True)
        self._silence_thread.start()

    def _silence_loop(self) -> None:
        # Silence can only be noticed by polling for absence: a can.Listener
        # only ever fires when a message *does* arrive.
        while not self._stop_event.wait(0.1):
            self.check_silence()

    def stop(self) -> None:
        self._stop_event.set()
        self._silence_thread.join(timeout=1.0)

    def now(self) -> float:
        return time.monotonic() - self.start_time

    def _raise(self, now: float, arb_id: int, rule: str, detail: str) -> None:
        self.alerts.append(IDSAlert(timestamp=now, arbitration_id=arb_id, rule=rule, detail=detail))

    def on_message_received(self, msg: can.Message) -> None:
        now = self.now()
        arb_id = msg.arbitration_id

        with self._lock:
            if arb_id not in KNOWN_IDS:
                self._raise(now, arb_id, "unknown_id", f"arbitration ID 0x{arb_id:X} not in whitelist")
                # still track it so a repeated unknown ID doesn''t also spam rate alerts oddly
            self._check_rate(now, arb_id)
            self._check_timing(now, arb_id)
            if self.secoc is not None:
                self._check_auth(now, arb_id, bytes(msg.data))
            self._silence_flagged.discard(arb_id)

    def _check_rate(self, now: float, arb_id: int) -> None:
        dq = self._recent_timestamps[arb_id]
        dq.append(now)
        while dq and now - dq[0] > self._window_s:
            dq.popleft()
        limit = self._max_per_window.get(arb_id, self._default_max)
        if len(dq) > limit:
            self._raise(
                now,
                arb_id,
                "rate_threshold",
                f"{len(dq)} msgs in last {self._window_s}s exceeds limit {limit}",
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

    def _check_auth(self, now: float, arb_id: int, data: bytes) -> None:
        ok, reason = self.secoc.verify(arb_id, data)
        if not ok:
            self._raise(now, arb_id, "auth_invalid", f"SecOC verification failed ({reason})")

    def check_silence(self) -> None:
        """Call periodically (not per-message) to catch IDs that have gone
        quiet. A message-driven listener alone can never notice absence."""
        now = self.now()
        with self._lock:
            for arb_id, profile in ECU_PROFILE.items():
                period = profile["period_s"]
                if period is None or arb_id in self._silence_flagged:
                    continue
                last = self._last_seen.get(arb_id)
                if last is None:
                    continue
                if now - last > period * SILENCE_RATIO:
                    self._raise(
                        now,
                        arb_id,
                        "silence",
                        f"no traffic for {now - last:.2f}s, exceeds {SILENCE_RATIO}x nominal period "
                        f"{period * 1000:.0f}ms - possible bus-off / DoS",
                    )
                    self._silence_flagged.add(arb_id)

    def alert_count(self) -> int:
        with self._lock:
            return len(self.alerts)