"""
Virtual ECU: a simulated node that periodically transmits one CAN arbitration
ID with jitter, approximating the periodic broadcast behaviour of real
automotive control units (engine, brakes, body control, etc).
"""

from __future__ import annotations

import random
import threading
import time

import can

from carnet.security.secoc import SecOCContext


class VirtualECU:
    """Sends `arbitration_id` on `bus` every `period_s` (+/- `jitter_s`) until stopped."""

    def __init__(
        self,
        bus: can.Bus,
        name: str,
        arbitration_id: int,
        period_s: float,
        jitter_s: float = 0.0,
        dlc: int = 8,
        secoc: SecOCContext | None = None,
        silenced_ids: set[int] | None = None,
    ):
        self.bus = bus
        self.name = name
        self.arbitration_id = arbitration_id
        self.period_s = period_s
        self.jitter_s = jitter_s
        self.dlc = dlc
        self.secoc = secoc
        self.silenced_ids = silenced_ids
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent_count = 0

    def _next_payload(self) -> bytes:
        payload = bytes(random.randint(0, 255) for _ in range(self.dlc))
        if self.secoc is not None:
            payload = self.secoc.protect(self.arbitration_id, payload)
        return payload

    def _run(self) -> None:
        while not self._stop_event.is_set():
            if self.silenced_ids is None or self.arbitration_id not in self.silenced_ids:
                msg = can.Message(
                    arbitration_id=self.arbitration_id,
                    data=self._next_payload(),
                    is_extended_id=False,
                )
                try:
                    self.bus.send(msg)
                    self.sent_count += 1
                except can.CanError:
                    pass
            interval = self.period_s + random.uniform(-self.jitter_s, self.jitter_s)
            self._stop_event.wait(max(interval, 0.001))

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name=f"ecu-{self.name}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None