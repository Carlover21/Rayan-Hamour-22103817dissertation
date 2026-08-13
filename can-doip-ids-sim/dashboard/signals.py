# Author: Rayan Hamour (22103817)
"""
Semantic CAN signal encode/decode for the dashboard demo. The CLI/evaluation
side of the project (src/carnet) uses random payloads since only traffic
*patterns* matter there; the live dashboard needs payloads that decode to
physically meaningful values (speed, steering angle, brake state) so an
attack's effect on the simulated car is visible.
"""

from __future__ import annotations

import random
import struct

STEERING_ID = 0x300
SPEED_ID = 0x100
BRAKE_ID = 0x200
BODY_ID = 0x400
BATTERY_ID = 0x500
DIAGNOSTIC_ID = 0x7E0


def encode_speed_kmh(speed_kmh: float) -> bytes:
    clipped = max(0, min(255, round(speed_kmh)))
    return bytes([clipped]) + bytes(7)


def decode_speed_kmh(data: bytes) -> float:
    return float(data[0]) if data else 0.0


def encode_steering_deg(angle_deg: float) -> bytes:
    clipped = max(-127, min(127, round(angle_deg)))
    return struct.pack("b", clipped) + bytes(7)


def decode_steering_deg(data: bytes) -> float:
    if not data:
        return 0.0
    return float(struct.unpack("b", data[0:1])[0])


def encode_brake(applied: bool) -> bytes:
    return bytes([1 if applied else 0]) + bytes(7)


def decode_brake(data: bytes) -> bool:
    return bool(data[0]) if data else False


class NormalSignalSource:
    """Smooth, physically-plausible baseline values for one signal (random walk)."""

    def __init__(self, start: float, step: float, low: float, high: float):
        self.value = start
        self.step = step
        self.low = low
        self.high = high

    def next(self) -> float:
        self.value += random.uniform(-self.step, self.step)
        self.value = max(self.low, min(self.high, self.value))
        return self.value


class BrakeTapSource:
    """Mostly released, with occasional brief brake taps, like normal driving."""

    def __init__(self, tap_probability: float = 0.03):
        self.tap_probability = tap_probability
        self._tap_ticks_remaining = 0

    def next(self) -> bool:
        if self._tap_ticks_remaining > 0:
            self._tap_ticks_remaining -= 1
            return True
        if random.random() < self.tap_probability:
            self._tap_ticks_remaining = random.randint(1, 3)
            return True
        return False
