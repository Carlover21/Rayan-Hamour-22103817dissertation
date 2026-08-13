# Author: Rayan Hamour (22103817)
"""
Tick-based simulation engine driving the live dashboard.

Runs on its own background thread with a *virtual* simulation clock,
independent of wall-clock time: the clock can be paused, slowed down, sped
up, or snapped back to real-time from the dashboard UI. Every tick,
scheduled ECU "sends" and any active attack's sends are processed in a
single-threaded loop (no locking races between senders), each message
updates the shared signal table, runs the tick-based IDS, and steps the
vehicle model - so the dashboard can show, live, what an attack does to the
CAN bus and to the simulated car.
"""

from __future__ import annotations

import random
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

from dashboard.doip_tick import DashboardDoIPGateway
from dashboard.ids_tick import TickIDS
from dashboard.signals import (
    BODY_ID,
    BATTERY_ID,
    BRAKE_ID,
    BrakeTapSource,
    DIAGNOSTIC_ID,
    NormalSignalSource,
    SPEED_ID,
    STEERING_ID,
    decode_brake,
    decode_speed_kmh,
    decode_steering_deg,
    encode_brake,
    encode_speed_kmh,
    encode_steering_deg,
)
from dashboard.vehicle import CRUISE_SPEED_KMH, VehicleState

TICK_HZ = 50
TICK_INTERVAL_S = 1.0 / TICK_HZ
MAX_MESSAGES = 3000
MAX_ALERTS = 500
MAX_DOIP_EVENTS = 200
MAX_VEHICLE_HISTORY = 6000  # ~2 minutes of history at 50Hz, for the scrub/replay control

IDLE_RPM = 800
MAX_RPM = 6500
BATTERY_MIN_V = 11.5
BATTERY_MAX_V = 14.0

TARGET_NAME_TO_ID = {
    "steering": STEERING_ID,
    "speed": SPEED_ID,
    "brake": BRAKE_ID,
    "diagnostic": DIAGNOSTIC_ID,
}
ID_TO_NAME = {v: k for k, v in TARGET_NAME_TO_ID.items()}

ATTACKER_ADDRESS = 0x0EEE


@dataclass
class ScheduledSender:
    arb_id: int
    period_s: float
    jitter_s: float
    payload_fn: Callable[[], bytes]
    source: str
    next_time: float = 0.0
    id_fn: Callable[[], int] | None = None  # overrides arb_id per-send (e.g. fuzzing)

    def schedule_next(self, now: float) -> None:
        interval = self.period_s + random.uniform(-self.jitter_s, self.jitter_s)
        self.next_time = now + max(interval, 0.005)


@dataclass
class AttackState:
    kind: str
    target: str
    rate_hz: float
    authorized: bool = True
    started_at: float = 0.0


class SimEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self.virtual_time = 0.0
        self.speed = 1.0
        self.paused = False

        self.vehicle = VehicleState()
        self.signals = {STEERING_ID: 0.0, SPEED_ID: CRUISE_SPEED_KMH, BRAKE_ID: False, BATTERY_ID: 0}

        self.ids = TickIDS()
        self.doip_gateway = DashboardDoIPGateway()

        self.messages: deque = deque(maxlen=MAX_MESSAGES)
        self.doip_events: deque = deque(maxlen=MAX_DOIP_EVENTS)
        self.vehicle_history: deque = deque(maxlen=MAX_VEHICLE_HISTORY)
        self._msg_seq = 1

        self._speed_src = NormalSignalSource(start=CRUISE_SPEED_KMH, step=1.5, low=40.0, high=80.0)
        self._brake_src = BrakeTapSource()
        self._body_rng = random.Random()
        self._battery_rng = random.Random()

        self.senders: list[ScheduledSender] = self._build_normal_senders()

        self.active_attack: AttackState | None = None
        self._attack_senders: list[ScheduledSender] = []
        self._doip_activated_logged = False

        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # -- setup -----------------------------------------------------------
    def _build_normal_senders(self) -> list[ScheduledSender]:
        return [
            ScheduledSender(STEERING_ID, 0.020, 0.004, self._gen_steering, "ecu"),
            ScheduledSender(SPEED_ID, 0.010, 0.002, self._gen_speed, "ecu"),
            ScheduledSender(BRAKE_ID, 0.020, 0.004, self._gen_brake, "ecu"),
            ScheduledSender(BODY_ID, 0.100, 0.010, self._gen_body, "ecu"),
            ScheduledSender(BATTERY_ID, 0.200, 0.020, self._gen_battery, "ecu"),
        ]

    def _gen_steering(self) -> bytes:
        # Models a basic lane-keeping ECU: steer proportionally to correct
        # lateral drift and heading error, so normal traffic holds lane
        # center on its own. Attacks override this signal outright.
        y = self.vehicle.y_m
        heading = self.vehicle.heading_deg
        correction = -(2.2 * y + 0.9 * heading)
        noise = random.uniform(-0.4, 0.4)
        value = max(-10.0, min(10.0, correction + noise))
        return encode_steering_deg(value)

    def _gen_speed(self) -> bytes:
        return encode_speed_kmh(self._speed_src.next())

    def _gen_brake(self) -> bytes:
        return encode_brake(self._brake_src.next())

    def _gen_body(self) -> bytes:
        return bytes(self._body_rng.randint(0, 255) for _ in range(4)) + bytes(4)

    def _gen_battery(self) -> bytes:
        return bytes(self._battery_rng.randint(0, 255) for _ in range(6)) + bytes(2)

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None:
            return
        now = self.virtual_time
        for s in self.senders:
            s.schedule_next(now)
        self._thread = threading.Thread(target=self._run, name="sim-engine", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        last_real = time.monotonic()
        while not self._stop.is_set():
            time.sleep(TICK_INTERVAL_S)
            now_real = time.monotonic()
            real_dt = min(now_real - last_real, 0.25)
            last_real = now_real
            with self.lock:
                self._tick(real_dt)

    # -- simulation step -----------------------------------------------------
    def _tick(self, real_dt: float) -> None:
        if self.paused:
            return
        virtual_dt = real_dt * self.speed
        self.virtual_time += virtual_dt

        for sender in self.senders:
            while self.virtual_time >= sender.next_time:
                due_time = sender.next_time
                self._emit(sender.arb_id, sender.payload_fn(), sender.source, due_time)
                sender.schedule_next(due_time)

        for attack_sender in self._attack_senders:
            while self.virtual_time >= attack_sender.next_time:
                due_time = attack_sender.next_time
                self._run_attack_send(attack_sender, due_time)
                attack_sender.schedule_next(due_time)

        steering = self.signals[STEERING_ID]
        target_speed = self.signals[SPEED_ID]
        brake = self.signals[BRAKE_ID]
        self.vehicle.step(virtual_dt, steering, target_speed, brake)
        self.vehicle_history.append((self.virtual_time, self.vehicle.as_dict()))

    def _emit(self, arb_id: int, data: bytes, source: str, now: float) -> None:
        if arb_id == STEERING_ID:
            self.signals[STEERING_ID] = decode_steering_deg(data)
        elif arb_id == SPEED_ID:
            self.signals[SPEED_ID] = decode_speed_kmh(data)
        elif arb_id == BRAKE_ID:
            self.signals[BRAKE_ID] = decode_brake(data)
        elif arb_id == BATTERY_ID and len(data) > 0:
            self.signals[BATTERY_ID] = data[0]

        self.ids.on_message(now, arb_id)
        self.messages.append(
            {
                "seq": self._msg_seq,
                "timestamp": round(now, 3),
                "arbitration_id": arb_id,
                "arbitration_id_hex": f"0x{arb_id:X}",
                "data_hex": data.hex(),
                "source": source,
            }
        )
        self._msg_seq += 1

    # -- attacks -----------------------------------------------------------
    def start_attack(
        self, kind: str, target: str, rate_hz: float, magnitude: float | None, authorized: bool
    ) -> None:
        with self.lock:
            target_id = TARGET_NAME_TO_ID.get(target, DIAGNOSTIC_ID)
            self.active_attack = AttackState(
                kind=kind, target=target, rate_hz=rate_hz, authorized=authorized, started_at=self.virtual_time
            )
            period = 1.0 / max(rate_hz, 0.1)
            self._attack_senders = self._build_attack_senders(kind, target_id, period, magnitude)
            for s in self._attack_senders:
                s.schedule_next(self.virtual_time)

            if kind == "doip":
                self.doip_gateway.reset()
                self._doip_activated_logged = False
                if authorized:
                    event = self.doip_gateway.routing_activation(self.virtual_time, ATTACKER_ADDRESS)
                    self.doip_events.append(event)

    def stop_attack(self) -> None:
        with self.lock:
            self.active_attack = None
            self._attack_senders = []

    def _build_attack_senders(
        self, kind: str, target_id: int, period: float, magnitude: float | None
    ) -> list[ScheduledSender]:
        rng = random.Random()

        def random_payload_for(tid: int) -> Callable[[], bytes]:
            def gen() -> bytes:
                if tid == STEERING_ID:
                    return encode_steering_deg(rng.uniform(-90, 90))
                if tid == SPEED_ID:
                    return encode_speed_kmh(rng.uniform(0, 255))
                if tid == BRAKE_ID:
                    return encode_brake(rng.random() < 0.5)
                return bytes(rng.randint(0, 255) for _ in range(8))

            return gen

        def fixed_payload() -> bytes:
            if target_id == STEERING_ID:
                value = -45.0 if magnitude is None else magnitude
                return encode_steering_deg(value)
            if target_id == SPEED_ID:
                value = 200.0 if magnitude is None else magnitude
                return encode_speed_kmh(value)
            if target_id == BRAKE_ID:
                return encode_brake(bool(magnitude))
            return bytes([0x22, 0xF1, 0x90]) + bytes(5)

        if kind == "flood":
            return [ScheduledSender(target_id, period, 0.0, random_payload_for(target_id), "attack")]

        if kind in ("spoof", "doip"):
            return [ScheduledSender(target_id, period, 0.0, fixed_payload, "attack")]

        if kind == "fuzz":
            # Scans the full 11-bit CAN ID space with random data - the
            # classic protocol-fuzzing approach to probing an unknown ECU
            # surface, almost always tripping the unknown-ID rule.
            def random_id() -> int:
                return rng.randint(0x000, 0x7FF)

            def random_data() -> bytes:
                return bytes(rng.randint(0, 255) for _ in range(8))

            return [ScheduledSender(0, period, 0.0, random_data, "attack", id_fn=random_id)]

        if kind == "replay":
            # Captures the current legitimate value once, then replays that
            # exact (valid-looking) payload out of cadence - value-based
            # checks see nothing wrong; only timing/rate rules catch it.
            captured = self._encode_current_signal(target_id)
            return [ScheduledSender(target_id, period, 0.0, lambda: captured, "attack")]

        if kind == "bus_flood":
            # Floods every legitimate signal at once - a full bus jam
            # rather than a single-ID attack.
            ids = [STEERING_ID, SPEED_ID, BRAKE_ID, BODY_ID, BATTERY_ID]
            return [ScheduledSender(tid, period, 0.0, random_payload_for(tid), "attack") for tid in ids]

        return []

    def _encode_current_signal(self, target_id: int) -> bytes:
        if target_id == STEERING_ID:
            return encode_steering_deg(self.signals[STEERING_ID])
        if target_id == SPEED_ID:
            return encode_speed_kmh(self.signals[SPEED_ID])
        if target_id == BRAKE_ID:
            return encode_brake(self.signals[BRAKE_ID])
        return bytes(8)

    def _run_attack_send(self, sender: ScheduledSender, now: float) -> None:
        attack = self.active_attack
        if attack is None:
            return
        arb_id = sender.id_fn() if sender.id_fn else sender.arb_id
        data = sender.payload_fn()

        if attack.kind == "doip":
            ok, event = self.doip_gateway.send_diagnostic(now, ATTACKER_ADDRESS, arb_id, data)
            self.doip_events.append(event)
            if not ok:
                return  # rejected by gateway - never reaches the CAN bus
            self._emit(arb_id, data, "doip", now)
        else:
            self._emit(arb_id, data, "attack", now)

    # -- control -------------------------------------------------------------
    def set_paused(self, paused: bool) -> None:
        with self.lock:
            self.paused = paused

    def set_speed(self, speed: float) -> None:
        with self.lock:
            self.speed = max(0.0, min(8.0, speed))

    def resume_realtime(self) -> None:
        with self.lock:
            self.paused = False
            self.speed = 1.0

    def reset_scenario(self) -> None:
        with self.lock:
            self.vehicle.reset()
            self.stop_attack()
            self.ids.reset()
            self.doip_gateway.reset()
            self.messages.clear()
            self.doip_events.clear()
            self.vehicle_history.clear()
            self.signals = {STEERING_ID: 0.0, SPEED_ID: CRUISE_SPEED_KMH, BRAKE_ID: False, BATTERY_ID: 0}
            self._speed_src = NormalSignalSource(start=CRUISE_SPEED_KMH, step=1.5, low=40.0, high=80.0)
            self._brake_src = BrakeTapSource()

    def _estimate_rpm(self) -> float:
        # Purely cosmetic derived telemetry (no separate RPM CAN signal
        # exists in this model): idle plus a linear scaling with speed,
        # clipped to a plausible range, so the gauge has something to show.
        speed = self.vehicle.speed_kmh
        return max(IDLE_RPM, min(MAX_RPM, IDLE_RPM + speed * 45))

    def _decode_battery_v(self) -> float:
        byte0 = self.signals.get(BATTERY_ID, 0)
        return BATTERY_MIN_V + (byte0 / 255.0) * (BATTERY_MAX_V - BATTERY_MIN_V)

    def get_vehicle_at(self, t: float) -> dict | None:
        """Nearest recorded vehicle snapshot to virtual time `t`, for the
        scrub/replay control - binary search over the history deque."""
        with self.lock:
            if not self.vehicle_history:
                return None
            history = self.vehicle_history
            lo, hi = 0, len(history) - 1
            if t <= history[0][0]:
                return history[0][1]
            if t >= history[-1][0]:
                return history[-1][1]
            while lo < hi:
                mid = (lo + hi) // 2
                if history[mid][0] < t:
                    lo = mid + 1
                else:
                    hi = mid
            return history[lo][1]

    # -- state export --------------------------------------------------------
    def get_state(self, since_msg_seq: int = 0, since_alert_seq: int = 0, since_doip_seq: int = 0) -> dict:
        with self.lock:
            new_messages = [m for m in self.messages if m["seq"] > since_msg_seq]
            new_alerts = [a for a in self.ids.alerts if a["seq"] > since_alert_seq]
            new_doip = [e for e in self.doip_events if e["seq"] > since_doip_seq]
            return {
                "virtual_time": round(self.virtual_time, 3),
                "speed": self.speed,
                "paused": self.paused,
                "vehicle": self.vehicle.as_dict(),
                "signals": {
                    "steering_deg": round(self.signals[STEERING_ID], 2),
                    "speed_kmh": round(self.signals[SPEED_ID], 1),
                    "brake": self.signals[BRAKE_ID],
                    "rpm": round(self._estimate_rpm()),
                    "battery_v": round(self._decode_battery_v(), 2),
                },
                "active_attack": (
                    {
                        "kind": self.active_attack.kind,
                        "target": self.active_attack.target,
                        "rate_hz": self.active_attack.rate_hz,
                        "authorized": self.active_attack.authorized,
                    }
                    if self.active_attack
                    else None
                ),
                "new_messages": new_messages,
                "new_alerts": new_alerts,
                "new_doip_events": new_doip,
                "last_msg_seq": self.messages[-1]["seq"] if self.messages else since_msg_seq,
                "last_alert_seq": self.ids.alerts[-1]["seq"] if self.ids.alerts else since_alert_seq,
                "last_doip_seq": self.doip_events[-1]["seq"] if self.doip_events else since_doip_seq,
                "total_alerts": len(self.ids.alerts),
            }
