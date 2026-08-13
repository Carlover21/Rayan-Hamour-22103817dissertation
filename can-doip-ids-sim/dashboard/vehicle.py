# Author: Rayan Hamour (22103817)
"""
Minimal vehicle dynamics model: turns the *decoded* CAN signal values
(steering angle, speed, brake) into a car position/heading on a road, so an
attack that corrupts those signals visibly makes the car swerve, lurch, or
run off the road on the dashboard. This is a illustrative kinematic model
for visualization, not a validated vehicle dynamics simulation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

WHEELBASE_M = 2.7
ROAD_HALF_WIDTH_M = 4.0
CRUISE_SPEED_KMH = 60.0
SPEED_BLEND_RATE = 1.5  # how fast displayed speed chases the target speed signal
MAX_HEADING_DEG = 75.0


@dataclass
class VehicleState:
    x_m: float = 0.0
    y_m: float = 0.0  # lateral offset from lane center; +/- ROAD_HALF_WIDTH_M is off-road
    heading_deg: float = 0.0
    speed_kmh: float = CRUISE_SPEED_KMH
    off_road: bool = False

    def reset(self) -> None:
        self.x_m = 0.0
        self.y_m = 0.0
        self.heading_deg = 0.0
        self.speed_kmh = CRUISE_SPEED_KMH
        self.off_road = False

    def step(self, dt_s: float, steering_deg: float, target_speed_kmh: float, brake_applied: bool) -> None:
        if dt_s <= 0:
            return

        effective_target = 0.0 if brake_applied else target_speed_kmh
        blend = min(1.0, SPEED_BLEND_RATE * dt_s * (3.0 if brake_applied else 1.0))
        self.speed_kmh += (effective_target - self.speed_kmh) * blend
        self.speed_kmh = max(0.0, self.speed_kmh)

        speed_ms = self.speed_kmh / 3.6
        steering_rad = math.radians(max(-90.0, min(90.0, steering_deg)))
        yaw_rate_deg_s = math.degrees((speed_ms / WHEELBASE_M) * math.tan(steering_rad))
        self.heading_deg += yaw_rate_deg_s * dt_s
        self.heading_deg = max(-MAX_HEADING_DEG, min(MAX_HEADING_DEG, self.heading_deg))

        heading_rad = math.radians(self.heading_deg)
        self.x_m += speed_ms * math.cos(heading_rad) * dt_s
        self.y_m += speed_ms * math.sin(heading_rad) * dt_s

        if abs(self.y_m) > ROAD_HALF_WIDTH_M:
            self.off_road = True

    def as_dict(self) -> dict:
        return {
            "x_m": round(self.x_m, 2),
            "y_m": round(self.y_m, 2),
            "heading_deg": round(self.heading_deg, 2),
            "speed_kmh": round(self.speed_kmh, 1),
            "off_road": self.off_road,
            "road_half_width_m": ROAD_HALF_WIDTH_M,
        }
