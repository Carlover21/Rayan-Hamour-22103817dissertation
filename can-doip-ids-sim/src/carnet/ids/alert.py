# Author: Rayan Hamour (22103817)
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class IDSAlert:
    timestamp: float  # seconds since IDS start
    arbitration_id: int
    rule: str  # "unknown_id" | "rate_threshold" | "timing_deviation"
    detail: str

    def __repr__(self) -> str:
        return f"[{self.timestamp:8.3f}s] ALERT id=0x{self.arbitration_id:X} rule={self.rule} - {self.detail}"