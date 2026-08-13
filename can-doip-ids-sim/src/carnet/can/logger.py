# Author: Rayan Hamour (22103817)
"""
CAN traffic logger: a can.Listener that records every observed frame, both
in memory (for the evaluation harness to analyse) and optionally to CSV
(for inspection / appendix material in the dissertation).
"""

from __future__ import annotations

import csv
import os
import threading
import time
from dataclasses import dataclass, field

import can


@dataclass
class CANLogRecord:
    timestamp: float  # seconds since logger start
    arbitration_id: int
    dlc: int
    data_hex: str


class CANLogger(can.Listener):
    def __init__(self, csv_path: str | None = None, start_time: float | None = None):
        self.start_time = start_time if start_time is not None else time.monotonic()
        self._lock = threading.Lock()
        self.records: list[CANLogRecord] = []
        self._csv_writer = None
        self._csv_file = None
        if csv_path:
            os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
            self._csv_file = open(csv_path, "w", newline="")
            self._csv_writer = csv.writer(self._csv_file)
            self._csv_writer.writerow(["timestamp_s", "arbitration_id_hex", "dlc", "data_hex"])

    def on_message_received(self, msg: can.Message) -> None:
        rec = CANLogRecord(
            timestamp=time.monotonic() - self.start_time,
            arbitration_id=msg.arbitration_id,
            dlc=msg.dlc,
            data_hex=msg.data.hex(),
        )
        with self._lock:
            self.records.append(rec)
            if self._csv_writer:
                self._csv_writer.writerow(
                    [f"{rec.timestamp:.6f}", f"0x{rec.arbitration_id:X}", rec.dlc, rec.data_hex]
                )
                self._csv_file.flush()

    def close(self) -> None:
        if self._csv_file:
            self._csv_file.close()