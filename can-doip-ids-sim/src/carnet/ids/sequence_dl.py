# Author: Rayan Hamour (22103817)
"""
LSTM sequence-based anomaly detector (PyTorch), for direct comparison
against the per-message rule-based and IsolationForest detectors. Several
of the papers in this project's literature review use CNN/LSTM approaches
that look at short sequences of messages rather than one at a time - this
detector is built specifically to test whether that extra temporal context
catches things a single-message model can't, particularly the mimicry
attack (carnet.attacks.mimicry), which is engineered to look individually
unremarkable and only becomes suspicious as a *pattern* across several
messages.

A small LSTM autoencoder per arbitration ID, trained only on baseline
(attack-free) sliding windows of [inter_arrival, byte0, byte1] triples, to
reconstruct its own input. Reconstruction error on unseen windows is the
anomaly score: windows containing an attack message tend to reconstruct
worse than the all-legitimate windows the model was trained on, since the
model never saw that timing/value pattern during training.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

import can
import torch
from torch import nn

from carnet.config import KNOWN_IDS
from carnet.ids.alert import IDSAlert

WINDOW = 8
FEATURE_DIM = 3
HIDDEN_SIZE = 16
MIN_TRAINING_WINDOWS = 15
TRAIN_EPOCHS = 60
ANOMALY_THRESHOLD_STDS = 3.0


class _LSTMAutoencoder(nn.Module):
    def __init__(self, feature_dim: int = FEATURE_DIM, hidden_size: int = HIDDEN_SIZE):
        super().__init__()
        self.encoder = nn.LSTM(feature_dim, hidden_size, batch_first=True)
        self.decoder = nn.LSTM(hidden_size, hidden_size, batch_first=True)
        self.output_layer = nn.Linear(hidden_size, feature_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (h_n, _) = self.encoder(x)
        seq_len = x.size(1)
        latent = h_n[-1].unsqueeze(1).repeat(1, seq_len, 1)
        decoded, _ = self.decoder(latent)
        return self.output_layer(decoded)


class SequenceIDS(can.Listener):
    def __init__(self, start_time: float | None = None, window: int = WINDOW):
        self.start_time = start_time if start_time is not None else time.monotonic()
        self.window = window
        self._lock = threading.Lock()
        self.alerts: list[IDSAlert] = []

        self._last_seen: dict[int, float] = {}
        self._training_windows: dict[int, list[list[list[float]]]] = defaultdict(list)
        self._buffer: dict[int, deque] = defaultdict(lambda: deque(maxlen=window))

        self._models: dict[int, _LSTMAutoencoder] = {}
        self._thresholds: dict[int, float] = {}
        self._trained = False

    def now(self) -> float:
        return time.monotonic() - self.start_time

    def _raise(self, now: float, arb_id: int, rule: str, detail: str) -> None:
        self.alerts.append(IDSAlert(timestamp=now, arbitration_id=arb_id, rule=rule, detail=detail))

    def _features(self, arb_id: int, data: bytes, now: float) -> list[float]:
        last = self._last_seen.get(arb_id)
        inter_arrival_ms = (now - last) * 1000 if last is not None else 0.0
        self._last_seen[arb_id] = now
        byte0 = data[0] / 255.0 if len(data) > 0 else 0.0
        byte1 = data[1] / 255.0 if len(data) > 1 else 0.0
        return [min(inter_arrival_ms / 100.0, 5.0), byte0, byte1]

    def on_message_received(self, msg: can.Message) -> None:
        now = self.now()
        arb_id = msg.arbitration_id
        data = bytes(msg.data)
        feats = self._features(arb_id, data, now)

        with self._lock:
            buf = self._buffer[arb_id]
            buf.append(feats)
            if not self._trained:
                if len(buf) == self.window:
                    self._training_windows[arb_id].append(list(buf))
                return
            # Unknown-ID is a simple membership check, not a sequence
            # property - flag it immediately rather than waiting for a full
            # window to fill, otherwise a short probe on a novel ID would
            # never be caught at all.
            if arb_id not in KNOWN_IDS:
                self._raise(now, arb_id, "seq_unknown_id", f"arbitration ID 0x{arb_id:X} never seen in training")
                return
            if len(buf) < self.window:
                return
            self._detect(now, arb_id, list(buf))

    def fit(self) -> None:
        """Call once, at the baseline/attack boundary: trains one small LSTM
        autoencoder per arbitration ID with enough collected windows, then
        switches into detection mode."""
        torch.manual_seed(42)
        with self._lock:
            for arb_id, windows in self._training_windows.items():
                if len(windows) < MIN_TRAINING_WINDOWS:
                    continue
                model = _LSTMAutoencoder()
                x = torch.tensor(windows, dtype=torch.float32)
                optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
                loss_fn = nn.MSELoss()
                model.train()
                for _ in range(TRAIN_EPOCHS):
                    optimizer.zero_grad()
                    recon = model(x)
                    loss = loss_fn(recon, x)
                    loss.backward()
                    optimizer.step()
                model.eval()
                with torch.no_grad():
                    recon = model(x)
                    per_window_errors = ((recon - x) ** 2).mean(dim=(1, 2))
                mean_err = per_window_errors.mean().item()
                std_err = per_window_errors.std().item() or mean_err * 0.5 + 1e-6
                self._models[arb_id] = model
                self._thresholds[arb_id] = mean_err + ANOMALY_THRESHOLD_STDS * std_err
            self._trained = True

    def _detect(self, now: float, arb_id: int, window: list[list[float]]) -> None:
        model = self._models.get(arb_id)
        if model is None:
            return  # not enough baseline windows to train a model for this ID
        x = torch.tensor([window], dtype=torch.float32)
        with torch.no_grad():
            recon = model(x)
            error = ((recon - x) ** 2).mean().item()
        threshold = self._thresholds[arb_id]
        if error > threshold:
            self._raise(
                now, arb_id, "seq_anomaly", f"LSTM reconstruction error {error:.4f} exceeds threshold {threshold:.4f}"
            )

    def alert_count(self) -> int:
        with self._lock:
            return len(self.alerts)
