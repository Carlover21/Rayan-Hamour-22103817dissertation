"""
Matplotlib plots for the evaluation chapter: detection rate vs attack
intensity, and a CAN traffic timeline for a single representative run with
the attack window and IDS alerts overlaid.
"""

from __future__ import annotations

import os

import matplotlib.pyplot as plt
import pandas as pd

from carnet.can.logger import CANLogger
from carnet.config import RESULTS_DIR
from carnet.ids.detector import RuleBasedIDS


def _out(path: str) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    return os.path.join(RESULTS_DIR, path)


def plot_detection_rate_by_intensity(df: pd.DataFrame, filename: str, title: str) -> str:
    grouped = df.groupby(["attack", "intensity"])["detected"].mean().reset_index()
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for attack, sub in grouped.groupby("attack"):
        sub = sub.sort_values("intensity")
        ax.plot(sub["intensity"], sub["detected"] * 100, marker="o", label=attack)
    ax.set_xlabel("Attack intensity (messages/sec)")
    ax.set_ylabel("Detection rate (%)")
    ax.set_ylim(-5, 105)
    ax.set_title(title)
    ax.legend()
    ax.grid(True, alpha=0.3)
    out_path = _out(filename)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_false_positive_summary(df: pd.DataFrame, filename: str) -> str:
    grouped = df.groupby("attack")["baseline_false_positives"].mean().reset_index()
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(grouped["attack"], grouped["baseline_false_positives"])
    ax.set_ylabel("Mean false-positive alerts during baseline (no attack)")
    ax.set_title("False positives under normal traffic, by scenario")
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()
    out_path = _out(filename)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_ml_vs_rule_comparison(df: pd.DataFrame, filename: str) -> str:
    grouped = df.groupby("attack").agg(
        rule_detection_rate=("rule_detected", "mean"), ml_detection_rate=("ml_detected", "mean")
    )
    grouped = (grouped * 100).round(1)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = range(len(grouped))
    width = 0.35
    ax.bar([i - width / 2 for i in x], grouped["rule_detection_rate"], width, label="Rule-based IDS")
    ax.bar([i + width / 2 for i in x], grouped["ml_detection_rate"], width, label="ML (IsolationForest) IDS")
    ax.set_xticks(list(x))
    ax.set_xticklabels(grouped.index, rotation=20)
    ax.set_ylabel("Detection rate (%)")
    ax.set_ylim(-5, 105)
    ax.set_title("Rule-based vs ML detection rate by attack type")
    ax.legend()
    ax.grid(True, alpha=0.3, axis="y")
    fig.tight_layout()
    out_path = _out(filename)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_traffic_timeline(
    logger: CANLogger,
    ids: RuleBasedIDS,
    attack_start_s: float,
    attack_end_s: float,
    filename: str,
) -> str:
    fig, ax = plt.subplots(figsize=(10, 5))
    ids_present = sorted({r.arbitration_id for r in logger.records})
    id_to_y = {arb_id: i for i, arb_id in enumerate(ids_present)}

    xs = [r.timestamp for r in logger.records]
    ys = [id_to_y[r.arbitration_id] for r in logger.records]
    ax.scatter(xs, ys, s=6, alpha=0.4, label="CAN frame")

    if ids.alerts:
        axs = [a.timestamp for a in ids.alerts if a.arbitration_id in id_to_y]
        ays = [id_to_y[a.arbitration_id] for a in ids.alerts if a.arbitration_id in id_to_y]
        ax.scatter(axs, ays, s=40, marker="x", color="red", label="IDS alert")

    ax.axvspan(attack_start_s, attack_end_s, color="orange", alpha=0.15, label="Attack window")
    ax.set_yticks(list(id_to_y.values()))
    ax.set_yticklabels([f"0x{i:X}" for i in id_to_y.keys()])
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Arbitration ID")
    ax.set_title("CAN bus traffic timeline with IDS alerts")
    ax.legend(loc="upper right")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    out_path = _out(filename)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path
