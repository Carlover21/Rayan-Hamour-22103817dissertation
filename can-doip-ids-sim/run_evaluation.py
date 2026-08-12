"""
Full evaluation run: sweeps flood, spoofing, and DoIP-injection attacks
across several intensities (with repeats), scores IDS detection rate and
baseline false positives, and writes CSVs + plots to results/ for use in
the dissertation's evaluation chapter.

Usage:
    python run_evaluation.py
"""

from __future__ import annotations

import pandas as pd

from carnet.eval.plots import plot_detection_rate_by_intensity, plot_false_positive_summary
from carnet.eval.sweep import save_results, sweep_doip_injection, sweep_flood, sweep_spoof

FLOOD_RATES = [20, 50, 100, 200, 500]
SPOOF_RATES = [10, 20, 50, 100, 200]
DOIP_RATES = [2, 5, 10, 20]
REPEATS = 3


def main() -> None:
    print("Running flood attack sweep...")
    flood_df = sweep_flood(FLOOD_RATES, repeats=REPEATS)
    print("Running spoofing attack sweep...")
    spoof_df = sweep_spoof(SPOOF_RATES, repeats=REPEATS)
    print("Running DoIP injection sweep (no routing activation - unauthorized)...")
    doip_unauth_df = sweep_doip_injection(DOIP_RATES, skip_routing_activation=True, repeats=REPEATS)
    print("Running DoIP injection sweep (with routing activation - abused access)...")
    doip_auth_df = sweep_doip_injection(DOIP_RATES, skip_routing_activation=False, repeats=REPEATS)

    all_df = pd.concat([flood_df, spoof_df, doip_unauth_df, doip_auth_df], ignore_index=True)
    csv_path = save_results(all_df, "evaluation_results.csv")
    print(f"\nSaved combined results to: {csv_path}")

    summary = all_df.groupby("attack").agg(
        detection_rate=("detected", "mean"),
        mean_baseline_false_positives=("baseline_false_positives", "mean"),
        mean_time_to_detect_s=("time_to_detect_s", "mean"),
        trials=("detected", "count"),
    )
    summary["detection_rate"] = (summary["detection_rate"] * 100).round(1)
    print("\n=== Summary by attack type ===")
    print(summary.to_string())

    plot1 = plot_detection_rate_by_intensity(
        pd.concat([flood_df, spoof_df], ignore_index=True),
        "detection_rate_flood_spoof.png",
        "Detection rate vs attack intensity (CAN-side attacks)",
    )
    plot2 = plot_detection_rate_by_intensity(
        pd.concat([doip_unauth_df, doip_auth_df], ignore_index=True),
        "detection_rate_doip.png",
        "Detection rate vs attack intensity (DoIP injection)",
    )
    plot3 = plot_false_positive_summary(all_df, "false_positive_summary.png")

    print(f"\nSaved plots:\n  {plot1}\n  {plot2}\n  {plot3}")


if __name__ == "__main__":
    main()
