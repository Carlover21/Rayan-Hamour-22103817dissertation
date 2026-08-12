"""
Extended evaluation run: covers the features added after the original
proposal scope - the bus-off attack, the infotainment-pivot and key-fob-relay
attack surfaces, SecOC authentication (with vs without), and a paired
rule-based-vs-ML detector comparison. Kept separate from run_evaluation.py
so the original evaluation (matching the proposal's stated scope) stays a
clean, unmodified baseline.

Usage:
    python run_evaluation_extended.py
"""

from __future__ import annotations

import pandas as pd

from carnet.eval.plots import (
    plot_detection_rate_by_intensity,
    plot_ml_vs_rule_comparison,
)
from carnet.eval.sweep import (
    save_results,
    sweep_busoff,
    sweep_infotainment_pivot,
    sweep_key_fob_relay,
    sweep_ml_vs_rule_comparison,
    sweep_secoc_comparison,
)

BUSOFF_RATES = [20, 50, 100]
INFOTAINMENT_RATES = [10, 30, 60]
SECOC_RATES = [2, 5, 10, 20]
REPEATS = 3


def main() -> None:
    print("Running bus-off attack sweep...")
    busoff_df = sweep_busoff(BUSOFF_RATES, repeats=REPEATS)

    print("Running infotainment-pivot attack sweep...")
    infotainment_df = sweep_infotainment_pivot(INFOTAINMENT_RATES, repeats=REPEATS)

    print("Running key-fob-relay attack (single-event, repeated trials)...")
    keyfob_df = sweep_key_fob_relay(repeats=10)

    print("Running SecOC comparison (authorized DoIP abuse, with vs without authentication)...")
    secoc_df = sweep_secoc_comparison(SECOC_RATES, repeats=REPEATS)

    print("Running rule-based vs ML detector comparison...")
    ml_df = sweep_ml_vs_rule_comparison(repeats=5)

    combined = pd.concat([busoff_df, infotainment_df, keyfob_df], ignore_index=True)
    csv1 = save_results(combined, "extended_attacks_results.csv")
    csv2 = save_results(secoc_df, "secoc_comparison_results.csv")
    csv3 = save_results(ml_df, "ml_vs_rule_results.csv")
    print(f"\nSaved: {csv1}\nSaved: {csv2}\nSaved: {csv3}")

    print("\n=== New attack types: detection rate by intensity ===")
    print(combined.groupby("attack")["detected"].mean().mul(100).round(1).to_string())

    print("\n=== Key-fob relay (single event, not rate-based) ===")
    print(f"Detection rate: {keyfob_df['detected'].mean() * 100:.1f}%  ({len(keyfob_df)} trials)")

    print("\n=== SecOC: detection rate with vs without authentication ===")
    print(secoc_df.groupby("secoc_enabled")["detected"].mean().mul(100).round(1).to_string())

    print("\n=== Rule-based vs ML detection rate ===")
    print(ml_df.groupby("attack")[["rule_detected", "ml_detected"]].mean().mul(100).round(1).to_string())
    print("\n=== False positives during baseline (rule vs ML) ===")
    print(ml_df.groupby("attack")[["rule_baseline_fp", "ml_baseline_fp"]].mean().round(2).to_string())

    plot1 = plot_detection_rate_by_intensity(
        combined[combined["attack"] != "key_fob_relay"],
        "detection_rate_extended_attacks.png",
        "Detection rate vs intensity - bus-off & infotainment-pivot attacks",
    )
    plot2 = plot_detection_rate_by_intensity(
        secoc_df.assign(attack=secoc_df["attack"]),
        "detection_rate_secoc_comparison.png",
        "Detection rate vs intensity - authorized DoIP abuse, with vs without SecOC",
    )
    plot3 = plot_ml_vs_rule_comparison(ml_df, "ml_vs_rule_comparison.png")

    print(f"\nSaved plots:\n  {plot1}\n  {plot2}\n  {plot3}")


if __name__ == "__main__":
    main()
