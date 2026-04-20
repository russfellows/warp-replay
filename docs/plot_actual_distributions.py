"""
plot_actual_distributions.py
Reads docs/dist_samples.tsv produced by the real Go code (go run ./docs/sample_distributions)
and plots the actual empirical distributions.  This is the ground-truth visualisation — the
data comes from the same GetExpRandSize / GetLogNormalRandSize functions that run in production.

Usage:
    go run ./docs/sample_distributions -n 100000 -typical 10MiB > docs/dist_samples.tsv
    python docs/plot_actual_distributions.py
"""

import sys
import math
import pathlib
import polars as pl
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

TSV = pathlib.Path(__file__).parent / "dist_samples.tsv"
OUT = pathlib.Path(__file__).parent / "randsize_distribution.png"

# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------
df = pl.read_csv(TSV, separator="\t")
print(df.head(5))
print(f"\nSchema: {df.schema}")
print(f"Rows: {len(df)}")

for mode, label in [("log2", "log₂"), ("logn", "lognormal")]:
    sub = df.filter(pl.col("mode") == mode)["size_bytes"].to_numpy()
    mib = sub / (1024**2)
    typ_mib = sub[0] if False else df.filter(pl.col("mode") == mode)["typical_bytes"][0] / (1024**2)
    max_mib = df.filter(pl.col("mode") == mode)["max_bytes"][0] / (1024**2)
    print(f"\n{label} (n={len(sub):,}):")
    print(f"  typical (--obj.size input) = {typ_mib:.1f} MiB")
    print(f"  computed max               = {max_mib:.1f} MiB")
    print(f"  observed min  = {mib.min():.3f} MiB")
    print(f"  observed mean = {mib.mean():.3f} MiB  ({100*mib.mean()/max_mib:.1f}% of max)")
    print(f"  observed p50  = {np.percentile(mib,50):.3f} MiB")
    print(f"  observed p90  = {np.percentile(mib,90):.3f} MiB")
    print(f"  observed p99  = {np.percentile(mib,99):.3f} MiB")
    print(f"  observed max  = {mib.max():.3f} MiB")

# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
fig.suptitle(
    "Actual object-size distributions sampled from production Go code\n"
    "(same functions that run during warp benchmarks)",
    fontsize=12, y=1.01,
)

COLORS = {"log2": "#2196F3", "logn": "#FF9800"}

for ax, (mode, label) in zip(axes, [("log2", "log₂"), ("logn", "lognormal")]):
    sub    = df.filter(pl.col("mode") == mode)["size_bytes"].to_numpy()
    mib    = sub / (1024**2)
    typ_b  = df.filter(pl.col("mode") == mode)["typical_bytes"][0]
    max_b  = df.filter(pl.col("mode") == mode)["max_bytes"][0]
    typ_mib = typ_b / (1024**2)
    max_mib = max_b / (1024**2)
    mean_mib   = float(mib.mean())
    median_mib = float(np.percentile(mib, 50))

    # log-spaced bins from ≥1 KiB to max
    lo = math.log2(max(mib.min(), 0.001))
    hi = math.log2(max_mib * 1.05)
    bins = np.power(2, np.linspace(lo, hi, 60))

    ax.hist(mib, bins=bins, color=COLORS[mode], alpha=0.85, edgecolor="white", linewidth=0.3)
    ax.set_xscale("log", base=2)

    # Reference lines
    ax.axvline(typ_mib,    color="green",  linewidth=1.8, linestyle="--",
               label=f"--obj.size (typical) = {typ_mib:.0f} MiB")
    ax.axvline(mean_mib,   color="red",    linewidth=1.5, linestyle="-.",
               label=f"mean = {mean_mib:.1f} MiB ({100*mean_mib/max_mib:.1f}% of max)")
    ax.axvline(median_mib, color="purple", linewidth=1.5, linestyle=":",
               label=f"median = {median_mib:.1f} MiB")
    ax.axvline(max_mib,    color="black",  linewidth=1.2, linestyle="-",
               label=f"computed max = {max_mib:.0f} MiB")

    ax.xaxis.set_major_formatter(ticker.FuncFormatter(
        lambda v, _: f"{v:.0f}" if v >= 1 else f"{v:.3f}"
    ))
    ax.set_xlabel("Object size (MiB, log₂ scale)")
    ax.set_ylabel("Sample count")

    subtitle = (
        f"GetExpRandSize(rng, 0, {max_mib:.0f} MiB)\n"
        f"Equal weight per doubling"
    ) if mode == "log2" else (
        f"GetLogNormalRandSize(rng, 0, {max_mib:.0f} MiB, σ=1.0)\n"
        f"mu = ln(max/10), median = max/10 = typical"
    )
    ax.set_title(f"{label} distribution\n{subtitle}", fontsize=10)
    ax.legend(fontsize=8)
    ax.grid(True, which="both", alpha=0.3)

plt.tight_layout()
plt.savefig(OUT, dpi=150, bbox_inches="tight")
print(f"\nSaved: {OUT}")
