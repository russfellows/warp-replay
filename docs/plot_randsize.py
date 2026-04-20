"""
Generate a comparison plot of the log₂ distribution vs the lognormal
distribution for warp's --obj.rand-log2 and --obj.rand-logn flags.

Both panels use --obj.size=10 MiB (the typical / user-facing size).
  --obj.rand-log2:  obj.size = target average  → max = 10 MiB / 0.179151 ≈ 55.8 MiB
  --obj.rand-logn:  obj.size = target median   → max = 10 MiB × 10        = 100 MiB

Plotted as histograms with SIZE on the X axis (log2 scale) and object
count on the Y axis.  Parameters: 50,000 samples, sigma=1.0.
"""

import math
import random
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

# --- Parameters -------------------------------------------------------
# Both panels use the same user-facing "typical" size.
TYPICAL_SIZE = 10 * 1024 * 1024   # --obj.size=10MiB

# Internally computed maxima (mirrors cli/generator.go logic)
LOG2_AVG_FACTOR = 0.179151
MAX_LOG2 = int(TYPICAL_SIZE / LOG2_AVG_FACTOR)   # ≈ 55.8 MiB
MAX_LOGN = TYPICAL_SIZE * 10                       # = 100 MiB

MIN_SIZE = 1
SIGMA    = 1.0
N        = 50_000
rng      = random.Random(42)

def fmt_bytes(n):
    for unit, div in [("GiB", 1<<30), ("MiB", 1<<20), ("KiB", 1<<10)]:
        if n >= div:
            return f"{n/div:.1f} {unit}"
    return f"{n} B"

# --- Log2 (legacy) sampler -------------------------------------------
def legacy_exp_rand_size(min_size, max_size):
    if max_size - min_size < 10:
        return 1 + min_size
    log_max = math.log2(max_size - 1)
    log_min = max(7.0, log_max - 8)
    if min_size > 0:
        log_min = math.log2(max(2, min_size) - 1)
    delta  = log_max - log_min
    r      = rng.random()
    log_s  = r * delta
    if log_s > 1:
        return 1 + int(2 ** (log_s + log_min))
    # Use log_s (not r) to be continuous with the log branch above — mirrors Go fix.
    return 1 + min_size + int(log_s * 2 ** (log_min + 1))

# --- Lognormal (new) sampler -----------------------------------------
def lognormal_rand_size(min_size, max_size, sigma=1.0):
    mu = math.log(max_size / 10.0)
    for _ in range(100):
        s = round(math.exp(mu + sigma * rng.gauss(0, 1)))
        if min_size <= s <= max_size:
            return s
    s = round(math.exp(mu + sigma * rng.gauss(0, 1)))
    return max(min_size, min(max_size, s))

# --- Sample -----------------------------------------------------------
# Both use --obj.size=10MiB as input; max is computed internally.
legacy_sizes    = [legacy_exp_rand_size(MIN_SIZE, MAX_LOG2)          for _ in range(N)]
lognormal_sizes = [lognormal_rand_size(MIN_SIZE, MAX_LOGN, SIGMA)    for _ in range(N)]

legacy_mean    = sum(legacy_sizes)    / N
lognormal_mean = sum(lognormal_sizes) / N
lognormal_median = sorted(lognormal_sizes)[N // 2]

# Bins: one per doubling, covering both distributions
max_overall = max(MAX_LOG2, MAX_LOGN)
bin_edges = [2**k for k in range(7, 32) if 2**k <= max_overall * 1.01]
bin_edges = sorted(set(bin_edges + [max_overall]))

# --- Plot -------------------------------------------------------------
fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=False)
fig.suptitle(
    f"warp --obj.size=10MiB: same user input, different distributions  |  n={N:,}, \u03c3={SIGMA}",
    fontsize=12, fontweight="bold"
)

tick_bytes  = [128, 1<<10, 8<<10, 64<<10, 512<<10, 4<<20, 32<<20, 128<<20]
tick_labels = ["128 B", "1 KiB", "8 KiB", "64 KiB", "512 KiB", "4 MiB", "32 MiB", "128 MiB"]

def make_panel(ax, data, title, color, mean_val, median_val, annot):
    counts, edges = np.histogram(data, bins=bin_edges)
    centres = [math.sqrt(edges[i] * edges[i+1]) for i in range(len(edges)-1)]
    widths  = [edges[i+1] - edges[i]             for i in range(len(edges)-1)]
    ax.bar(centres, counts, width=widths, color=color, edgecolor="white",
           linewidth=0.4, alpha=0.85, align="center")

    ax.set_xscale("log", base=2)
    ax.set_xticks(tick_bytes)
    ax.set_xticklabels(tick_labels, rotation=35, ha="right", fontsize=8.5)
    ax.set_xlim(100, max_overall * 1.8)
    ax.set_xlabel("Object Size  (log\u2082 scale)", fontsize=10)
    ax.set_ylabel("Number of Objects", fontsize=10)
    ax.set_title(title, fontsize=10, fontweight="bold")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.grid(axis="y", alpha=0.3)

    ax.axvline(mean_val, color="black", linewidth=1.2, linestyle="--")
    ymax = ax.get_ylim()[1]
    ax.text(mean_val * 1.15, ymax * 0.82,
            f"mean\n{fmt_bytes(int(mean_val))}", fontsize=8)

    ax.text(0.03, 0.95, annot, transform=ax.transAxes, fontsize=8,
            va="top", bbox=dict(boxstyle="round,pad=0.3", fc="white", alpha=0.85))

make_panel(axes[0], legacy_sizes,
           f"--obj.size=10MiB --obj.rand-log2\n(avg=10 MiB \u2192 max={fmt_bytes(MAX_LOG2)} computed internally)",
           "#e07b54", legacy_mean, legacy_mean,
           f"Equal count per doubling\n(flat in log\u2082-space)\nNo \"typical\" object size\nmax={fmt_bytes(MAX_LOG2)}")

make_panel(axes[1], lognormal_sizes,
           f"--obj.size=10MiB --obj.rand-logn\n(median=10 MiB \u2192 max={fmt_bytes(MAX_LOGN)} computed internally)",
           "#4c8cbf", lognormal_mean, lognormal_median,
           f"Bell curve in log-space\nMedian={fmt_bytes(int(lognormal_median))}\n\u03c3={SIGMA} \u2192 ~9 doublings span\nmax={fmt_bytes(MAX_LOGN)}")

plt.tight_layout()
out = "docs/randsize_distribution.png"
plt.savefig(out, dpi=150, bbox_inches="tight")
print(f"Saved: {out}")
print(f"Log2   input=10MiB, computed max={fmt_bytes(MAX_LOG2)}, mean={fmt_bytes(int(legacy_mean))}  ({legacy_mean/MAX_LOG2*100:.1f}% of max)")
print(f"Logn   input=10MiB, computed max={fmt_bytes(MAX_LOGN)}, mean={fmt_bytes(int(lognormal_mean))} ({lognormal_mean/MAX_LOGN*100:.1f}% of max), median={fmt_bytes(int(lognormal_median))}")
