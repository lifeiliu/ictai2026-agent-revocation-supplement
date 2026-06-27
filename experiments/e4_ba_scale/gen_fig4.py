"""Generate Figure 4: BA scale experiment results."""

import sys
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

sys.path.insert(0, str(Path(__file__).parents[2]))
from experiments.e4_ba_scale.run import run_trial, summarise

# ── Run experiments ────────────────────────────────────────────────────────────
configs = [
    (100,  2, 50, 50),
    (100,  4, 50, 50),
    (500,  2, 50, 50),
    (500,  4, 50, 50),
    (2000, 2, 30, 30),
    (2000, 4, 30, 30),
]

summaries = []
for n, m, n_graphs, n_edges in configs:
    print(f"n={n}, m={m} ...", end=" ", flush=True)
    r = run_trial(n, m, n_graphs=n_graphs, n_edges=n_edges)
    s = summarise(r, n)
    s["m"] = m
    summaries.append(s)
    print("done")

ns_m2 = [s["n"] for s in summaries if s["m"] == 2]
ns_m4 = [s["n"] for s in summaries if s["m"] == 4]
or_m2 = [s["tree_overrev_mean"] for s in summaries if s["m"] == 2]
or_m4 = [s["tree_overrev_mean"] for s in summaries if s["m"] == 4]
or_m2_pct = [s["tree_overrev_pct"] for s in summaries if s["m"] == 2]
or_m4_pct = [s["tree_overrev_pct"] for s in summaries if s["m"] == 4]
mp_m2 = [s["mp_rate_pct"] for s in summaries if s["m"] == 2]
mp_m4 = [s["mp_rate_pct"] for s in summaries if s["m"] == 4]

# ── Figure ─────────────────────────────────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(10, 4))
fig.suptitle("E4: Tree Cascade Failure on Barabási-Albert Scale-Free DAGs",
             fontsize=11, fontweight="bold")

# Panel A: Mean OverRev (absolute nodes) vs n
ax = axes[0]
ax.plot(ns_m2, or_m2, "o-", color="#d62728", linewidth=2, markersize=8, label="m=2")
ax.plot(ns_m4, or_m4, "s--", color="#9467bd", linewidth=2, markersize=8, label="m=4")
ax.set_xlabel("Graph size n (nodes)", fontsize=10)
ax.set_ylabel("Mean |OverRev| (wrongly revoked nodes)", fontsize=10)
ax.set_title("A: OverRev magnitude (absolute)", fontsize=10)
ax.set_xscale("log")
ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{int(x):,}"))
ax.legend(title="Attachment m", fontsize=9)
ax.grid(True, alpha=0.3)
ax.annotate("100% of revocations fail\n(prevalence = 1.0 for all cells)",
            xy=(0.5, 0.05), xycoords="axes fraction",
            ha="center", va="bottom", fontsize=8,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#fff3cd", alpha=0.8))

# Panel B: OverRev as % of graph size vs n
ax = axes[1]
ax.plot(ns_m2, or_m2_pct, "o-", color="#d62728", linewidth=2, markersize=8, label="m=2")
ax.plot(ns_m4, or_m4_pct, "s--", color="#9467bd", linewidth=2, markersize=8, label="m=4")
ax.set_xlabel("Graph size n (nodes)", fontsize=10)
ax.set_ylabel("|OverRev| / n  (%)", fontsize=10)
ax.set_title("B: OverRev as % of graph size", fontsize=10)
ax.set_xscale("log")
ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{int(x):,}"))
ax.legend(title="Attachment m", fontsize=9)
ax.grid(True, alpha=0.3)
ax.annotate("Higher m → denser multi-parent structure\n→ larger cascade error",
            xy=(0.5, 0.95), xycoords="axes fraction",
            ha="center", va="top", fontsize=8,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#d4edda", alpha=0.8))

plt.tight_layout()

out = Path(__file__).parents[2] / "figures"
out.mkdir(exist_ok=True)
for ext in ("pdf", "png"):
    plt.savefig(out / f"fig4_e4_ba_scale.{ext}", dpi=150, bbox_inches="tight")
    print(f"Saved fig4_e4_ba_scale.{ext}")

plt.close()

# ── Print summary table ────────────────────────────────────────────────────────
print("\nSummary table (for paper §7.4):")
print(f"{'n':>6} {'m':>3} {'MP%':>7} {'T2 mean':>8} "
      f"{'Casc Prev':>10} {'OverRev':>8} {'OverRev%':>9}")
print("-" * 58)
for s in summaries:
    print(f"  {s['n']:>4} {s['m']:>3}   {s['mp_rate_pct']:>5.1f}%  "
          f"{s['t2_mean']:>6.2f}    "
          f"{s['tree_prev_pct']:>7.1f}%  "
          f"{s['tree_overrev_mean']:>7.1f}  "
          f"{s['tree_overrev_pct']:>7.2f}%")
