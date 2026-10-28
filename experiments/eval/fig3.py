"""Fig. 3: replay cost of the four judges on the same synthetic THR-015 stream (shaped like the real added
records). (a) peak resident memory of the judge process vs distinct proofs held in state; (b) p95 decision
latency vs offered load (open loop). Measurements come from experiments/eval/harness (CSV); this module only
summarises and plots them. Medians over repeats are plotted; ranges remain in JSON.
Memory remains the original common 10--10,000 range. The 100,000-proof probe is
reported separately. 3,000 runs/s is retained in data but not plotted (Echo queues)."""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

OUT = Path(__file__).resolve().parents[2] / "results"
RAW = OUT / "data" / "cost"
SHOW_RANGE = False   # min-max over repeats kept in data/fig3.json, not drawn
STY = {"pltl": ("Two-valued (PLTL)", "k", "o", "-"),
       "ltl3": ("Three-valued (LTL3)", "tab:blue", "v", "-."),
       "fo": ("First-order (MonPoly)", "tab:green", "s", "--"),
       "tdid": ("T-DID", "tab:red", "^", "-"),
       "tdid_diag": ("T-DID, rule and state only (diagnostic)", "tab:red", "^", (0, (4, 2))),
       "echo": ("Harness only (no judge)", "0.55", "x", ":")}


def _rows(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader(f))


def summarise() -> dict:
    mem = defaultdict(lambda: defaultdict(list))
    for r in _rows(RAW / "memory.csv"):
        if r["peak_rss_kib"] not in ("", "None", None):
            mem[r["judge"]][int(r["n_proofs"])].append(int(r["peak_rss_kib"]) / 1024)
    lat = defaultdict(lambda: defaultdict(list))
    thr = defaultdict(lambda: defaultdict(list))
    backlog = defaultdict(lambda: defaultdict(list))
    for r in _rows(RAW / "latency_summary.csv"):
        if r["p95_ms"] not in ("", "None", "nan"):
            lat[r["judge"]][float(r["load"])].append(float(r["p95_ms"]) / 1000)
        thr[r["judge"]][float(r["load"])].append(float(r["achieved_runs_per_s"]))
        backlog[r["judge"]][float(r["load"])].append(int(r["backlog_at_end"]))
    def pack(d):
        return {j: {str(k): {"median": float(np.median(v)), "min": float(min(v)), "max": float(max(v))}
                    for k, v in sorted(s.items())} for j, s in d.items()}
    out = {"memory_mib": pack(mem), "p95_s": pack(lat), "achieved_runs_per_s": pack(thr),
           "backlog_at_end": pack(backlog)}
    out['scope'] = {'target': 'THR-015 only', 'tdid_active_rules': 1,
                    'memory': 'original matched range; 100k diagnostic separate',
                    'latency_plot_max_runs_per_s': 2000,
                    'all_rules_results': 'cost_followup/latency_summary.csv'}
    # saturation: first load whose median achieved throughput is below 95% of the offered load
    sat = {}
    for j, s in thr.items():
        sat[j] = next((k for k in sorted(s) if np.median(s[k]) < 0.95 * k), None)
    out["saturation_runs_per_s"] = sat
    return out


def plot(s: dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.grid": True, "grid.linestyle": ":",
                         "grid.alpha": 0.6, "legend.frameon": True, "legend.framealpha": 1,
                         "legend.edgecolor": "black", "legend.fontsize": 6.5, "axes.labelsize": 8,
                         "xtick.labelsize": 7, "ytick.labelsize": 7, "pdf.fonttype": 42})
    fig, axs = plt.subplots(1, 2, figsize=(7.1, 2.6))
    for key, ax in (("memory_mib", axs[0]), ("p95_s", axs[1])):
        for j, (lab, c, mk, ls) in STY.items():
            d = s[key].get(j)
            if not d or (key == "memory_mib" and j == "tdid_diag"):   # diagnostic line: latency only
                continue
            if key == 'p95_s':
                d = {k: v for k, v in d.items() if float(k) <= 2000}
            x = np.array([float(k) for k in d])
            order = np.argsort(x)
            med = np.array([v["median"] for v in d.values()])[order]
            lo = np.array([v["min"] for v in d.values()])[order]
            hi = np.array([v["max"] for v in d.values()])[order]
            # min-max over repeats as error bars, dodged in log space per judge
            xd = x[order] * (1 + 0.035 * (list(STY).index(j) - 2.5))
            if SHOW_RANGE:
                ax.errorbar(xd, med, yerr=[np.maximum(med - lo, 0), np.maximum(hi - med, 0)], fmt="none", ecolor=c, elinewidth=0.6, capsize=1.6,
                            capthick=0.6, alpha=0.8)
            ax.plot(x[order], med, color=c, marker=mk, ms=3.5, mfc="none", lw=1, ls=ls, label=lab)
    axs[0].set_xscale("log")
    axs[0].set_xlabel("Distinct proofs held in state\n(a)")
    axs[0].set_ylabel("Peak resident memory (MiB)")

    axs[1].set_xscale("log")
    axs[1].set_yscale("log")
    axs[1].set_xlabel("Offered load (runs/s)\n(b)")
    axs[1].set_ylabel("p95 latency (s)")
    h, lab = axs[0].get_legend_handles_labels()
    h2, lab2 = axs[1].get_legend_handles_labels()
    for hh, ll in zip(h2, lab2, strict=True):
        if ll not in lab:
            h.append(hh)
            lab.append(ll)
    fig.legend(h, lab, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.0))
    fig.tight_layout(rect=[0, 0, 1, 0.84])
    fig.savefig(OUT / "fig3.pdf", bbox_inches="tight", pad_inches=0.02)
    fig.savefig(OUT / "fig3.png", dpi=250, bbox_inches="tight", pad_inches=0.02)


def main() -> None:
    s = summarise()
    (OUT / "data" / "fig3.json").write_text(json.dumps(s, indent=2) + "\n")
    plot(s)
    json.dump({k: s[k] for k in ("saturation_runs_per_s",)}, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
