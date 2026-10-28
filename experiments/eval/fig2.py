"""Fig. 2: wrong and withheld verdicts as required evidence is lost, four judges on the same events.

Input: the T-DID evidence condition (added records) of all 39 workflows with known ground truth
(THR-015: 15 walt.id + 12 Credo TS issuance runs; THR-019: 12 presentation runs). For each loss ratio p
(0, 0.1, ..., 1) and seed (30 seeds), every required evidence item of every event is removed independently
with probability p (field-level items; see experiments/eval/loss). The same lossy events go to T-DID and to
the three comparators (two-valued PLTL, three-valued LTL3, first-order MFOTL). Each judge's per-decision
verdicts are aggregated per workflow with the common rule, then scored against ground truth:
  wrong    = decided verdict (attack / no attack) that contradicts the ground truth
  withheld = undetermined (T-DID incomplete_evidence, LTL3 '?')
Both as a share of the 39 workflows. Before anything is plotted, the four judges must give the same verdict
on every workflow that T-DID decides at p = 0 (complete information); otherwise the run stops.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import numpy as np

from experiments.eval.common import (
    ATTACK,
    NO_ATTACK,
    PRODUCTS,
    THREAT,
    WITHHELD,
    events,
    layout,
    per_case,
    tdid_event_verdicts,
)

OUT = Path(__file__).resolve().parents[2] / "results"
PS = [round(x, 1) for x in np.arange(0, 1.0001, 0.1)]
SEEDS = range(30)
JUDGE_NAMES = ("pltl", "fo", "ltl3", "tdid")
MON_TO = {"attack": ATTACK, "no_attack": NO_ATTACK, "undetermined": WITHHELD}

# which T-DID conditions an evidence item can leave unknown (for checking that T-DID names what is missing)
AFFECTS = {
    "proof_ref": {"SameProofAcceptedBefore", "ExceedsAllowedUses", "ReturnsNewCredential"},
    "key_proof_check": {"KeyProofValidated", "SameProofAcceptedBefore", "ExceedsAllowedUses",
                        "ReturnsNewCredential"},
    "output_ref": {"ReturnsNewCredential", "SameProofAcceptedBefore", "ExceedsAllowedUses"},
    "decision": {"Issued", "RelyingDecisionAccepted", "SameProofAcceptedBefore", "ExceedsAllowedUses",
                 "ReturnsNewCredential"},
    "request_ref": {"DirectPostResponseMode", "WalletCompletedRequest", "InitiatingSessionConcluded",
                    "CompletionBindingIneffective", "CompletingContextDiffers", "InitiatorIsNotWalletUser",
                    "RelyingDecisionAccepted"},
    # without the session link the decision cannot be tied to the initiating session, so every
    # decision-side condition of the initiating session is unknown (thr019 provisional subject)
    "frontend_session_ref": {"InitiatingSessionConcluded", "CompletionBindingIneffective",
                             "CompletingContextDiffers", "RelyingDecisionAccepted"},
    "vp_response_mode": {"DirectPostResponseMode"},
    "response_code_check": {"CompletionBindingIneffective", "CompletingContextDiffers"},
}


# structurally unobservable (no honest component records it): always unknown when THR-019 is undecided
BLIND = {"InitiatorIsNotWalletUser"}


def field_items() -> dict[str, tuple[str, ...]]:
    from experiments.eval.loss import ITEMS
    return {kind: tuple(i for i in items if i != "record") for kind, items in ITEMS.items()}


def judge_all(product: str, evs: list[dict[str, Any]], index_case: list[str]) -> dict[str, dict[str, str]]:
    from experiments.eval.monitors import judge
    out: dict[str, dict[str, str]] = {}
    ids = {ev["event_id"]: i for i, ev in enumerate(evs)}
    for name in ("pltl", "fo", "ltl3"):
        by_index: dict[int, list[str]] = {}
        for row in judge(name, evs, THREAT[product]):
            by_index.setdefault(ids[row["event_id"]], []).append(MON_TO[row["verdict"]])
        out[name] = per_case(index_case, by_index)
    out["tdid"] = per_case(index_case, tdid_event_verdicts(evs, THREAT[product]))
    return out


def tdid_unknowns(product: str, evs: list[dict[str, Any]], index_case: list[str],
                  any_verdict: bool = False) -> dict[str, set[str]]:
    """Unknown conditions T-DID reports per workflow (of incomplete findings; with ``any_verdict`` of all
    findings, i.e. conditions already unknown before any loss)."""
    from tdid.dataset import run_result
    ids = {ev["event_id"]: i for i, ev in enumerate(evs)}
    out: dict[str, set[str]] = {}
    for f in run_result(evs)["findings"]:
        if f["threat_id"] == THREAT[product] and (any_verdict or f["verdict"] == "incomplete"):
            out.setdefault(index_case[ids[f["trigger_event_id"]]], set()).update(f["unknown_conditions"])
    return out


def equivalence() -> dict[str, Any]:
    """p = 0: all four judges on every workflow T-DID decides (complete information)."""
    report: dict[str, Any] = {"checked": 0, "mismatches": [], "withheld_by_tdid": []}
    for product in PRODUCTS:
        lay = layout(product)
        evs = events(product, "added")
        v = judge_all(product, evs, lay.index_case["added"])
        for c in lay.cases:
            if c.truth == "unknown":
                continue
            t = v["tdid"].get(c.case_id)
            row = {j: v[j].get(c.case_id) for j in JUDGE_NAMES}
            if t == WITHHELD:
                report["withheld_by_tdid"].append({"product": product, "case": c.case_id, **row})
                continue
            report["checked"] += 1
            if len(set(row.values())) != 1:
                report["mismatches"].append({"product": product, "case": c.case_id, "truth": c.truth, **row})
    return report


def sweep() -> dict[str, Any]:
    from experiments.eval.loss import drop
    items = field_items()
    lays = {p: layout(p) for p in PRODUCTS}
    base = {p: events(p, "added") for p in PRODUCTS}
    base_unknown = {p: tdid_unknowns(p, base[p], lays[p].index_case["added"], True) for p in PRODUCTS}
    total = sum(1 for p in PRODUCTS for c in lays[p].cases if c.truth != "unknown")
    wrong = {j: np.zeros((len(SEEDS), len(PS))) for j in JUDGE_NAMES}
    held = {j: np.zeros((len(SEEDS), len(PS))) for j in JUDGE_NAMES}
    named = {"withheld": 0, "explained": 0}
    # attack runs only: what each judge reports for a real attack (panel c)
    cats = ("missed", "withheld", "detected")
    att = {j: {k: np.zeros((len(SEEDS), len(PS))) for k in cats} for j in JUDGE_NAMES}
    n_attacks = sum(1 for p in PRODUCTS for c in lays[p].cases if c.truth == ATTACK)
    for si, seed in enumerate(SEEDS):
        for pi, p in enumerate(PS):
            for product in PRODUCTS:
                lay = lays[product]
                lossy, removed = drop(base[product], p, seed, items=items)
                if len(lossy) != len(base[product]):
                    raise RuntimeError("field-level loss must not drop records")
                v = judge_all(product, lossy, lay.index_case["added"])
                removed_by_case: dict[str, set[str]] = {}
                ids = {ev["event_id"]: i for i, ev in enumerate(base[product])}
                for event_id, item in removed:
                    removed_by_case.setdefault(lay.index_case["added"][ids[event_id]], set()).add(item)
                unknown = tdid_unknowns(product, lossy, lay.index_case["added"])
                for c in lay.cases:
                    if c.truth == "unknown":
                        continue
                    for j in JUDGE_NAMES:
                        verdict = v[j].get(c.case_id, NO_ATTACK)   # no output = no alarm
                        if verdict == WITHHELD:
                            held[j][si, pi] += 1
                        elif verdict != c.truth:
                            wrong[j][si, pi] += 1
                        if c.truth == ATTACK:
                            kind = {ATTACK: "detected", WITHHELD: "withheld"}.get(verdict, "missed")
                            att[j][kind][si, pi] += 1
                    if v["tdid"].get(c.case_id) == WITHHELD:
                        named["withheld"] += 1
                        allowed = set(base_unknown[product].get(c.case_id, set())) | BLIND
                        for item in removed_by_case.get(c.case_id, set()):
                            allowed |= AFFECTS[item]
                        if unknown.get(c.case_id, set()) and unknown[c.case_id] <= allowed:
                            named["explained"] += 1
    def stats(a):
        a = 100 * a / total
        return {"mean": a.mean(0).tolist(), "min": a.min(0).tolist(), "max": a.max(0).tolist()}
    def astats(a):
        a = 100 * a / n_attacks
        return {"mean": a.mean(0).tolist(), "min": a.min(0).tolist(), "max": a.max(0).tolist()}
    return {"ps": PS, "seeds": len(SEEDS), "workflows": total,
            "wrong": {j: stats(wrong[j]) for j in JUDGE_NAMES},
            "withheld": {j: stats(held[j]) for j in JUDGE_NAMES},
            "attacks": {"n": n_attacks, **{j: {k: astats(att[j][k]) for k in cats} for j in JUDGE_NAMES}},
            "tdid_missing_named": named}


def plot(data: dict[str, Any]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.grid": True, "grid.linestyle": ":",
                         "grid.alpha": 0.6, "legend.frameon": True, "legend.framealpha": 1,
                         "legend.edgecolor": "black", "legend.fontsize": 6.5, "axes.labelsize": 8,
                         "xtick.labelsize": 7, "ytick.labelsize": 7, "pdf.fonttype": 42})
    # The input encoding yields equal values here; a shared legend makes that
    # visible without implying independent detection evidence from two engines.
    for key in ("wrong", "withheld"):
        assert data[key]["pltl"] == data[key]["fo"], key
    assert data["attacks"]["pltl"] == data["attacks"]["fo"]
    sty = {"pltl": ("PLTL / MonPoly (identical values)", "k", "o", "-"),
           "fo": ("_nolegend_", "tab:green", "s", "--"),
           "ltl3": ("Three-valued (LTL3)", "tab:blue", "v", "-."),
           "tdid": ("T-DID", "tab:red", "^", "-")}
    ps = np.array(data["ps"])
    fig, (ax_a, ax_b, axc) = plt.subplots(1, 3, figsize=(7.1, 2.6))
    axs = [ax_a, ax_b]
    for key, ax, yl in (("wrong", axs[0], "Wrong verdicts (%)"), ("withheld", axs[1], "Withheld verdicts (%)")):
        for k, (j, (lab, c, mk, ls)) in enumerate(sty.items()):
            s = data[key][j]
            _range(ax, ps + DODGE[k], s, c)
            ax.plot(ps, s["mean"], color=c, marker=mk, ms=3.5, mfc="none", lw=1, ls=ls, label=lab)
        ax.set_xlabel("Evidence-loss ratio")
        ax.set_ylabel(yl)
        ax.set_xlim(0, 1)
        top = max(max(data[key][j]["max"]) for j in sty)
        ax.set_ylim(-3, 100) if top > 40 else ax.set_ylim(-1, 30)
        _ticks(ax, ps)
    axs[0].set_xlabel("Evidence-loss ratio\n(a)")
    axs[1].set_xlabel("Evidence-loss ratio\n(b)")
    _attack_panel(axc, data, sty, ps)
    from matplotlib.lines import Line2D
    h, lab = axs[0].get_legend_handles_labels()
    from matplotlib.legend_handler import HandlerTuple
    # Keep the established black / green styles in one shared legend entry.
    h[0] = (axs[0].lines[0], axs[0].lines[1])
    h += [Line2D([], [], color="0.3", lw=1), Line2D([], [], color="0.3", lw=0.9, ls=":")]
    lab += ["(c) solid: no alarm, excluding withheld", "(c) dotted: attack reported"]
    fig.legend(h, lab, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.0),
               handler_map={tuple: HandlerTuple(ndivide=None)})
    fig.tight_layout(rect=[0, 0.0, 1, 0.84])
    fig.savefig(OUT / "fig2.pdf", bbox_inches="tight", pad_inches=0.02)
    fig.savefig(OUT / "fig2.png", dpi=250, bbox_inches="tight", pad_inches=0.02)


# Range over seeds as min-max error bars, dodged slightly per judge so coinciding judges stay readable.
DODGE = np.array([-0.018, -0.006, 0.006, 0.018])


SHOW_RANGE = False   # ranges over seeds are reported in the data / Supplementary, not drawn


def _range(ax, x: np.ndarray, s: dict[str, list[float]], color: str) -> None:
    if not SHOW_RANGE:
        return
    mean, lo, hi = (np.array(s[k]) for k in ("mean", "min", "max"))
    ax.errorbar(x, mean, yerr=[np.maximum(mean - lo, 0), np.maximum(hi - mean, 0)], fmt="none", ecolor=color, elinewidth=0.6, capsize=1.6,
                capthick=0.6, alpha=0.8)


def _ticks(ax, ps: np.ndarray) -> None:
    ax.set_xticks(ps)
    ax.set_xticklabels([f"{x:.1f}" if i % 2 == 0 else "" for i, x in enumerate(ps)])


def _attack_panel(ax, data: dict[str, Any], sty: dict[str, tuple], ps: np.ndarray) -> None:
    """(c) The attack runs only: solid = reported benign (missed), dotted = attack reported (same colour);
    the remainder of each judge is withheld. Error bars: min-max over seeds for the missed share."""
    for k, (j, (lab, c, mk, ls)) in enumerate(sty.items()):
        miss = data["attacks"][j]["missed"]
        _range(ax, ps + DODGE[k], miss, c)
        ax.plot(ps, miss["mean"], color=c, marker=mk, ms=3.5, mfc="none", lw=1, ls=ls)
        ax.plot(ps, data["attacks"][j]["detected"]["mean"], color=c, lw=0.9, ls=":")
    ax.set_xlabel("Evidence-loss ratio")
    ax.set_ylabel(f"Attack runs (%, n={data['attacks']['n']})")
    ax.set_xlim(0, 1)
    ax.set_ylim(-3, 100)
    ax.set_xticks(ps)
    _ticks(ax, ps)
    ax.set_xlabel("Evidence-loss ratio\n(c)")


def main() -> None:
    if "--plot-only" in sys.argv:
        plot(json.loads((OUT / "data" / "fig2.json").read_text()))
        return
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "data").mkdir(exist_ok=True)
    eq = equivalence()
    (OUT / "data" / "fig2_equivalence.json").write_text(json.dumps(eq, indent=2) + "\n")
    print("equivalence: checked", eq["checked"], "mismatches", len(eq["mismatches"]))
    if eq["mismatches"]:
        print(json.dumps(eq["mismatches"], indent=1))
        sys.exit("judges disagree on complete information: encoding bug, Fig. 2 not drawn")
    data = sweep()
    data["equivalence"] = {"checked": eq["checked"], "mismatches": 0}
    (OUT / "data" / "fig2.json").write_text(json.dumps(data, indent=2) + "\n")
    plot(data)
    for k in ("wrong", "withheld"):
        for j in JUDGE_NAMES:
            print(k, j, [round(x, 1) for x in data[k][j]["mean"]])
    print("T-DID withheld workflows whose unknown conditions match the removed items:",
          data["tdid_missing_named"])


if __name__ == "__main__":
    main()
