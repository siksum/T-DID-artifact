"""Input-representation table (formerly Fig. 1): verdicts of the same T-DID engine under four input
representations. Writes data/fig1.json and table_input.tex.

Conditions (x axis)
  Product log        records the unmodified product already emits (collector level ``native``)
  Std. mapping       the T-DID evidence expressed in a generic log standard, core fields only, read back
  Std. + extension   the same with the standard's defined optional/extension fields
  T-DID evidence     records collected per the T-DID field dictionary (collector level ``added``)
For the two middle conditions the four standards (OCSF 1.6.0, ECS 9.1.0, OpenTelemetry Logs, CloudEvents
1.0.2) are evaluated separately; the figure shows the standard that yields the most decided verdicts
(the comparison most favourable to the standards), all four are in the Supplementary table.
The table lists the ground truth, the product log, every standard at both levels and the T-DID evidence
(attack succeeded = T-DID succeeded, benign = no_witness, withheld = incomplete_evidence); wrong verdicts
are counted separately and must be zero for the table (it stops otherwise).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from experiments.eval.common import ATTACK, NO_ATTACK, THREAT, WITHHELD, events, layout, tdid_cases

OUT = Path(__file__).resolve().parents[2] / "results"
CONDITIONS = ("product_log", "std_core", "std_ext", "tdid")
PANELS = {"THR-015": ("waltid", "credo"), "THR-019": ("credo-vp",)}


def _per_request(product: str, evs: list[dict[str, Any]]) -> Counter:
    from tdid.dataset import run_result
    report = run_result(evs)
    return Counter(f["verdict"] for f in report["findings"] if f["threat_id"] == THREAT[product])


def _judge(product: str, evs: list[dict[str, Any]], index_case: list[str]) -> dict[str, str]:
    from tdid.dataset import run_result
    rejected = run_result(evs)["rejected_records"]
    if rejected:
        raise RuntimeError(f"{product}: rejected records {rejected[:2]}")
    return tdid_cases(product, evs, index_case)


def _score(lay, verdicts: dict[str, str]) -> dict[str, int]:
    out = Counter()
    for c in lay.cases:
        if c.truth == "unknown":
            continue
        v = verdicts.get(c.case_id, "none")
        out[v] += 1
        if v in (ATTACK, NO_ATTACK) and v != c.truth:
            out["wrong"] += 1
    return {k: out.get(k, 0) for k in (ATTACK, NO_ATTACK, WITHHELD, "none", "wrong")}


def deployment_config(product: str, evs: list[dict[str, Any]]) -> dict[str, Any]:
    """Operator configuration, identical in every condition: the policy the dataset was packed with (the
    collectors received the same) and the checks each decision type requires (as the collectors declare)."""
    from experiments.eval.common import DATASETS
    manifest = json.loads((DATASETS[product] / "MANIFEST.json").read_text())
    required: dict[str, list[str]] = {}
    for ev in evs:
        for c in ev["checks"]["required"]:
            required.setdefault(ev["event_type"], [])
            if c not in required[ev["event_type"]]:
                required[ev["event_type"]].append(c)
    return {"policy": manifest.get("policy"), "required": required, "fresh": manifest.get("fresh_start", False)}


def run() -> dict[str, Any]:
    from experiments.eval import mappers
    data: dict[str, Any] = {"per_standard": {}, "panels": {}, "per_request": {}}
    for panel, products in PANELS.items():
        totals = {cond: Counter() for cond in CONDITIONS}
        std_totals: dict[str, dict[str, Counter]] = {
            lvl: {s: Counter() for s in mappers.STANDARDS} for lvl in ("core", "ext")}
        for product in products:
            lay = layout(product)
            native, added = events(product, "native"), events(product, "added")
            conds = {"product_log": (native, lay.index_case["native"]),
                     "tdid": (added, lay.index_case["added"])}
            for cond, (evs, idx) in conds.items():
                totals[cond].update(_score(lay, _judge(product, evs, idx)))
                data["per_request"].setdefault(product, {})[cond] = dict(_per_request(product, evs))
            deployment = deployment_config(product, added)
            for lvl in ("core", "ext"):
                for std in mappers.STANDARDS:
                    back = mappers.roundtrip(added, std, lvl, deployment)
                    if len(back) != len(added) or [e["event_type"] for e in back] != [
                            e["event_type"] for e in added]:
                        raise RuntimeError(f"{std}/{lvl}: round trip changed the event sequence")
                    score = _score(lay, _judge(product, back, lay.index_case["added"]))
                    std_totals[lvl][std].update(score)
                    data["per_request"][product][f"{std}_{lvl}"] = dict(_per_request(product, back))
        for lvl in ("core", "ext"):
            data["per_standard"].setdefault(panel, {})[lvl] = {s: dict(c) for s, c in std_totals[lvl].items()}
            # most favourable standard: most decided verdicts, then fewest wrong
            def merit(s):
                c = std_totals[lvl][s]
                return c[ATTACK] + c[NO_ATTACK] - c["wrong"]
            top = max(merit(s) for s in mappers.STANDARDS)
            best = [s for s in mappers.STANDARDS if merit(s) == top]
            if any(std_totals[lvl][s] != std_totals[lvl][best[0]] for s in best):
                raise RuntimeError(f"{panel}/{lvl}: tied standards differ in verdict counts")
            totals[f"std_{lvl}"] = std_totals[lvl][best[0]]
            data["panels"].setdefault(panel, {})[f"best_{lvl}"] = best
        data["panels"][panel]["counts"] = {cond: dict(totals[cond]) for cond in CONDITIONS}
        data["panels"][panel]["n"] = sum(totals["tdid"][k] for k in (ATTACK, NO_ATTACK, WITHHELD, "none"))
    return data


COND = [("product_log", "Product log"), ("std_core", "Standard-field mapping"),
        ("std_ext", "Standard + extension fields"), ("tdid", "T-DID evidence")]


def truth_counts(products: tuple[str, ...]) -> dict[str, int]:
    out = {ATTACK: 0, NO_ATTACK: 0, WITHHELD: 0}
    for p in products:
        for c in layout(p).cases:
            if c.truth in (ATTACK, NO_ATTACK):
                out[c.truth] += 1
    return out


def table(data: dict[str, Any]) -> str:
    """LaTeX table (replaces the former Fig. 1): workflow verdicts of the same T-DID engine per input
    condition, every standard at both levels, with the ground truth on top."""
    std_names = {"ocsf": "OCSF 1.6.0", "ecs": "ECS 9.1.0", "otel": "OpenTelemetry Logs",
                 "cloudevents": "CloudEvents 1.0.2"}

    def cells(c: dict[str, int], truth: bool = False) -> list[str]:
        out = [str(c.get(ATTACK, 0)), str(c.get(NO_ATTACK, 0))]
        out.append("--" if truth else str(c.get(WITHHELD, 0)))
        return out

    def row(label: str, per_panel: list[dict[str, int]], truth: bool = False, bold: bool = False) -> str:
        vals = [v for c in per_panel for v in cells(c, truth)]
        if bold:
            label, vals = rf"\textbf{{{label}}}", [rf"\textbf{{{v}}}" for v in vals]
        return f"{label} & " + " & ".join(vals) + r" \\"

    panels = list(PANELS)
    for panel in panels:
        for cond in CONDITIONS:
            if data["panels"][panel]["counts"][cond]["wrong"]:
                raise RuntimeError("a wrong verdict exists; the table has no column for it")
        for lvl in ("core", "ext"):
            if any(v["wrong"] for v in data["per_standard"][panel][lvl].values()):
                raise RuntimeError("a wrong verdict exists; the table has no column for it")
    n = {p: data["panels"][p]["n"] for p in panels}
    lines = [
        r"\begin{table}[t]",
        r"\centering\footnotesize",
        r"\caption{Verdicts of the same T-DID engine on the same runs under different input representations "
        rf"(THR-015: {n['THR-015']} issuer runs with known product outcome; THR-019: {n['THR-019']} "
        r"presentation runs). A: threat\_witness (attack succeeded), B: no\_witness (benign), W: "
        r"incomplete\_evidence (withheld). Standard rows carry the T-DID evidence through the standard and "
        r"back, using its own fields (core) or also its defined optional and extension fields (ext). No "
        r"condition produced a wrong verdict.}",
        r"\label{tab:input-representation}",
        r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{@{}lcccccc@{}}\toprule",
        r" & \multicolumn{3}{c}{THR-015} & \multicolumn{3}{c}{THR-019} \\",
        r"\cmidrule(lr){2-4}\cmidrule(lr){5-7}",
        r"Input condition & A & B & W & A & B & W \\ \midrule",
        row("Ground truth", [truth_counts(PANELS[p]) for p in panels], truth=True),
        r"\midrule",
        row("Product log", [data["panels"][p]["counts"]["product_log"] for p in panels]),
    ]
    for lvl, title in (("core", "Standard fields"), ("ext", "Standard + extension fields")):
        lines.append(rf"\multicolumn{{7}}{{@{{}}l}}{{\textit{{{title}}}}} \\")
        for std, name in std_names.items():
            lines.append(row(rf"\quad {name}", [data["per_standard"][p][lvl][std] for p in panels]))
    lines += [row("T-DID evidence", [data["panels"][p]["counts"]["tdid"] for p in panels], bold=True),
              r"\bottomrule\end{tabular}", r"\end{table}", ""]
    return "\n".join(lines)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    data = run()
    (OUT / "data").mkdir(exist_ok=True)
    (OUT / "data" / "fig1.json").write_text(json.dumps(data, indent=2) + "\n")
    (OUT / "table_input.tex").write_text(table(data))
    print(json.dumps(data["panels"], indent=1))
    print(json.dumps(data["per_standard"], indent=1))


if __name__ == "__main__":
    main()
