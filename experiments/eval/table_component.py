"""Component-level evidence loss (handoff 2, part B): every record of one producer role is removed at once;
the four judges then judge the same remaining events. No randomness, no seeds.

Per threat and removed role: wrong verdicts (decided against ground truth), withheld verdicts, and runs with
no output at all (no decision event left; scored as no alarm, the same for every judge). Unknown-truth runs
are excluded as everywhere else. Base = the T-DID evidence condition (added records).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from experiments.eval.common import (ATTACK, NO_ATTACK, THREAT, WITHHELD, events, layout, per_case,
                                     tdid_event_verdicts)

OUT = Path(__file__).resolve().parents[2] / "results"
ROLES = ("issuer", "wallet", "verifier", "resolver", "status_service", "relying_party")
JUDGES = ("pltl", "fo", "ltl3", "tdid")
GROUPS = {"THR-015": ("waltid", "credo"), "THR-019": ("credo-vp",)}
MON_TO = {"attack": ATTACK, "no_attack": NO_ATTACK, "undetermined": WITHHELD}


def _judge(product: str, evs: list[dict[str, Any]], cases: list[str]) -> dict[str, dict[str, str]]:
    from experiments.eval.monitors import judge
    ids = {ev["event_id"]: i for i, ev in enumerate(evs)}
    out = {"tdid": per_case(cases, tdid_event_verdicts(evs, THREAT[product]))}
    for name in ("pltl", "fo", "ltl3"):
        by: dict[int, list[str]] = {}
        for row in judge(name, evs, THREAT[product]):
            by.setdefault(ids[row["event_id"]], []).append(MON_TO[row["verdict"]])
        out[name] = per_case(cases, by)
    return out


def run() -> dict[str, Any]:
    data: dict[str, Any] = {}
    for group, products in GROUPS.items():
        rows: dict[str, Any] = {}
        for role in (None, *ROLES):
            cell = {j: {"wrong": 0, "withheld": 0, "silent": 0, "changed": 0, "runs": 0} for j in JUDGES}
            present = False
            for product in products:
                lay = layout(product)
                base = events(product, "added")
                idx = lay.index_case["added"]
                base_v = _judge(product, base, idx)
                keep = [i for i, ev in enumerate(base) if ev["producer"]["role"] != role]
                present |= len(keep) != len(base)
                evs = [base[i] for i in keep]
                v = _judge(product, evs, [idx[i] for i in keep])
                for c in lay.cases:
                    if c.truth == "unknown":
                        continue
                    for j in JUDGES:
                        got = v[j].get(c.case_id)
                        x = cell[j]
                        x["runs"] += 1
                        if got is None:
                            x["silent"] += 1
                            got = NO_ATTACK          # no output = no alarm, for every judge
                        if got == WITHHELD:
                            x["withheld"] += 1
                        elif got != c.truth:
                            x["wrong"] += 1
                        if got != base_v[j].get(c.case_id, NO_ATTACK):
                            x["changed"] += 1
            rows[role or "none (base)"] = {"records_present": present or role is None, "judges": cell}
        data[group] = rows
    return data


def latex(data: dict[str, Any]) -> str:
    names = {"pltl": "Two-valued", "fo": "First-order", "ltl3": "Three-valued", "tdid": "T-DID"}
    role_name = {"none (base)": "none (complete)", "issuer": "Issuer", "wallet": "Wallet", "verifier": "Verifier",
                 "resolver": "DID resolver", "status_service": "Status service", "relying_party": "Relying party"}
    lines = [r"\begin{table}[t]", r"\centering\footnotesize",
             r"\caption{Component-level evidence loss: all records of one producer are removed. Cells: wrong / "
             r"withheld runs (THR-015: 27 runs, THR-019: 12 runs); a run without any remaining decision gets "
             r"no output and counts as no alarm for every judge, marked $^\dagger$. --: the dataset has no "
             r"record of that producer.}",
             r"\label{tab:component-loss}", r"\setlength{\tabcolsep}{3pt}",
             r"\begin{tabular}{@{}ll" + "c" * len(JUDGES) + r"@{}}\toprule",
             "Threat & Removed & " + " & ".join(names[j] for j in JUDGES) + r" \\ \midrule"]
    for group, rows in data.items():
        first = True
        for role, r in rows.items():
            if not r["records_present"]:
                cells = ["--"] * len(JUDGES)
            else:
                cells = []
                for j in JUDGES:
                    x = r["judges"][j]
                    mark = r"$^\dagger$" if x["silent"] else ""
                    cells.append(f"{x['wrong']} / {x['withheld']}{mark}")
            lines.append(f"{group if first else ''} & {role_name[role]} & " + " & ".join(cells) + r" \\")
            first = False
        lines.append(r"\midrule" if group != list(data)[-1] else r"\bottomrule")
    lines += [r"\end{tabular}", r"\end{table}", ""]
    return "\n".join(lines)


def main() -> None:
    data = run()
    (OUT / "data").mkdir(parents=True, exist_ok=True)
    (OUT / "data" / "table_component.json").write_text(json.dumps(data, indent=2) + "\n")
    (OUT / "table_component.tex").write_text(latex(data))
    for group, rows in data.items():
        for role, r in rows.items():
            print(group, f"{role:16s}", "present" if r["records_present"] else "absent ",
                  {j: (x["wrong"], x["withheld"], x["silent"]) for j, x in r["judges"].items()})


if __name__ == "__main__":
    main()
