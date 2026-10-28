"""Table II: what each kind of information contributes to T-DID's verdicts.

Base: the T-DID evidence condition (added records) of each product. One kind of information is removed from
every event, the same engine judges again, and each workflow's verdict is compared with the base verdict.
Columns: THR-015 walt.id, THR-015 Credo TS, THR-019; each split by ground truth (benign / attack).
Cell symbol (one per cell, legend in the caption):
  X  some workflow now gets no_witness / no_attack without the evidence to support it (silent assurance)
  V  some workflow's decided verdict becomes incomplete_evidence (withheld), none silently cleared
  -  no workflow's verdict changes
Unknown-truth runs (Credo HTTP 500) are excluded as everywhere else.
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from pathlib import Path
from typing import Any

from experiments.eval.common import (
    ATTACK,
    NO_ATTACK,
    PRODUCTS,
    TDID_TO,
    THREAT,
    WITHHELD,
    events,
    layout,
    per_case,
)

OUT = Path(__file__).resolve().parents[2] / "results"

DECISIONS = {"ISSUANCE_DECISION", "RELYING_AUTHENTICATION_DECISION"}


def _unavailable(ev: dict[str, Any], dotted: str, value_kept: bool = False) -> None:
    """Declare the field missing. A placeholder value (pending, unavailable) is not marked Unavailable in
    provenance, since the Gate refuses an Unavailable field that carries a value."""
    if not value_kept:
        ev.setdefault("provenance", {})[dotted] = "Unavailable"
    elif dotted in (ev.get("provenance") or {}):
        del ev["provenance"][dotted]
    ev.setdefault("missing", []).append({"field": dotted, "owner": ev["producer"]["role"]})


def _drop_ref(ev: dict[str, Any], name: str) -> None:
    if name in (ev.get("refs") or {}):
        del ev["refs"][name]
        if not ev["refs"]:
            del ev["refs"]
        _unavailable(ev, f"refs.{name}")


def _drop_check(ev: dict[str, Any], name: str) -> None:
    results = ev["checks"]["results"]
    if name in results:
        results[name] = "unavailable"
        ev["checks"]["performed"] = [c for c in ev["checks"]["performed"] if c != name]
        _unavailable(ev, f"checks.{name}", value_kept=True)


def _drop_decision(ev: dict[str, Any]) -> None:
    if ev["event_type"] in DECISIONS:
        ev["decision"] = {"outcome": "pending"}
        _unavailable(ev, "decision.outcome", value_kept=True)


# Row -> transformation of the whole event list (each returns new events)
def history(evs):
    """Earlier records unavailable: each decision is judged with only its own record, and nothing tells
    T-DID that the component's history starts there."""
    out = []
    for ev in evs:
        if ev["event_type"] in DECISIONS:
            e = copy.deepcopy(ev)
            e["producer"]["instance"] = f"{e['producer']['instance']} #{e['event_id']}"
            e["producer"]["seq"] = 0
            e["producer"].pop("stream_start", None)
            out.append(e)
    return out


def final_result(evs):
    out = copy.deepcopy(evs)
    for ev in out:
        _drop_decision(ev)
        _drop_ref(ev, "output_ref")
    return out


def flow_link(evs):
    out = copy.deepcopy(evs)
    for ev in out:
        for name in ("proof_ref", "request_ref", "frontend_session_ref"):
            _drop_ref(ev, name)
    return out


def security_check(evs):
    out = copy.deepcopy(evs)
    for ev in out:
        _drop_check(ev, "credential_key_proof_validation")
        _drop_check(ev, "vp_response_code_validation")
    return out


def provenance(evs):
    out = copy.deepcopy(evs)
    for ev in out:
        ev.pop("provenance", None)
        ev.pop("missing", None)
        ev["integrity"] = {"result": "not_checked"}
    return out


ROWS = [
    ("Earlier records (history)", history, False),
    ("Missing-evidence verdict", None, True),
    ("Final result", final_result, False),
    ("Flow link (proof / request / session refs)", flow_link, False),
    ("Security-check result", security_check, False),
    ("Provenance, integrity", provenance, False),
]


def _verdicts(product: str, evs: list[dict[str, Any]], index_case: list[str], two_valued: bool,
              ids: dict[str, int]) -> dict[str, str]:
    """T-DID workflow verdicts. ``two_valued`` removes the incomplete value: an unknown condition is read
    as false (the 'missing-evidence verdict' ablation)."""
    from tdid.dataset import run_result
    report = run_result(evs)
    if report["rejected_records"]:
        raise RuntimeError(f"{product}: records rejected: {report['rejected_records'][:3]}")
    by_index: dict[int, list[str]] = {}
    for f in report["findings"]:
        if f["threat_id"] != THREAT[product]:
            continue
        verdict = TDID_TO[f["verdict"]]
        if two_valued and verdict == WITHHELD:
            verdict = NO_ATTACK
        by_index.setdefault(ids[f["trigger_event_id"]], []).append(verdict)
    return per_case(index_case, by_index)


def run() -> dict[str, Any]:
    table: dict[str, Any] = {"rows": [], "columns": []}
    for product in PRODUCTS:
        for truth in (NO_ATTACK, ATTACK):
            table["columns"].append({"product": product, "truth": truth})
    for name, transform, two_valued in ROWS:
        row = {"row": name, "cells": [], "counts": []}
        for product in PRODUCTS:
            lay = layout(product)
            base_events = events(product, "added")
            index_case = lay.index_case["added"]
            ids = {ev["event_id"]: i for i, ev in enumerate(base_events)}
            base = _verdicts(product, base_events, index_case, False, ids)
            if transform is None:
                after = _verdicts(product, base_events, index_case, two_valued, ids)
            else:
                changed = transform(base_events)
                # the case of each surviving event, by its original event id
                cids = [index_case[ids[ev["event_id"]]] for ev in changed]
                new_ids = {ev["event_id"]: i for i, ev in enumerate(changed)}
                after = _verdicts(product, changed, cids, False, new_ids)
            for truth in (NO_ATTACK, ATTACK):
                trans: Counter = Counter()
                for c in lay.cases:
                    if c.truth != truth:
                        continue
                    trans[(base.get(c.case_id, "none"), after.get(c.case_id, "none"))] += 1
                silent = sum(n for (b, a), n in trans.items() if b != a and a == NO_ATTACK)
                held = sum(n for (b, a), n in trans.items() if b != a and a == WITHHELD)
                symbol = "X" if silent else ("V" if held else "-")
                row["cells"].append(symbol)
                row["counts"].append({f"{b}->{a}": n for (b, a), n in sorted(trans.items())})
        table["rows"].append(row)
    return table


SYMBOL = {"X": r"\X", "V": r"\Y", "-": "--"}


def latex(table: dict[str, Any]) -> str:
    head = (r"\begin{table}[t]" "\n" r"\centering\footnotesize" "\n"
            r"\caption{Verdict change when one kind of information is removed from the T-DID evidence "
            r"condition. Columns: THR-015 issuer runs (walt.id, Credo TS) and THR-019 presentation runs, "
            r"split into benign (B) and attack (A) runs by ground truth. \Y: some verdict becomes "
            r"incomplete\_evidence; \X: some run receives no\_witness without supporting evidence "
            r"(silent assurance); --: unchanged. Missing-evidence verdict: incomplete\_evidence replaced by "
            r"no\_witness. Per-run transitions are in Supplementary Table S-T2.}" "\n"
            r"\label{tab:ablation}" "\n"
            r"\begin{tabular}{@{}lcccccc@{}}\toprule" "\n"
            r" & \multicolumn{2}{c}{015 walt.id} & \multicolumn{2}{c}{015 Credo} & "
            r"\multicolumn{2}{c}{019} \\" "\n"
            r"\cmidrule(lr){2-3}\cmidrule(lr){4-5}\cmidrule(lr){6-7}" "\n"
            r"Removed & B & A & B & A & B & A \\ \midrule" "\n")
    body = "".join(f"{r['row']} & " + " & ".join(SYMBOL[s] for s in r["cells"]) + r" \\" + "\n"
                   for r in table["rows"])
    return head + body + r"\bottomrule\end{tabular}" + "\n" + r"\end{table}" + "\n"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    table = run()
    (OUT / "data").mkdir(exist_ok=True)
    (OUT / "data" / "table2.json").write_text(json.dumps(table, indent=2) + "\n")
    from experiments.eval.table1 import PREAMBLE
    (OUT / "table2.tex").write_text(PREAMBLE + latex(table))
    for r in table["rows"]:
        print(f"{r['row']:<45}", " ".join(r["cells"]), r["counts"])


if __name__ == "__main__":
    main()
