"""Shared evaluation plumbing: datasets, ground truth per workflow, and the one aggregation rule.

Unit of evaluation: the workflow run (THR-015: 30 issuance runs, 15 per issuer; THR-019: 12 presentation
runs). Every judge (T-DID and the comparators) emits verdicts per decision event; a workflow's verdict is
  attack       if any of its decisions is judged attack (T-DID: succeeded),
  withheld     else if any is undetermined (T-DID: incomplete),
  no_attack    otherwise.
Ground truth comes from the actual issuance / access result recorded apart from the detector
(``truth/``): THR-015 a credential that was newly delivered for a replayed proof (client-side signature
verification of the returned credential, ``oracle.jsonl``); THR-019 the relying party granted access to a
session whose controller is not the verified subject (``oracle.json``). Server errors whose effect is
unknown make the truth unknown; those runs are excluded from every condition and reported.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DATASETS = {"waltid": ROOT / "datasets/sept2026-thr015", "credo": ROOT / "datasets/sept2026-thr015",
            "credo-vp": ROOT / "datasets/sept2026-thr019"}
THREAT = {"waltid": "TDID-THR-015", "credo": "TDID-THR-015", "credo-vp": "TDID-THR-019"}
LABEL = {"waltid": "THR-015 walt.id", "credo": "THR-015 Credo TS", "credo-vp": "THR-019 Credo TS + RP"}
PRODUCTS = ("waltid", "credo", "credo-vp")
ATTACK, NO_ATTACK, WITHHELD = "attack", "no_attack", "withheld"
TDID_TO = {"succeeded": ATTACK, "not_succeeded": NO_ATTACK, "incomplete": WITHHELD}


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def events(product: str, level: str) -> list[dict[str, Any]]:
    return _jsonl(DATASETS[product] / "events" / f"{product}.{level}.jsonl")


@dataclass
class Case:
    case_id: str
    scenario: str            # display only; never used for truth or verdicts
    truth: str               # attack / no_attack / unknown
    requests: int = 0


@dataclass
class Layout:
    """Cases of one product and, per event index of a level's event list, the case it belongs to."""
    product: str
    cases: list[Case]
    index_case: dict[str, list[str]] = field(default_factory=dict)   # level -> case id per event index


def layout(product: str) -> Layout:
    ds = DATASETS[product]
    if THREAT[product] == "TDID-THR-015":
        oracle = _jsonl(ds / "truth" / product / "oracle.jsonl")
        design = _jsonl(ds / "truth" / product / "case-design.jsonl")
        per_request = [(r["request_id"].rsplit("-", 1)[0], r["outcome"]) for r in oracle]
        cases = []
        for row in design:
            outs = [o for c, o in per_request if c == row["case_id"]]
            truth = (ATTACK if "duplicate_delivery" in outs else
                     "unknown" if "unknown_server_outcome" in outs else NO_ATTACK)
            cases.append(Case(row["case_id"], row["scenario"], truth, len(outs)))
        lay = Layout(product, cases)
        for level in ("native", "added"):
            evs = events(product, level)
            if len(evs) != len(per_request):
                raise ValueError(f"{product}.{level}: {len(evs)} decisions vs {len(per_request)} requests")
            # one issuer decision per credential request, both in issuer order (verified in step 1)
            lay.index_case[level] = [c for c, _ in per_request]
        return lay
    plan = json.loads((ds / "meta" / "plan.json").read_text())
    cases = []
    for row in plan["schedule"]:
        o = json.loads((ds / "truth" / product / row["case_id"] / "oracle.json").read_text())
        if not all(o[k] for k in ("result_verified", "transaction_matches", "subject_matches_wallet")):
            truth = "unknown"
        elif o["consumer_controller"] != o["verified_subject"] and o["access_entry"] == "granted":
            truth = ATTACK
        else:
            truth = NO_ATTACK
        cases.append(Case(row["case_id"], row["action"], truth, 1))
    lay = Layout(product, cases)
    for level in ("native", "added"):
        lay.index_case[level] = [ev["event_id"].split("-verifier")[0].split("-wallet")[0].split("-rp")[0]
                                 for ev in events(product, level)]
    return lay


def aggregate(verdicts: list[str]) -> str:
    if ATTACK in verdicts:
        return ATTACK
    if WITHHELD in verdicts:
        return WITHHELD
    return NO_ATTACK


def tdid_event_verdicts(evs: list[dict[str, Any]], threat: str) -> dict[int, list[str]]:
    """Final T-DID findings of the threat, keyed by the index of their trigger event in ``evs``."""
    from tdid.dataset import run_result
    report = run_result(evs)
    index = {ev["event_id"]: i for i, ev in enumerate(evs)}
    out: dict[int, list[str]] = {}
    for f in report["findings"]:
        if f["threat_id"] == threat:
            out.setdefault(index[f["trigger_event_id"]], []).append(TDID_TO[f["verdict"]])
    return out


def per_case(index_case: list[str], event_verdicts: dict[int, list[str]]) -> dict[str, str]:
    """Workflow verdict per case; a case with no verdict at all is reported as 'none'."""
    grouped: dict[str, list[str]] = {}
    for i, vs in event_verdicts.items():
        grouped.setdefault(index_case[i], []).extend(vs)
    return {c: aggregate(vs) for c, vs in grouped.items()}


def tdid_cases(product: str, evs: list[dict[str, Any]], index_case: list[str]) -> dict[str, str]:
    return per_case(index_case, tdid_event_verdicts(evs, THREAT[product]))


def count(cases: list[Case], verdicts: dict[str, str]) -> dict[str, int]:
    """Verdict counts over the cases with known truth (unknown-truth runs excluded)."""
    out = {ATTACK: 0, NO_ATTACK: 0, WITHHELD: 0, "none": 0}
    for c in cases:
        if c.truth != "unknown":
            out[verdicts.get(c.case_id, "none")] += 1
    return out
