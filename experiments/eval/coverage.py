"""Supplementary: share of the threat's success conditions that the records settle
(true or false) under each input condition, same T-DID engine (no new runs; computed from the predicates
T-DID reports with every finding). Per workflow: mean over its final findings; then the mean over workflows
with known ground truth. Middle conditions: the standard with the highest share (all four in data JSON).
Reported with the workflows decided / workflows of Fig. 1. Explains why the middle conditions of Fig. 1 withhold.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from experiments.eval.common import ATTACK, NO_ATTACK, THREAT, events, layout

OUT = Path(__file__).resolve().parents[2] / "results"
CONDS = [("native", "Product log"), ("core", "Standard-field\nmapping"),
         ("ext", "Standard +\nextension fields"), ("added", "T-DID\nevidence")]
PANELS = {"THR-015": ("waltid", "credo"), "THR-019": ("credo-vp",)}
NAMES = {"ocsf": "OCSF", "ecs": "ECS", "otel": "OTel", "cloudevents": "CE"}
# conditions no honest component can observe (THR-019, OpenID4VP 1.0 section 14.2)
BLIND = {"TDID-THR-019": {"InitiatorIsNotWalletUser"}}


def _shares(product: str, evs: list[dict], index_case: list[str]) -> dict[str, list[float]]:
    from tdid.dataset import run_result
    report = run_result(evs)
    ids = {e["event_id"]: i for i, e in enumerate(evs)}
    out: dict[str, list[float]] = {}
    for f in report["findings"]:
        if f["threat_id"] == THREAT[product]:
            p = f["predicates"]
            out.setdefault(index_case[ids[f["trigger_event_id"]]], []).append(
                sum(v is not None for v in p.values()) / len(p))
    return out


def run() -> dict:
    from experiments.eval import mappers
    from experiments.eval.fig1 import deployment_config
    fig1 = json.loads((OUT / "data" / "fig1.json").read_text())
    data: dict = {}
    for panel, products in PANELS.items():
        row: dict = {}
        for cond, _ in CONDS:
            options = [None] if cond in ("native", "added") else list(mappers.STANDARDS)
            per_std = {}
            for std in options:
                values = []
                for product in products:
                    lay = layout(product)
                    if std is None:
                        evs, idx = events(product, cond), lay.index_case[cond]
                    else:
                        added = events(product, "added")
                        evs = mappers.roundtrip(added, std, cond, deployment_config(product, added))
                        idx = lay.index_case["added"]
                    shares = _shares(product, evs, idx)
                    values += [float(np.mean(shares.get(c.case_id, [0.0])))
                               for c in lay.cases if c.truth != "unknown"]
                per_std[std or cond] = 100 * float(np.mean(values))
            best = max(per_std, key=per_std.get)
            key = {"native": "product_log", "core": "std_core", "ext": "std_ext", "added": "tdid"}[cond]
            counts = fig1["panels"][panel]["counts"][key]
            row[cond] = {"share": per_std[best], "by_standard": per_std,
                         "best": [s for s, v in per_std.items() if abs(v - per_std[best]) < 1e-9],
                         "decided": counts[ATTACK] + counts[NO_ATTACK], "n": fig1["panels"][panel]["n"],
                         "wrong": counts["wrong"]}
        data[panel] = row
    data["observable_max"] = {"THR-019": 100 * 5 / 7}
    return data


def main() -> None:
    data = run()
    (OUT / "data" / "coverage.json").write_text(json.dumps(data, indent=2) + "\n")
    for panel in PANELS:
        print(panel, {c: (round(r["share"], 1), r["best"], f"{r['decided']}/{r['n']}")
                      for c, r in data[panel].items()})


if __name__ == "__main__":
    main()
