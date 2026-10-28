"""Evidence-loss generator: remove the evidence items THR-015 / THR-019 success conditions read.

Each (event, item) pair gets one uniform draw from ``random.Random(seed)``, made in a fixed order (events in
input order, items in ``ITEMS`` order) whether or not the item is present or removed. An item is removed when
its draw is below p. The draw stream therefore does not depend on p, so with one seed the removals at a
smaller p are a subset of those at a larger p (curves are monotone per seed).

How a removal is written, so the event stays valid for ``tdid.ingest.Gate().admit``:
- ref / fact: deleted from ``refs`` / ``facts``; provenance ``refs.<name>`` / ``facts.<name>`` set to
  "Unavailable"; ``{"field": "refs.<name>", "owner": producer.role}`` appended to ``missing``.
- check: result set to "unavailable" and dropped from ``performed``; provenance ``checks.<name>`` (the
  collectors' key form) set to "Unavailable"; ``missing`` gets ``checks.<name>``.
- decision: outcome set to "pending"; ``missing`` gets ``decision.outcome``. No Unavailable provenance is
  written for it, because the Gate rejects an Unavailable path that still carries a value ("pending").
  ``checks.required`` is left as is (the Gate accepts a pending decision with required checks).
- record: the whole event is dropped. The producer's remaining events keep their original ``producer.seq``,
  so the loss shows up as a sequence gap (or a stream that does not start at seq 0), which is what a lost
  record looks like to T-DID.

An item already absent (e.g. a ref the product never recorded, a check already "unavailable", a decision
already pending) is not removable and is not listed in ``removed``. When the record item is drawn, only
``(event_id, "record")`` is listed for that event.
"""

from __future__ import annotations

import copy
import random
from collections.abc import Iterable
from typing import Any

# item kind -> (section, name). "record" is the whole event.
_KIND: dict[str, tuple[str, str]] = {
    "proof_ref": ("refs", "proof_ref"),
    "output_ref": ("refs", "output_ref"),
    "request_ref": ("refs", "request_ref"),
    "frontend_session_ref": ("refs", "frontend_session_ref"),
    "vp_response_mode": ("facts", "vp_response_mode"),
    "key_proof_check": ("checks", "credential_key_proof_validation"),
    "response_code_check": ("checks", "vp_response_code_validation"),
    "decision": ("decision", "outcome"),
    "record": ("record", ""),
}

ITEMS: dict[str, tuple[str, ...]] = {
    "ISSUANCE_DECISION": ("proof_ref", "key_proof_check", "output_ref", "decision", "record"),
    "PRESENTATION_REQUESTED": ("request_ref", "frontend_session_ref", "vp_response_mode", "record"),
    "WALLET_RESPONSE_SENT": ("request_ref", "record"),
    "RELYING_AUTHENTICATION_DECISION": ("request_ref", "frontend_session_ref", "response_code_check",
                                        "decision", "record"),
}


def removable(ev: dict[str, Any], kind: str) -> bool:
    section, name = _KIND[kind]
    if section == "record":
        return True
    if section in ("refs", "facts"):
        return name in (ev.get(section) or {})
    if section == "checks":
        return ev["checks"]["results"].get(name, "unavailable") != "unavailable"
    return ev["decision"]["outcome"] != "pending"


def _remove(ev: dict[str, Any], kind: str) -> None:
    """Remove one non-record item from ev in place."""
    section, name = _KIND[kind]
    prov = ev.setdefault("provenance", {})
    if section in ("refs", "facts"):
        ev[section].pop(name)
        if not ev[section]:
            del ev[section]
        path = f"{section}.{name}"
        prov[path] = "Unavailable"
    elif section == "checks":
        checks = ev["checks"]
        checks["results"][name] = "unavailable"
        checks["performed"] = [c for c in checks["performed"] if c != name]
        path = f"checks.{name}"
        prov[path] = "Unavailable"
    else:
        ev["decision"]["outcome"] = "pending"
        ev["decision"].pop("reason_class", None)
        path = "decision.outcome"
        prov.pop(path, None)
    if not prov:
        del ev["provenance"]
    entry = {"field": path, "owner": ev["producer"]["role"]}
    missing = ev.setdefault("missing", [])
    if entry not in missing:
        missing.append(entry)


def _apply(events: Iterable[dict[str, Any]], pick) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    out: list[dict[str, Any]] = []
    removed: list[tuple[str, str]] = []
    for ev in events:
        kinds = ITEMS.get(ev["event_type"], ())
        chosen = [k for k in kinds if pick(ev, k)]   # pick is called for every item, in fixed order
        if "record" in chosen:
            removed.append((ev["event_id"], "record"))
            continue
        new = copy.deepcopy(ev)
        for kind in chosen:
            if removable(new, kind):
                _remove(new, kind)
                removed.append((ev["event_id"], kind))
        out.append(new)
    return out, removed


def drop(events: list[dict[str, Any]], p: float, seed: int,
         items: dict[str, tuple[str, ...]] | None = None) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """Remove each evidence item independently with probability p. ``items`` restricts which kinds may be
    removed (same shape as ITEMS); draws are still made for every ITEMS kind so that restricting items does
    not shift the random stream."""
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"p must be in [0, 1]: {p}")
    rng = random.Random(seed)
    allowed = items if items is not None else ITEMS

    def pick(ev: dict[str, Any], kind: str) -> bool:
        u = rng.random()
        return u < p and kind in allowed.get(ev["event_type"], ())

    return _apply(events, pick)


def drop_kind(events: list[dict[str, Any]], kinds: set[str]) -> list[dict[str, Any]]:
    """Remove the named item kinds from every event that has them (deterministic; for an ablation)."""
    unknown = set(kinds) - set(_KIND)
    if unknown:
        raise ValueError(f"unknown item kinds: {sorted(unknown)}")
    out, _ = _apply(events, lambda ev, kind: kind in kinds)
    return out
