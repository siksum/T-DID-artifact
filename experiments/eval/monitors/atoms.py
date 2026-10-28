"""Grounded propositions for the propositional monitors (PLTL and LTL3).

PLTL (PHOENIX) and LTL3 (Bauer et al.) are propositional: an atom is true or false at each event and
cannot compare data values across events. The success conditions of TDID-THR-015 and TDID-THR-019 compare
values (the same proof, the same output, the same request and session). The standard way to monitor such
properties with a propositional monitor is grounding: one monitor instance per relevant data valuation.
Here the instance is one decision event k, and every atom of event e is computed relative to k's values
(proof p_k, output o_k; request r_k, session s_k). This grounding is the preprocessing these monitors
need; it is done here, outside the monitor, and is reported as such.

Semantics of missing data (the monitors' own, two-valued): an atom about a field that is absent is false.
Equality with an absent value is false (absent equals nothing). There is no third value.

Atom definitions mirror the T-DID rules (src/tdid/rules/thr015.py, thr019.py) condition by condition.
"""

from __future__ import annotations

from itertools import product
from typing import Any

THR015 = "TDID-THR-015"
THR019 = "TDID-THR-019"
DECISION = {THR015: "ISSUANCE_DECISION", THR019: "RELYING_AUTHENTICATION_DECISION"}
DIRECT_POST = frozenset({"direct_post", "direct_post.jwt"})
CODE_CHECK = "vp_response_code_validation"
KEY_PROOF_CHECK = "credential_key_proof_validation"

# Atom order per threat (also the letter encoding order for LTL3).
ATOMS = {
    # d: this event is decision instance k
    # u: another issuance decision with proof p_k, key proof validated, issued (a counted earlier use)
    # r: like u and its output is o_k (o_k already issued for p_k: a re-delivery, not a new credential)
    # v, i: this event's key-proof validation passed / outcome issue
    # x: this event carries the deployment limit allowed_proof_uses (encodings fixed for a limit <= 1)
    THR015: ("d", "u", "r", "v", "i", "x"),
    # d: this event is decision instance k
    # q: presentation request with request_ref r_k in response mode direct_post / direct_post.jwt
    # w: Wallet response sent (outcome none) for request_ref r_k
    # n: presentation request with request_ref r_k created in frontend session s_k (initiating session)
    # b: Response Code check fail or not_performed (binding ineffective); c: check fail (context differs)
    # h: initiator is not the Wallet user (no field records it, so never true)
    # a: relying decision accepted
    THR019: ("d", "q", "w", "n", "b", "c", "h", "a"),
}


def _ref(ev: dict[str, Any], name: str) -> Any:
    refs = ev.get("refs")
    return refs.get(name) if isinstance(refs, dict) else None


def _eq(a: Any, b: Any) -> bool:
    return a is not None and b is not None and a == b


def _outcome(ev: dict[str, Any]) -> Any:
    return (ev.get("decision") or {}).get("outcome")


def _check(ev: dict[str, Any], name: str) -> Any:
    return ((ev.get("checks") or {}).get("results") or {}).get(name)


def allowed(ev: dict[str, Any]) -> Any:
    return ((ev.get("policy") or {}).get("params") or {}).get("allowed_proof_uses")


def decision_positions(events: list[dict[str, Any]], threat: str) -> list[int]:
    kind = DECISION[threat]
    return [i for i, ev in enumerate(events) if ev.get("event_type") == kind]


def instance_of(ev: dict[str, Any], threat: str) -> dict[str, Any]:
    """The data values of decision event `ev` that its grounded instance is relative to."""
    if threat == THR015:
        limit = allowed(ev)
        if limit is not None and not isinstance(limit, bool) and isinstance(limit, (int, float)) and limit > 1:
            raise NotImplementedError(
                "propositional THR-015 encoding is fixed for allowed_proof_uses <= 1 "
                "(counting distinct outputs needs grounding over outputs); use the FO monitor")
        return {"event_id": ev.get("event_id"), "proof": _ref(ev, "proof_ref"), "output": _ref(ev, "output_ref")}
    return {"event_id": ev.get("event_id"), "request": _ref(ev, "request_ref"),
            "session": _ref(ev, "frontend_session_ref")}


def valuation(ev: dict[str, Any], threat: str, inst: dict[str, Any]) -> dict[str, bool]:
    """Truth values of the atoms at event `ev`, relative to instance `inst`."""
    kind = ev.get("event_type")
    d = kind == DECISION[threat] and _eq(ev.get("event_id"), inst["event_id"])
    if threat == THR015:
        is_dec = kind == "ISSUANCE_DECISION"
        v = is_dec and _check(ev, KEY_PROOF_CHECK) == "pass"
        i = is_dec and _outcome(ev) == "issue"
        u = is_dec and not d and _eq(_ref(ev, "proof_ref"), inst["proof"]) and v and i
        r = u and _eq(_ref(ev, "output_ref"), inst["output"])
        limit = allowed(ev) if is_dec else None
        x = limit is not None and not isinstance(limit, bool) and isinstance(limit, (int, float))
        return {"d": d, "u": u, "r": r, "v": v, "i": i, "x": x}
    req = kind == "PRESENTATION_REQUESTED" and _eq(_ref(ev, "request_ref"), inst["request"])
    facts = ev.get("facts") if isinstance(ev.get("facts"), dict) else {}
    q = req and facts.get("vp_response_mode") in DIRECT_POST
    n = req and _eq(_ref(ev, "frontend_session_ref"), inst["session"])
    w = (kind == "WALLET_RESPONSE_SENT" and _eq(_ref(ev, "request_ref"), inst["request"])
         and _outcome(ev) == "none")
    is_dec = kind == "RELYING_AUTHENTICATION_DECISION"
    code = _check(ev, CODE_CHECK) if is_dec else None
    return {"d": d, "q": q, "w": w, "n": n,
            "b": code in ("fail", "not_performed"), "c": code == "fail",
            "h": False,  # InitiatorIsNotWalletUser: no field exists; the atom has no data, so it is false
            "a": is_dec and _outcome(ev) == "accept"}


def feasible(threat: str) -> list[tuple[bool, ...]]:
    """Valuations `valuation` can produce: the LTL3 alphabet (one letter per valuation)."""
    names = ATOMS[threat]
    out = []
    for bits in product((False, True), repeat=len(names)):
        a = dict(zip(names, bits))
        if threat == THR015:
            ok = (not a["u"] or (not a["d"] and a["v"] and a["i"])) and (not a["r"] or a["u"])
        else:
            request = a["q"] or a["n"]
            decision = a["d"] or a["b"] or a["c"] or a["h"] or a["a"]
            ok = ((not a["c"] or a["b"])
                  and sum((request, a["w"], decision)) <= 1)
        if ok:
            out.append(bits)
    return out


def as_bits(val: dict[str, bool], threat: str) -> tuple[bool, ...]:
    return tuple(bool(val[n]) for n in ATOMS[threat])


# ---- parametric trace slicing (incremental monitoring) ----------------------------------------------------
# A grounded instance is parameterised by (group, member): THR-015 (proof p, output o), THR-019 (request r,
# frontend session s). An event touches the slices of its own group value only; for every other slice all
# data-matching atoms (THR-015 d, u, r; THR-019 d, q, w, n) are false at that event.
MATCH_ATOMS = {THR015: ("d", "u", "r"), THR019: ("d", "q", "w", "n")}
UNOBSERVED = frozenset({"pending", "error"})
_NOBODY = object()  # event id of a slice: matches no event, so d is false while a slice is updated


def slice_key(ev: dict[str, Any], threat: str) -> tuple[Any, Any]:
    """(group, member) data values the event carries; None where absent."""
    if threat == THR015:
        return _ref(ev, "proof_ref"), _ref(ev, "output_ref")
    return _ref(ev, "request_ref"), _ref(ev, "frontend_session_ref")


def slice_inst(threat: str, group: Any, member: Any) -> dict[str, Any]:
    """The instance of slice (group, member), used to update it with an event that is not its decision."""
    if threat == THR015:
        return {"event_id": _NOBODY, "proof": group, "output": member}
    return {"event_id": _NOBODY, "request": group, "session": member}


def outcome_observed(ev: dict[str, Any]) -> bool:
    return _outcome(ev) not in UNOBSERVED
