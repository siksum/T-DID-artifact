"""PHOENIX-style two-valued past-time LTL monitor.

Echeverria et al., "PHOENIX: Device-Centric Cellular Network Protocol Monitoring using Runtime
Verification", NDSS 2021, Sec. VI.A/B: properties are PLTL formulas monitored with the dynamic-programming
algorithm of Havelund and Rosu ("Synthesizing monitors for safety properties", TACAS 2002); the verdict at
each event is a boolean.

Havelund-Rosu: keep two arrays over the subformulas in post order, `pre` (values at the previous event) and
`now` (values at the current one). At each event `now` is filled bottom-up in O(|phi|):
    atom p      now = p holds at this event
    not / and / or  as usual over `now`
    Y f         now = pre[f]                  (false at the first event)
    O f         now = now[f] or pre[O f]      (= now[f] at the first event)
    H f         now = now[f] and pre[H f]     (= now[f] at the first event)
    f S g       now = now[g] or (now[f] and pre[f S g])   (= now[g] at the first event)

Data: PLTL is propositional, so the THR-015/019 conditions over proof/output/request/session values are
grounded per decision instance (see atoms.py): the verdict at decision k is the formula's value at k with
atoms computed relative to k's values.

Incremental evaluation (parametric trace slicing): every temporal subformula of FORMULAS is `Y O a` for a
data-matching atom a. The Havelund-Rosu state of `O a` is kept per data slice (THR-015: u per proof p, r per
(p, o); THR-019: q and w per request r, n per (r, s)) and updated only by events that carry that slice's
data, in O(|O a|). An event that does not carry the slice's data has a false, and O is unchanged by a false
step, so skipping it is exact. At a decision, `Y O a` is the slice's value before the decision, and the
top formula is evaluated over it and the decision's own atoms in O(|phi|). `verdict_at` re-reads the
prefix (reference implementation, used in tests).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from experiments.eval.monitors import atoms as A


@dataclass(frozen=True)
class F:
    op: str                      # atom, not, and, or, Y, O, H, S
    args: tuple[F, ...] = ()
    name: str = ""

    def __str__(self) -> str:
        if self.op == "atom":
            return self.name
        if self.op == "not":
            return f"!{self.args[0]}"
        if self.op in ("and", "or"):
            return "(" + (" & " if self.op == "and" else " | ").join(map(str, self.args)) + ")"
        if self.op == "S":
            return f"({self.args[0]} S {self.args[1]})"
        return f"{self.op}({self.args[0]})"


def Atom(name: str) -> F: return F("atom", (), name)
def Not(f: F) -> F: return F("not", (f,))
def And(*fs: F) -> F: return F("and", tuple(fs))
def Or(*fs: F) -> F: return F("or", tuple(fs))
def Y(f: F) -> F: return F("Y", (f,))
def O(f: F) -> F: return F("O", (f,))
def H(f: F) -> F: return F("H", (f,))
def S(f: F, g: F) -> F: return F("S", (f, g))


def subformulas(phi: F) -> list[F]:
    """Post order, each distinct subformula once; phi last."""
    out: list[F] = []
    seen: set[F] = set()

    def walk(f: F) -> None:
        if f in seen:
            return
        for a in f.args:
            walk(a)
        seen.add(f)
        out.append(f)

    walk(phi)
    return out


class Monitor:
    """Havelund-Rosu dynamic-programming monitor for one PLTL formula."""

    def __init__(self, phi: F) -> None:
        self.phi = phi
        self.subs = subformulas(phi)
        self.idx = {f: j for j, f in enumerate(self.subs)}
        self.pre: list[bool] | None = None

    def step(self, val: dict[str, bool]) -> bool:
        pre, now, ix = self.pre, [False] * len(self.subs), self.idx
        for j, f in enumerate(self.subs):
            op = f.op
            if op == "atom":
                now[j] = bool(val.get(f.name, False))
            elif op == "not":
                now[j] = not now[ix[f.args[0]]]
            elif op == "and":
                now[j] = all(now[ix[a]] for a in f.args)
            elif op == "or":
                now[j] = any(now[ix[a]] for a in f.args)
            elif op == "Y":
                now[j] = pre[ix[f.args[0]]] if pre is not None else False
            elif op == "O":
                now[j] = now[ix[f.args[0]]] or (pre[j] if pre is not None else False)
            elif op == "H":
                now[j] = now[ix[f.args[0]]] and (pre[j] if pre is not None else True)
            elif op == "S":
                g, h = now[ix[f.args[0]]], now[ix[f.args[1]]]
                now[j] = h or (g and pre[j]) if pre is not None else h
            else:  # pragma: no cover
                raise ValueError(op)
        self.pre = now
        return now[-1]

    @property
    def value(self) -> bool:
        """Value of the formula at the last event read (False before any event)."""
        return self.pre[-1] if self.pre is not None else False


def evaluate(phi: F, val: dict[str, bool], given: dict[F, bool]) -> bool:
    """Value of phi at one event from its atoms `val` and the values `given` of its temporal subformulas."""
    if phi in given:
        return given[phi]
    op = phi.op
    if op == "atom":
        return bool(val.get(phi.name, False))
    if op == "not":
        return not evaluate(phi.args[0], val, given)
    if op == "and":
        return all(evaluate(a, val, given) for a in phi.args)
    if op == "or":
        return any(evaluate(a, val, given) for a in phi.args)
    raise ValueError(f"temporal subformula {phi} has no slice value")


_a = {n: Atom(n) for n in set(A.ATOMS[A.THR015]) | set(A.ATOMS[A.THR019])}

# Attack at the decision instance (evaluated at that event).
# THR-015 (allowed_proof_uses <= 1, so ExceedsAllowedUses == SameProofAcceptedBefore when the limit is set):
#   d & v & i & x & Y O u & !Y O r
FORMULAS = {
    A.THR015: And(_a["d"], _a["v"], _a["i"], _a["x"], Y(O(_a["u"])), Not(Y(O(_a["r"])))),
    # THR-019: d & Y O q & Y O w & Y O n & b & c & h & a
    A.THR019: And(_a["d"], Y(O(_a["q"])), Y(O(_a["w"])), Y(O(_a["n"])),
                  _a["b"], _a["c"], _a["h"], _a["a"]),
}


def verdict_at(events: list[dict[str, Any]], k: int, threat: str) -> bool:
    """Formula value at event k for the instance grounded on decision k (True = attack)."""
    inst = A.instance_of(events[k], threat)
    mon = Monitor(FORMULAS[threat])
    out = False
    for ev in events[: k + 1]:
        out = mon.step(A.valuation(ev, threat, inst))
    return out


# Data-matching atoms under `Y O`: kept per group value (proof / request) or per (group, member).
GROUP_ATOMS = {A.THR015: ("u",), A.THR019: ("q", "w")}
MEMBER_ATOMS = {A.THR015: ("r",), A.THR019: ("n",)}


class Online:
    """Incremental PLTL monitor over parametric slices; feed() is O(|phi|) per event."""

    def __init__(self, threat: str) -> None:
        self.threat = threat
        self.phi = FORMULAS[threat]
        self.group: dict[tuple[str, Any], Monitor] = {}    # (atom, group value) -> monitor of O atom
        self.member: dict[tuple[str, Any, Any], Monitor] = {}

    def _value(self, key: tuple, table: dict) -> bool:
        mon = table.get(key)
        return mon.value if mon is not None else False

    def feed(self, ev: dict[str, Any]) -> bool | None:
        """Read one event; for a decision of the threat return True (attack) / False, else None."""
        threat = self.threat
        verdict = None
        g, m = A.slice_key(ev, threat)
        if ev.get("event_type") == A.DECISION[threat]:
            val = A.valuation(ev, threat, A.instance_of(ev, threat))
            given = {Y(O(_a[a])): (g is not None and self._value((a, g), self.group))
                     for a in GROUP_ATOMS[threat]}
            given.update({Y(O(_a[a])): (g is not None and m is not None
                                        and self._value((a, g, m), self.member))
                          for a in MEMBER_ATOMS[threat]})
            verdict = evaluate(self.phi, val, given)
        if g is not None:  # update the slices this event touches, as an event other than their decision
            val = A.valuation(ev, threat, A.slice_inst(threat, g, m))
            for a in GROUP_ATOMS[threat]:
                self.group.setdefault((a, g), Monitor(O(_a[a]))).step(val)
            if m is not None:
                for a in MEMBER_ATOMS[threat]:
                    self.member.setdefault((a, g, m), Monitor(O(_a[a]))).step(val)
        return verdict


def judge(events: list[dict[str, Any]], threat: str) -> list[dict[str, Any]]:
    mon, rows = Online(threat), []
    for ev in events:
        verdict = mon.feed(ev)
        if verdict is not None:
            rows.append({"event_id": ev.get("event_id"), "workflow_ref": ev.get("workflow_ref"),
                         "verdict": "attack" if verdict else "no_attack"})
    return rows


def reference_judge(events: list[dict[str, Any]], threat: str) -> list[dict[str, Any]]:
    """Non-incremental: one fresh monitor per decision re-reads the prefix (for equivalence tests)."""
    return [{"event_id": events[k].get("event_id"), "workflow_ref": events[k].get("workflow_ref"),
             "verdict": "attack" if verdict_at(events, k, threat) else "no_attack"}
            for k in A.decision_positions(events, threat)]
