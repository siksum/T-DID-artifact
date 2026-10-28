"""LTL3 three-valued monitor (Bauer, Leucker, Schallhart, "Runtime Verification for LTL and TLTL",
ACM TOSEM 20(4), 2011).

For an LTL formula phi and a finite prefix u, the LTL3 verdict is
    top    if every infinite continuation of u satisfies phi,
    bottom if no infinite continuation satisfies phi,
    ?      otherwise.
The monitor is the minimal Moore machine of that construction. It is generated with LamaConv
(vendor/rltlconv.jar, `--formula --moore --min`), parsed, and cached as JSON next to this module
(ltl3_<threat>.json). `regenerate()` rebuilds the cache with Java.

LamaConv reads one letter per step, so each step's valuation of the grounded atoms (atoms.py) is one
letter: the alphabet is the set of valuations atoms.valuation can produce (atoms.feasible), and an atom in
the formula stands for the disjunction of the letters in which it holds.

Encoding per decision instance k (atoms relative to k's values; future time from the trace start; k's
decision event d terminates the property):
    phi = F d & !A
    THR-015: A = (!d & !r) U (!d & !r & u & ((!d & !r) U (d & v & i & x)))
    THR-019: A = (!d U (!d & q)) & (!d U (!d & w)) & (!d U (!d & n)) & (!d U (d & b & c & h & a))
Verdict: top = no attack at k, bottom = attack at k, ? = k's decision not (yet) seen.

The decision letter d means "k's decision with an observed outcome". A decision record whose outcome is not
observed (decision.outcome pending or error, which is how a lost decision is written) is not the settling
event: d is false there, the instance never reads its terminator, and the verdict stays ? (undetermined).
The other atoms keep missing-as-false.

Incremental evaluation (parametric trace slicing): the Moore state is kept per slice (THR-015: (p, o), plus
one per proof for outputs not seen yet; THR-019: (r, s), plus one per request for sessions not seen yet) and
stepped only by events that carry the slice's group value. Every other event reads, for that slice, a letter
in which all data-matching atoms are false; `skip_is_exact` checks that every such letter is a self-loop in
every reachable state of the minimal machine (tested), otherwise every live slice is stepped. At a decision,
a copy of its slice state is stepped with the decision letter and the output read. `reference_judge`
re-reads the whole trace per decision (equivalence tests).
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from experiments.eval.monitors import atoms as A

HERE = Path(__file__).resolve().parent
JAR = HERE / "vendor" / "rltlconv.jar"

LTL = {
    A.THR015: "F(d) && !((!d && !r) U (!d && !r && u && ((!d && !r) U (d && v && i && x))))",
    A.THR019: ("F(d) && !((!d U (!d && q)) && (!d U (!d && w)) && (!d U (!d && n)) "
               "&& (!d U (d && b && c && h && a)))"),
}
CACHE = {A.THR015: HERE / "ltl3_thr015.json", A.THR019: HERE / "ltl3_thr019.json"}
VERDICT = {"true": "no_attack", "false": "attack", "?": "undetermined"}


def _letter(bits: tuple[bool, ...]) -> str:
    return "s" + "".join("1" if b else "0" for b in bits)


def lamaconv_input(threat: str) -> tuple[str, list[str]]:
    """The LamaConv formula over letters, and the alphabet."""
    names = A.ATOMS[threat]
    alphabet = A.feasible(threat)
    letters = [_letter(b) for b in alphabet]
    formula = LTL[threat]

    def expand(m: re.Match[str]) -> str:
        j = names.index(m.group(0))
        holds = [_letter(b) for b in alphabet if b[j]]
        if not holds:  # LamaConv has no constant false; an atom that holds in no letter is p & !p
            return f"({letters[0]} && !{letters[0]})"
        return "(" + " || ".join(holds) + ")"

    pattern = r"\b(" + "|".join(names) + r")\b"
    # F/U are operators, not atoms: atom names are lower case, operators upper case
    return re.sub(pattern, expand, formula), letters


def parse_moore(text: str) -> dict[str, Any]:
    states = dict(re.findall(r"(\w+):(true|false|\?)", re.search(r"STATES\s*=\s*\[(.*?)\]", text).group(1)))
    start = re.search(r"START\s*=\s*(\w+)", text).group(1)
    delta: dict[str, dict[str, str]] = {q: {} for q in states}
    for q, label, target in re.findall(r'DELTA\((\w+),\s*("[^"]*"|\?)\)\s*=\s*(\w+)', text):
        delta[q][label.strip('"') if label != "?" else "?"] = target
    return {"states": states, "start": start, "delta": delta}


def regenerate(threat: str) -> dict[str, Any]:
    formula, letters = lamaconv_input(threat)
    arg = f"LTL={formula},ALPHABET=[{','.join(letters)}]"
    out = subprocess.run(["java", "-jar", str(JAR), arg, "--formula", "--moore", "--min"],
                         capture_output=True, text=True, check=True).stdout
    machine = parse_moore(out)
    machine.update({"threat": threat, "ltl": LTL[threat], "atoms": list(A.ATOMS[threat]),
                    "alphabet": letters, "lamaconv_formula": formula,
                    "tool": "LamaConv rltlconv.jar --formula --moore --min", "raw": out})
    CACHE[threat].write_text(json.dumps(machine, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return machine


_machines: dict[str, dict[str, Any]] = {}


def machine(threat: str) -> dict[str, Any]:
    if threat not in _machines:
        path = CACHE[threat]
        m = json.loads(path.read_text(encoding="utf-8")) if path.exists() else regenerate(threat)
        if m.get("ltl") != LTL[threat]:
            m = regenerate(threat)
        _machines[threat] = m
    return _machines[threat]


class Monitor:
    """Moore machine run for one grounded instance."""

    def __init__(self, threat: str) -> None:
        self.m = machine(threat)
        self.threat = threat
        self.state = self.m["start"]

    def step(self, val: dict[str, bool]) -> str:
        letter = _letter(A.as_bits(val, self.threat))
        if letter not in self.m["alphabet"]:
            raise ValueError(f"valuation {letter} outside the monitor alphabet")
        row = self.m["delta"][self.state]
        self.state = row.get(letter, row.get("?", self.state))
        return self.m["states"][self.state]

    @property
    def verdict(self) -> str:
        return self.m["states"][self.state]


def valuation(ev: dict[str, Any], threat: str, inst: dict[str, Any]) -> dict[str, bool]:
    """atoms.valuation, with d false at a decision whose outcome is not observed."""
    val = A.valuation(ev, threat, inst)
    if val["d"] and not A.outcome_observed(ev):
        val["d"] = False
    return val


def instance_verdict(events: list[dict[str, Any]], threat: str, inst: dict[str, Any]) -> str:
    """LTL3 verdict ("true"/"false"/"?") of instance `inst` over the whole trace `events`."""
    mon = Monitor(threat)
    for ev in events:
        if mon.step(valuation(ev, threat, inst)) != "?":
            break  # top and bottom are final
    return mon.verdict


def reachable(m: dict[str, Any]) -> set[str]:
    seen, todo = {m["start"]}, [m["start"]]
    while todo:
        q = todo.pop()
        row = m["delta"][q]
        for letter in m["alphabet"]:
            t = row.get(letter, row.get("?", q))
            if t not in seen:
                seen.add(t)
                todo.append(t)
    return seen


def skip_is_exact(threat: str) -> bool:
    """Every letter with all data-matching atoms false is a self-loop in every reachable state."""
    m = machine(threat)
    names = A.ATOMS[threat]
    idle = [x for x in m["alphabet"]
            if all(x[1 + names.index(a)] == "0" for a in A.MATCH_ATOMS[threat])]
    return all(m["delta"][q].get(x, m["delta"][q].get("?", q)) == q for q in reachable(m) for x in idle)


class Online:
    """Incremental LTL3 monitor over parametric slices."""

    def __init__(self, threat: str) -> None:
        self.threat = threat
        self.m = machine(threat)
        self.skip = skip_is_exact(threat)
        self.base: dict[Any, str] = {}                     # group -> state for members not seen yet
        self.slices: dict[Any, dict[Any, str]] = {}        # group -> member -> state

    def _next(self, q: str, ev: dict[str, Any], inst: dict[str, Any]) -> str:
        if self.m["states"][q] != "?":
            return q  # top and bottom are final
        letter = _letter(A.as_bits(valuation(ev, self.threat, inst), self.threat))
        if letter not in self.m["alphabet"]:
            raise ValueError(f"valuation {letter} outside the monitor alphabet")
        row = self.m["delta"][q]
        return row.get(letter, row.get("?", q))

    def feed(self, ev: dict[str, Any]) -> str | None:
        """Read one event; for a decision of the threat return its verdict, else None."""
        threat, start = self.threat, self.m["start"]
        verdict = None
        g, m = A.slice_key(ev, threat)
        if ev.get("event_type") == A.DECISION[threat]:
            members = self.slices.get(g, {})
            q = start if g is None else members.get(m, self.base.get(g, start))
            verdict = VERDICT[self.m["states"][self._next(q, ev, A.instance_of(ev, threat))]]
        # update the slices of this event's group as an event other than their decision (all live slices
        # when skipping idle letters is not exact)
        if self.skip:
            groups = [g] if g is not None else []
        else:
            groups = list({**self.base, **({g: None} if g is not None else {})})
        for grp in groups:
            members = self.slices.setdefault(grp, {})
            if grp == g and m is not None and m not in members:
                members[m] = self.base.get(g, start)
            for member, q in members.items():
                members[member] = self._next(q, ev, A.slice_inst(threat, grp, member))
            self.base[grp] = self._next(self.base.get(grp, start), ev, A.slice_inst(threat, grp, None))
        return verdict


# Event that starts a monitored run before its decision (2026-10-21, handoff 2 part B). An LTL3 instance
# exists from the run's first event: for THR-019 the verifier's request (request r, initiating session s).
# If no decision with an observed outcome for the same (r, s) follows, the instance never sees its
# terminator d and its verdict at the end of the trace is '?'. THR-015 runs start with their decision.
START = {A.THR019: "PRESENTATION_REQUESTED"}


def judge(events: list[dict[str, Any]], threat: str) -> list[dict[str, Any]]:
    mon, rows = Online(threat), []
    started: list[tuple[dict[str, Any], tuple[Any, Any]]] = []
    decided: set[tuple[Any, Any]] = set()
    for ev in events:
        verdict = mon.feed(ev)
        if verdict is not None:
            rows.append({"event_id": ev.get("event_id"), "workflow_ref": ev.get("workflow_ref"),
                         "verdict": verdict})
            if A.outcome_observed(ev):
                decided.add(A.slice_key(ev, threat))
        elif ev.get("event_type") == START.get(threat):
            started.append((ev, A.slice_key(ev, threat)))
    return rows + _unterminated(started, decided)


def _unterminated(started: list[tuple[dict[str, Any], tuple[Any, Any]]],
                  decided: set[tuple[Any, Any]]) -> list[dict[str, Any]]:
    """Runs whose start was observed but no decision with an observed outcome for the same data: '?'."""
    return [{"event_id": ev.get("event_id"), "workflow_ref": ev.get("workflow_ref"), "verdict": "undetermined"}
            for ev, key in started if None in key or key not in decided]


def reference_judge(events: list[dict[str, Any]], threat: str) -> list[dict[str, Any]]:
    rows = []
    for k in A.decision_positions(events, threat):
        inst = A.instance_of(events[k], threat)
        rows.append({"event_id": events[k].get("event_id"), "workflow_ref": events[k].get("workflow_ref"),
                     "verdict": VERDICT[instance_verdict(events, threat, inst)]})
    started = [(ev, A.slice_key(ev, threat)) for ev in events if ev.get("event_type") == START.get(threat)]
    decided = {A.slice_key(events[k], threat) for k in A.decision_positions(events, threat)
               if A.outcome_observed(events[k])}
    return rows + _unterminated(started, decided)
