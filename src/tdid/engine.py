"""Detection engine: validated events -> history -> threat rules -> verdicts."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from tdid.ingest import Gate, InputRejected, UnregisteredProducer
from tdid.model import Finding, Rejection, RunResult, Verdict
from tdid.rules import all_rules
from tdid.rules.base import Rule
from tdid.state import State, View


class Engine:
    def __init__(self, rules: list[Rule] | None = None, producers: frozenset[str] | None = None) -> None:
        self.rules = rules if rules is not None else all_rules()
        self.state = State()
        self.gate = Gate(producers=producers)
        self.result = RunResult()

    def feed(self, ev: Any, line: int = 0) -> list[Finding]:
        event_id = ev.get("event_id") if isinstance(ev, dict) else None
        try:
            if not self.gate.admit(ev):
                self.result.duplicate_events += 1
                return []
            view = View(self.state, self.gate.stream_complete, self.gate.unit_complete)
            produced: list[Finding] = []
            deltas = []
            for rule in self.rules:
                if ev["event_type"] not in rule.triggers:
                    continue
                result = rule.evaluate(ev, view)
                if result is None:
                    continue
                for evaluation in result if isinstance(result, list) else [result]:
                    if not evaluation.record_only:
                        produced.append(rule.finding(ev, evaluation))
                    deltas.extend(evaluation.deltas)
        except InputRejected as exc:
            self.result.rejections.append(Rejection(line, event_id, str(exc)))
            self._hole(ev, f"record {event_id} rejected at the gate: {exc}", exc)
            return []
        except (KeyError, TypeError, ValueError, ArithmeticError, RecursionError) as exc:  # a rule failed
            self.result.rejections.append(Rejection(line, event_id, f"rule evaluation error: {exc!r}"))
            # The gate already advanced this producer's sequence; the dropped record is a hole in its
            # history, so history-dependent conditions for this producer must become unknown.
            self.gate.mark_incomplete(ev["producer"]["instance"], f"record {event_id} rejected by a rule")
            return []
        self.state.commit(deltas)
        self.result.accepted_events += 1
        self.result.findings.extend(produced)
        return produced

    def _hole(self, ev: Any, why: str, exc: InputRejected) -> None:
        """A record a known producer emitted but T-DID could not use leaves a hole in that producer's
        history, so absence-based conditions for it become unknown. Records of unregistered producers and
        records that name no producer are not attributed to any history."""
        producer = ev.get("producer") if isinstance(ev, dict) else None
        instance = producer.get("instance") if isinstance(producer, dict) else None
        if not isinstance(instance, str) or isinstance(exc, UnregisteredProducer):
            return
        # Only the hole is recorded. The rejected record's role or service is not trusted: a forged line
        # must not move a real producer into another unit. An instance never admitted has an unknown unit.
        self.gate.mark_incomplete(instance, why)

    def run(self, records: Iterable[tuple[int, Any]]) -> RunResult:
        """Judge a finished batch. A producer's history can turn out incomplete only at a later record
        (a sequence gap, a missing stream_start, a record a rule could not read), after decisions that
        relied on it were judged. So the batch is judged again with every incompleteness found in the
        previous pass known from the start, until nothing new is found."""
        batch = list(records)
        known: dict[str, str] = {}
        units: dict[str, tuple[str, str | None]] = {}
        for _ in range(len(batch) + 1):
            self.state, self.gate, self.result = State(), Gate(producers=self.gate.producers), RunResult()
            self.gate.incomplete.update(known)
            self.gate.units.update(units)
            for line, ev in batch:
                self.feed(ev, line)
            if self.gate.incomplete == known and self.gate.units == units:
                break
            known, units = dict(self.gate.incomplete), dict(self.gate.units)
        self.result.incomplete_streams = dict(self.gate.incomplete)
        return self.result


def replay_order(records: Iterable[tuple[int, Any]]) -> list[tuple[int, Any]]:
    """Order a finished batch for replay: each producer's records stay in sequence order, and producers
    are interleaved by occurred_at. Verdicts then do not depend on how files were concatenated.
    Records that cannot be ordered (unparseable, no producer or time) go first and are judged at the gate."""
    loose, streams = [], {}
    for line, ev in records:
        try:
            when = datetime.fromisoformat(str(ev["occurred_at"]).replace("Z", "+00:00"))
            if when.tzinfo is None:
                raise ValueError("no offset")
            key = (ev["producer"]["instance"], int(ev["producer"]["seq"]), when)
        except (KeyError, TypeError, ValueError, AttributeError):
            loose.append((line, ev))
            continue
        streams.setdefault(key[0], []).append((key[1], key[2], line, ev))
    heads = []
    for instance, items in streams.items():
        items.sort(key=lambda x: (x[0], x[2]))
        heads.append((instance, items))
    out = list(loose)
    cursor = {instance: 0 for instance, _ in heads}
    pending = dict(heads)
    while pending:
        # next record: the earliest occurred_at among each producer's next record
        instance = min(pending, key=lambda i: (pending[i][cursor[i]][1], i))
        _, _, line, ev = pending[instance][cursor[instance]]
        out.append((line, ev))
        cursor[instance] += 1
        if cursor[instance] == len(pending[instance]):
            del pending[instance]
    return out


def read_jsonl(lines: Iterable[str]) -> Iterable[tuple[int, Any]]:
    for number, raw in enumerate(lines, start=1):
        text = raw.strip()
        if not text:
            continue
        try:
            yield number, json.loads(text, parse_constant=_no_constant)
        # JSONDecodeError, NaN/Infinity, huge integers, deep nesting: only this line is rejected
        except (ValueError, RecursionError) as exc:
            yield number, _Unparseable(f"{type(exc).__name__}: {str(exc)[:200]}")


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


class _Unparseable(dict):
    """Marker that fails admission with a clear reason."""

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message


def final_findings(findings: list[Finding]) -> list[Finding]:
    """Drop findings superseded by a later finding about the same (threat, subject)."""
    latest: dict[tuple[str, str], Finding] = {}
    for f in findings:
        latest[(f.threat_id, f.subject or f.trigger_event_id)] = f
    return [f for f in findings if latest[(f.threat_id, f.subject or f.trigger_event_id)] is f]


def workflow_summary(findings: list[Finding]) -> list[dict[str, Any]]:
    """One verdict per (threat, workflow) over final findings: any success wins, then any incomplete,
    else not succeeded."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in final_findings(findings):
        groups.setdefault((f.threat_id, f.workflow_ref), []).append(f)
    rows = []
    for (threat, workflow), items in sorted(groups.items()):
        verdicts = {f.verdict for f in items}
        if Verdict.SUCCEEDED in verdicts:
            verdict = Verdict.SUCCEEDED
        elif Verdict.INCOMPLETE in verdicts:
            verdict = Verdict.INCOMPLETE
        else:
            verdict = Verdict.NOT_SUCCEEDED
        unknown = sorted({u for f in items for u in f.unknown}) if verdict is Verdict.INCOMPLETE else []
        # Incomplete with nothing settled: the input carried no record about this threat at all.
        no_record = verdict is Verdict.INCOMPLETE and all(f.established == 0 for f in items)
        rows.append({"threat_id": threat, "workflow_ref": workflow, "verdict": str(verdict),
                     "no_relevant_record": no_record, "decisions": len(items),
                     "unknown_conditions": unknown})
    return rows
