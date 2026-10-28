"""Bounded follow-up measurements; run from the repository root with PYTHONPATH=src:.

No detector code is replaced. Stage timers wrap the real methods; allocations are
traced in separate processes and are never used as latency or RSS measurements.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import tracemalloc
from collections import defaultdict
from pathlib import Path

from experiments.eval.harness import run as harness
from experiments.eval.harness.synth import iter_runs
from tdid.engine import Engine
from tdid.rules import all_rules


def status():
    return {s.split(':')[0]: int(s.split()[1])
            for s in Path('/proc/self/status').read_text().splitlines()
            if s.startswith(('VmRSS:', 'VmHWM:'))}


def state(n, count, seed, trace):
    engine = Engine(rules=[r for r in all_rules() if count == 21 or r.threat_id == 'TDID-THR-015'])
    initial = status()
    if trace:
        tracemalloc.start()
    base = tracemalloc.get_traced_memory()[0] if trace else 0
    expected_events = 0
    for run in iter_runs(n, seed):
        for raw in run.lines():
            engine.feed(json.loads(raw))
            expected_events += 1
        engine.result.findings.clear()
    if engine.result.rejections or engine.result.accepted_events != expected_events:
        raise RuntimeError('rejected or missing input')
    heap = tracemalloc.get_traced_memory()[0] - base if trace else None
    if trace:
        tracemalloc.stop()
    final = status()
    return dict(n_proofs=n, rules=count, seed=seed, traced=trace,
                state_entries=sum(map(len, engine.state.data.values())),
                namespaces={k: len(v) for k, v in engine.state.data.items()},
                gate_seen_ids=len(engine.gate.seen), accepted_events=expected_events,
                heap_growth_bytes=heap, rss_after_init_kib=initial['VmRSS'],
                hwm_after_init_kib=initial['VmHWM'], rss_end_kib=final['VmRSS'],
                hwm_end_kib=final['VmHWM'])


def stages(n, count, seed, instrumented):
    engine = Engine(rules=[r for r in all_rules() if count == 21 or r.threat_id == 'TDID-THR-015'])
    totals, calls = defaultdict(int), defaultdict(int)

    def wrap(obj, name, key):
        original = getattr(obj, name)

        def timed(*args, **kwargs):
            t0 = time.perf_counter_ns()
            try:
                return original(*args, **kwargs)
            finally:
                totals[key] += time.perf_counter_ns() - t0
                calls[key] += 1
        setattr(obj, name, timed)

    if instrumented:
        wrap(engine.gate, 'admit', 'gate')
        wrap(engine.state, 'commit', 'commit')
        for rule in engine.rules:
            wrap(rule, 'evaluate', 'rule_evaluate')
    digest = hashlib.sha256()
    events = 0
    for run in iter_runs(n, seed):
        for raw in run.lines():  # generation and serialisation excluded from processing timers
            t0 = time.perf_counter_ns()
            ev = json.loads(raw)
            t1 = time.perf_counter_ns()
            findings = engine.feed(ev)
            t2 = time.perf_counter_ns()
            totals['parse'] += t1 - t0
            totals['feed'] += t2 - t1
            events += 1
            own = [(f.trigger_event_id, str(f.verdict)) for f in findings
                   if f.threat_id == 'TDID-THR-015']
            digest.update(json.dumps(own, separators=(',', ':')).encode())
            engine.result.findings.clear()
    if engine.result.rejections or engine.result.accepted_events != events:
        raise RuntimeError('rejected or missing input')
    if instrumented:
        totals['other_engine'] = totals['feed'] - sum(totals[k] for k in ('gate', 'commit', 'rule_evaluate'))
    totals['processing'] = totals['parse'] + totals['feed']
    return dict(rules=count, seed=seed, instrumented=instrumented, runs=n, events=events,
                target_verdict_sha256=digest.hexdigest(), calls=dict(calls),
                ns=dict(totals), us_per_event={k: v / events / 1000 for k, v in totals.items()})


def latency(out):
    judges = harness.default_judges()
    judges['tdid_all'] = {'argv': judges['tdid']['argv'] + ['--all-rules']}
    judges['fo_pre'] = judges['fo']
    judges['echo_pre'] = judges['echo']
    summaries = []
    # Interleaved pairs, reversed every other repeat, with matched workload seeds.
    # Keep event records incrementally so an interrupted run loses no finished cell.
    with (out / 'latency_events.jsonl').open('x') as raw:
        cells = []
        for load in (1000, 2000):
            for repeat in range(5):
                names = ('tdid', 'tdid_all', 'echo') if repeat % 2 == 0 else ('echo', 'tdid_all', 'tdid')
                cells.extend((load, repeat, name, False) for name in names)
        # Paired control for a concrete harness contribution: JSON encoding in
        # the timed sender. It does not identify OS vs pipe vs monitor time.
        for load, names in ((1500, ('fo', 'fo_pre')), (2000, ('fo', 'fo_pre')),
                            (3000, ('echo', 'echo_pre'))):
            for repeat in range(3):
                order = names if repeat % 2 == 0 else names[::-1]
                cells.extend((load, repeat, name, name.endswith('_pre')) for name in order)
        for load, repeat, name, preencode in cells:
            row, records = harness.measure_latency(name, judges, load, repeat, 5, 1, 5,
                                                   preencode=preencode)
            if row['completed'] != row['offered_runs']:
                raise RuntimeError(f'incomplete cell: {row}')
            invalid = ('rejected', 'no_finding', '')
            if not name.startswith('echo') and any(r['verdict'] in invalid for r in records):
                raise RuntimeError('target verdict missing')
            for record in records:
                raw.write(json.dumps(record, separators=(',', ':')) + '\n')
            raw.flush()
            summaries.append(row)
            harness._write_csv(out / 'latency_summary.csv', summaries)
            print(json.dumps(row), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=['state', 'stages', 'latency'])
    ap.add_argument('--n', type=int, default=3000)
    ap.add_argument('--rules', type=int, choices=[1, 21], default=1)
    ap.add_argument('--seed', type=int, default=0)
    ap.add_argument('--trace', action='store_true')
    ap.add_argument('--instrumented', action='store_true')
    ap.add_argument('--out', type=Path)
    args = ap.parse_args()
    if args.mode == 'latency':
        args.out.mkdir(parents=True, exist_ok=True)
        latency(args.out)
    elif args.mode == 'state':
        print(json.dumps(state(args.n, args.rules, args.seed, args.trace)), flush=True)
    else:
        print(json.dumps(stages(args.n, args.rules, args.seed, args.instrumented)), flush=True)


if __name__ == '__main__':
    main()
