"""Bounded cost diagnosis; uses the existing engine, stream judges and harness.

No security check or threat predicate is changed. This is a fresh measurement
session, not extra points spliced into the older cost curves.
"""
from __future__ import annotations
import argparse
import calendar
import gzip
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

from experiments.eval.harness import run as harness
from experiments.eval.harness.followup import status
from experiments.eval.harness.synth import iter_runs
from tdid.engine import Engine
from tdid.rules import all_rules


def memory(seed, count):
    engine = Engine(rules=[r for r in all_rules() if count == 21 or r.threat_id == 'TDID-THR-015'])
    checkpoints = set(range(0, 100001, 10000))
    events = 0
    digest = hashlib.sha256()

    def emit(n):
        s = status()
        entries = sum(map(len, engine.state.data.values()))
        assert entries == n and not engine.result.rejections
        assert engine.result.accepted_events == events
        print(json.dumps(dict(n_proofs=n, rules=count, seed=seed,
            state_entries=entries, gate_seen_ids=len(engine.gate.seen),
            accepted_events=events, rss_kib=s['VmRSS'], peak_rss_kib=s['VmHWM'],
            target_verdict_sha256=digest.hexdigest())), flush=True)

    emit(0)
    for n, run in enumerate(iter_runs(100000, seed), 1):
        for j, raw in enumerate(run.lines()):
            findings = engine.feed(json.loads(raw))
            own = [f for f in findings if f.threat_id == 'TDID-THR-015']
            expected = 'succeeded' if j == 1 else 'not_succeeded'
            assert len(own) == 1 and str(own[0].verdict) == expected
            digest.update((own[0].trigger_event_id + ':' + str(own[0].verdict) + '\n').encode())
            events += 1
            engine.result.findings.clear()
        if n in checkpoints:
            emit(n)


def main(out, budget, resume=False):
    out.mkdir(parents=True, exist_ok=resume)
    began = time.monotonic()
    env = dict(start_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        base_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        python=sys.version, platform=platform.platform(),
        purpose='Dense cost diagnosis; same THR-015 workload, all checks retained',
        loads=list(range(500, 2001, 250)), repeats=3, window_s=5, warmup_s=1,
        preencode=True, memory_checkpoints=list(range(0, 100001, 10000)),
        memory_processes='fresh process for each rule count and seed; cumulative within process',
        budget_s=budget, complete=False)
    if resume:
        previous = json.loads((out/'environment.json').read_text())
        saved = out/'scoring_vocabulary_attempt'
        saved.mkdir(exist_ok=False)
        for name in ['environment.json','latency_summary.csv','latency_events.jsonl.gz']:
            if (out/name).exists():
                (out/name).rename(saved/name)
        env['start_utc'] = previous['start_utc']
        elapsed = time.time() - calendar.timegm(time.strptime(env['start_utc'], '%Y-%m-%dT%H:%M:%SZ'))
        began -= elapsed
        env['resumed_latency_after_s'] = elapsed
        env['resume_reason'] = 'Correct scoring-only verdict aliases; preserve complete memory phase and previous attempt'
        kept = [json.loads(line) for line in (out/'memory.jsonl').read_text().splitlines()]
        assert len(kept)==66
        assert {(r['rules'],r['seed'],r['n_proofs']) for r in kept} == {
            (count,seed,n) for count in (1,21) for seed in range(3) for n in range(0,100001,10000)}
    (out/'environment.json').write_text(json.dumps(env, indent=2))
    # Memory first: 6 independent processes, 11 snapshots per process.
    with (out/'memory.jsonl').open('a' if resume else 'x') as fh:
        for seed in range(3):
            for count in ((1,21) if seed % 2 == 0 else (21,1)):
                if resume:
                    continue
                elapsed = time.monotonic() - began
                if elapsed > budget - 30:
                    raise TimeoutError('bounded diagnostic budget exhausted')
                cp = subprocess.run([sys.executable, __file__, '--memory', str(count),
                    '--seed', str(seed)], text=True, capture_output=True, check=True,
                    timeout=min(180, budget-elapsed))
                rows = [json.loads(line) for line in cp.stdout.splitlines()]
                assert len(rows) == 11
                fh.write(cp.stdout); fh.flush()
                print(json.dumps(dict(phase='memory', rules=count, seed=seed,
                    rss_end_mib=rows[-1]['rss_kib']/1024,
                    elapsed_s=round(time.monotonic()-began,2))), flush=True)
    judges = harness.default_judges()
    judges['tdid_all'] = {'argv': judges['tdid']['argv'] + ['--all-rules']}
    names = ['tdid_all','pltl','ltl3','fo','echo']
    summaries = []
    # One raw row per event; retain every final run after warmup for percentiles.
    with gzip.open(out/'latency_events.jsonl.gz', 'xt') as raw:
        for repeat in range(3):
            loads = env['loads'] if repeat % 2 == 0 else env['loads'][::-1]
            for load_index, load in enumerate(loads):
                shift = (repeat + load_index) % len(names)
                order = names[shift:] + names[:shift]
                if repeat % 2:
                    order = order[::-1]
                for name in order:
                    if time.monotonic()-began > budget-15:
                        raise TimeoutError('bounded diagnostic budget exhausted')
                    summary, records = harness.measure_latency(name, judges, load,
                        repeat, window=5, warmup=1, drain=5, preencode=True)
                    assert summary['completed'] == summary['offered_runs']
                    assert len(records) == len({r['event_id'] for r in records})
                    # Synthetic truth is used only after the run, for scoring.
                    wrong = 0
                    final = {}
                    for r in records:
                        final[r['run']] = r
                        if name != 'echo':
                            if r['verdict'] not in ('succeeded','not_succeeded','attack','no_attack'):
                                raise AssertionError('missing, rejected or unknown target verdict')
                        raw.write(json.dumps(r, separators=(',',':'))+'\n')
                    if name != 'echo':
                        aliases = {'succeeded':'attack','not_succeeded':'no_attack',
                                   'attack':'attack','no_attack':'no_attack'}
                        wrong = sum(aliases[r['verdict']] != ('attack' if r['attack'] else 'no_attack')
                                    for r in final.values())
                        assert wrong == 0
                    summary.update(preencode=True, target_wrong=wrong,
                        elapsed_s=round(time.monotonic()-began,2))
                    summaries.append(summary)
                    raw.flush()
                    harness._write_csv(out/'latency_summary.csv', summaries)
                    print(json.dumps(summary), flush=True)
    env.update(complete=True, elapsed_s=round(time.monotonic()-began,2),
        end_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        memory_rows=66, latency_cells=len(summaries))
    (out/'environment.json').write_text(json.dumps(env, indent=2))


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path)
    ap.add_argument('--budget', type=float, default=900)
    ap.add_argument('--memory', type=int, choices=[1,21])
    ap.add_argument('--seed', type=int, default=0)
    ap.add_argument('--resume-latency', action='store_true')
    args = ap.parse_args()
    if args.memory:
        memory(args.seed, args.memory)
    else:
        main(args.out, args.budget,args.resume_latency)
