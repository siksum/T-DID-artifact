"""Paired product collection OFF/ON cost; reuses pinned collection points and request recipes."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
BUILD = Path('build')


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def validate_block(dest, product, mode, repetitions):
    out = dest / ('waltid' if product == 'waltid' else 'credo')
    load = lambda name: [json.loads(x) for x in (out / name).read_text().splitlines()]
    design, truth = load('case-design.jsonl'), load('oracle.jsonl')
    assert len(design) == repetitions * 5, (product, 'case count', len(design))
    expected = {'fresh': [200], 'different_proof': [200,200], 'same_session_reuse': [200,200],
                'new_session_reuse': [200,400] if product == 'waltid' else [200,200],
                'bad_signature': [200,400]}
    by_case = {}
    for row in truth:
        by_case.setdefault(row['case_id'], []).append(row)
    for row in design:
        rows = by_case[row['case_id']]
        statuses = row['statuses'] if product == 'waltid' else [r['http_status'] for t in rows for r in t['requests']]
        assert statuses == expected[row['scenario']], (row['case_id'], statuses)
        attack = row['scenario'] == 'same_session_reuse' or (product == 'credo' and row['scenario'] == 'new_session_reuse')
        assert any(r['truth'] == 'succeeded' for r in rows) == attack, row['case_id']
        if product == 'waltid':
            assert sum(rows[0]['valid_credentials_per_proof']) == sum(s == 200 for s in statuses), row['case_id']
        else:
            assert all(r['credentials_received'] == (1 if r['http_status'] == 200 else 0) for t in rows for r in t['requests']), row['case_id']
    events = load('tdid-events.jsonl') if (out / 'tdid-events.jsonl').exists() else []
    assert len(events) == (repetitions * 9 if mode == 'on' else 0), (product, mode, 'events', len(events))
    write(dest / 'validation.json', {'passed': True, 'cases': len(design), 'events': len(events),
        'credential_requests': repetitions * 9, 'status_and_independent_truth_match_predefined_recipes': True})


def walt_block(dest, mode, repetitions):
    spec = importlib.util.spec_from_file_location('walt', REPO / 'testbed/tdid/waltid/run_waltid.py')
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    source = BUILD / ('waltid-identity-' + w.COMMIT)
    ctx = w.Run(dest, source, repetitions)
    ctx.out.mkdir(parents=True)
    work = dest / 'work'
    work.mkdir()
    events = ctx.out / 'tdid-events.jsonl'
    counts = {}
    callback = w.callback_server(ctx.out / 'callbacks.jsonl', ctx.keys['native_capture'])
    env = {}
    if mode == 'on':
        env = {'TDID_EVENTS_PATH': str(events), 'TDID_ROLE': 'issuer',
               'TDID_INSTANCE': f'waltid-cost-{dest.name}',
               'TDID_POLICY': json.dumps(ctx.policy('issuer', {'allowed_proof_uses': 1})),
               'TDID_LOCAL_KEY': ctx.keys['issuer'].hex()}
    proc, threads, binary = w.start_service(source, 'issuer', work, ctx.out, env, counts)
    try:
        w.wait_ready(ctx.origin('issuer'), proc)
        st, ctx.issuer = ctx.client.call('issuer.onboard', 'POST', ctx.origin('issuer') + '/onboard/issuer',
            body={'key': {'backend': 'jwk', 'keyType': 'Ed25519'}, 'did': {'method': 'key'}})
        assert st == 200
        _, meta = ctx.client.call('issuer.metadata', 'GET', ctx.origin('issuer') + '/draft13/.well-known/openid-credential-issuer')
        ctx.vct = meta['credential_configurations_supported']['identity_credential_vc+sd-jwt']['vct']
        original_add = ctx.design.add
        last_bytes = 0
        def design_add(row):
            nonlocal last_bytes
            current = events.stat().st_size if events.exists() else 0
            row.update(mode=mode, phase='warmup' if row['repetition'] < 10 else 'measured', event_bytes=current-last_bytes)
            last_bytes = current
            original_add(row)
        ctx.design.add = design_add
        assert ctx.thr015() == repetitions * 5
        write(dest / 'block.json', {'status': 'completed', 'product': 'waltid', 'mode': mode,
            'repetitions': repetitions, 'binary': binary, 'source_commit': w.COMMIT, 'redactions': counts})
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        for thread in threads:
            thread.join(timeout=5)
        callback.shutdown()
        shutil.rmtree(work)


def credo_block(dest, mode, repetitions):
    tree = BUILD / 'credo-ts-3c32928107639bc355f82d4ba11c4d91901e11cb'
    target = tree / 'packages/openid4vc/tests/tdid-cost.e2e.test.ts'
    shutil.copy2(REPO / 'testbed/tdid/credo/tdid-cost.e2e.test.ts', target)
    dest.mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith('TDID_')}
    env.update(TDID_RUN_DIR=str(dest), TDID_REPS=str(repetitions), TDID_COST_MODE=mode)
    command = ['node', 'node_modules/vitest/vitest.mjs', 'run', '--project', 'e2e', '--no-cache',
               'packages/openid4vc/tests/tdid-cost.e2e.test.ts']
    with (dest / 'runner.log').open('w') as log:
        subprocess.run(command, cwd=tree, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
    write(dest / 'block.json', {'status': 'completed', 'product': 'credo', 'mode': mode,
        'repetitions': repetitions, 'command': command, 'source_commit': tree.name.split('credo-ts-')[1]})


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--products', nargs='+', default=['waltid', 'credo'])
    p.add_argument('--pairs', type=int, default=10)
    p.add_argument('--repetitions', type=int, default=30)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    write(a.out / 'protocol.json', {'pairs': a.pairs, 'warmup_cases_per_block': min(10, a.repetitions) * 5,
        'measured_cases_per_block': max(0, a.repetitions - 10) * 5, 'scenario_mix': 'equal five THR-015 existing recipes',
        'timing': 'monotonic credential request to full response body; startup/oracle excluded',
        'baseline': 'same pinned build, added collection OFF; not pristine unpatched binary',
        'products': a.products, 'repetitions': a.repetitions,
        'python': sys.version, 'platform': platform.platform(),
        'commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),
        'loadavg': os.getloadavg(), 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())})
    for product in a.products:
        for pair in range(a.pairs):
            for order, mode in enumerate(('off','on') if pair % 2 == 0 else ('on','off')):
                dest = a.out / f'{product}-pair{pair:02d}-{mode}'
                if (dest / 'completion.json').exists():
                    continue
                print(product, pair, order, mode, 'start', flush=True)
                (walt_block if product == 'waltid' else credo_block)(dest, mode, a.repetitions)
                validate_block(dest, product, mode, a.repetitions)
                shutil.copy2(dest / 'block.json', dest / 'completion.json')
                print(product, pair, order, mode, 'completed', flush=True)


if __name__ == '__main__':
    main()
