"""Narrow sequential follow-up: preserve completed memory work; stages and latency only."""
import json
import argparse
import platform
import subprocess
import sys
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--out', type=Path, default=Path('results/data/cost_followup'))
out = parser.parse_args().out
out.mkdir(parents=True, exist_ok=True)
cmd = [sys.executable, '-m', 'experiments.eval.harness.followup']
metadata = json.loads((out / 'environment.json').read_text()) if (out / 'environment.json').exists() else {
    'python': sys.version, 'platform': platform.platform(),
    'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()}
metadata['latency_start_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
(out / 'environment.json').write_text(json.dumps(metadata, indent=2))
with (out / 'stages.jsonl').open('x') as f:
    for seed in range(5):
        signatures = []
        for count in (1, 21):
            for instrumented in (False, True):
                args = ['stages', '--n', '3000', '--rules', str(count), '--seed', str(seed)]
                if instrumented:
                    args += ['--instrumented']
                raw = subprocess.check_output(cmd + args, timeout=120, text=True)
                row = json.loads(raw)
                signatures.append(row['target_verdict_sha256'])
                f.write(json.dumps(row) + '\n'); f.flush()
                print(raw.strip(), flush=True)
        if len(set(signatures)) != 1:
            raise RuntimeError('instrumentation or all-rules changed target verdicts')
subprocess.run(cmd + ['latency', '--out', str(out)], timeout=360, check=True)
metadata['end_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
(out / 'environment.json').write_text(json.dumps(metadata, indent=2))
print('bounded latency session complete', flush=True)
