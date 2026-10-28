"""Recompute paper evidence from the published records; never infer oracle truth from a detector."""
from pathlib import Path
from collections import Counter, defaultdict
import argparse
import csv
import gzip
import json
import math
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
OUT = ROOT / 'results'
EXPECTED = ROOT / 'data/expected'

def load(path):
    return json.loads(path.read_text())

def same(a, b, path='root'):
    if isinstance(a, dict) and isinstance(b, dict):
        assert a.keys() == b.keys(), (path, a.keys() ^ b.keys())
        for k in a:
            same(a[k], b[k], path + '.' + str(k))
    elif isinstance(a, list) and isinstance(b, list):
        assert len(a) == len(b), (path, len(a), len(b))
        for i, (x, y) in enumerate(zip(a, b)):
            same(x, y, path + f'[{i}]')
    elif isinstance(a, (int, float)) and isinstance(b, (int, float)):
        assert math.isclose(a, b, rel_tol=1e-10, abs_tol=1e-9), (path, a, b)
    else:
        assert a == b, (path, a, b)

def rows(path):
    return list(csv.DictReader(path.open(encoding='utf-8-sig')))

def percentile(values, q):
    a = sorted(values)
    t = (len(a) - 1) * q
    lo = int(t)
    return a[lo] + (a[min(lo + 1, len(a) - 1)] - a[lo]) * (t - lo)

def static_checks():
    p = ROOT/'data/static'
    categories = Counter(r['eligibility'] for r in rows(p/'implementation_feasibility_315.csv'))
    assert categories == {'controlled_evaluation_designable': 22,
                          'applicable_evidence_or_truth_missing': 142, 'not_applicable': 151}
    attack = Counter(r['classification'] for r in rows(p/'attack_elements.csv'))
    assert attack == {'exact': 5, 'partial': 5, 'analogous': 8, 'none': 3}, attack
    assert len(rows(p/'taxonomy_correspondence.csv')) == 63
    assert len(rows(p/'implementation_versions_15.csv')) == 15
    return {'static_cells': sum(categories.values()), 'applicable': 164,
            'eligibility': dict(categories), 'taxonomy_cells': 84, 'attack_correspondence': dict(attack)}

def cost_checks():
    raw = ROOT/'data/measurements/dense-cost-20261022'
    saved = {(r['judge'], float(r['load']), int(r['repeat'])): r for r in rows(raw/'latency_summary.csv')}
    checked = 0
    current = None
    final = {}
    def flush(key, records):
        if key is None:
            return
        nonlocal checked
        values = [float(r['latency_ms']) for r in records.values()
                  if float(r['scheduled_ms']) >= 1000 and r['read_ms'] != '']
        expected = saved[key]
        assert len(values) == int(expected['measured_runs']), (key, len(values), expected)
        # Stored event/summary rows are rounded to 0.001 ms independently.
        assert abs(percentile(values, .95) - float(expected['p95_ms'])) <= .002, key
        assert abs(percentile(values, .5) - float(expected['p50_ms'])) <= .002, key
        checked += 1
    with gzip.open(raw/'latency_events.jsonl.gz', 'rt') as f:
        for line in f:
            r = json.loads(line)
            key = (r['judge'], float(r['load']), int(r['repeat']))
            if current != key:
                flush(current, final)
                final = {}
                current = key
            final[r['run']] = r
    flush(current, final)
    assert checked == len(saved) == 105
    mem = [json.loads(x) for x in (raw/'memory.jsonl').read_text().splitlines() if x.startswith('{')]
    assert len(mem) == 66
    assert all(r['state_entries'] == r['n_proofs'] and r['n_proofs'] <= r['accepted_events'] <= 2*r['n_proofs']
               and r['gate_seen_ids'] == r['accepted_events'] for r in mem)
    end = [r['rss_kib']/1024 for r in mem if r['rules'] == 21 and r['n_proofs'] == 100000]
    assert len(end) == 3 and abs(statistics.median(end)-128.1953125) < 1e-9
    command = [sys.executable, '-m', 'experiments.eval.summarise_product_cost',
               str(ROOT/'data/measurements/product-cost-20261022'), '--out', str(OUT/'product-cost')]
    subprocess.run(command, check=True, cwd=ROOT, stdout=subprocess.DEVNULL)
    product = load(OUT/'product-cost/summary.json')
    reference = load(EXPECTED/'product_cost.json')
    for key in ['complete', 'summary', 'blocks', 'pairs']:
        same(product[key], reference[key], 'product_cost.'+key)
    return {'latency_cells': checked, 'memory_rows': len(mem),
            'all_21_rules_100k_median_rss_mib': statistics.median(end),
            'product_cost_aggregation_matches': True}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full', action='store_true', help='also recompute all 30 deletion seeds')
    args = parser.parse_args()
    started = time.monotonic()
    OUT.mkdir(exist_ok=True)
    checks = {'mode': 'full' if args.full else 'quick', 'new_product_execution': False,
              'new_performance_measurement': False}
    for ds in sorted((ROOT/'datasets').iterdir()):
        command = [sys.executable, '-m', 'tdid.cli', 'dataset', 'verify', str(ds)]
        p = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        (OUT/(ds.name+'-verify.log')).write_text(p.stdout+p.stderr)
        assert p.returncode == 0, (ds.name, p.stdout[-1500:], p.stderr[-1000:])
    checks['dataset_manifests'] = 2
    subprocess.run([sys.executable, str(ROOT/'scripts/verify_saved_truth.py')], check=True)
    checks['static'] = static_checks()
    from experiments.eval import fig1, table2, table_component, fig2
    for name, module in [('fig1',fig1), ('table2',table2), ('table_component',table_component)]:
        actual = module.run()
        same(actual, load(EXPECTED/(name+'.json')), name)
        (OUT/(name+'.json')).write_text(json.dumps(actual, indent=2))
        checks[name] = 'recomputed; matches archived reference'
        print('PASS', name, flush=True)
    eq = fig2.equivalence()
    assert eq['mismatches'] == []
    checks['complete_information_equivalence'] = eq
    if args.full:
        print('Recomputing 30-seed deletion experiment...', flush=True)
        actual = fig2.sweep()
        expected = load(EXPECTED/'fig2.json')
        for key in ['ps','seeds','workflows','wrong','withheld','attacks','tdid_missing_named']:
            same(actual[key], expected[key], 'deletion.'+key)
        (OUT/'field-deletion.json').write_text(json.dumps(actual, indent=2))
        checks['field_deletion'] = 'all 11 probabilities x 30 seeds match'
    checks['cost'] = cost_checks()
    for name in ['draw_diagrams.py','plot_results.py']:
        subprocess.run([sys.executable, str(ROOT/'scripts'/name)], check=True)
    checks['generated_figures'] = [str(x.relative_to(ROOT)) for x in sorted((ROOT/'figures').glob('Fig[1-4].*'))]
    assert len(checks['generated_figures']) == 12
    checks['elapsed_s'] = round(time.monotonic()-started, 2)
    checks['passed'] = True
    (OUT/'reproduction.json').write_text(json.dumps(checks, indent=2))
    print(json.dumps(checks, indent=2))

if __name__ == '__main__':
    main()
