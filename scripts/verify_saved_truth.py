"""Reaggregate saved, redacted oracle fields; does not rerun product or signatures."""
from pathlib import Path
from collections import Counter
import csv, json

def main():
    root = Path(__file__).resolve().parent
    with (root.parent/'data/static/workflow_evidence_42.csv').open(encoding='utf-8-sig', newline='') as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        witness = json.loads(row['safe_truth_fields'])
        if row['threat'] == 'TDID-THR-015':
            outcomes = [x['outcome'] for x in witness]
            actual = ('attack' if 'duplicate_delivery' in outcomes else
                      'unknown' if 'unknown_server_outcome' in outcomes else 'no_attack')
        else:
            assert row['threat'] == 'TDID-THR-019'
            valid = all(witness[k] for k in ('result_verified', 'transaction_matches', 'subject_matches_wallet'))
            actual = ('unknown' if not valid else 'attack' if
                      witness['consumer_controller_differs_from_verified_subject'] and witness['access_entry'] == 'granted'
                      else 'no_attack')
        assert actual == row['truth'], (row['product'], row['workflow'], actual, row['truth'])
    known = [r for r in rows if r['included_in_39'].lower() == 'true']
    assert len(rows) == 42 and len(known) == 39
    assert Counter(r['truth'] for r in rows) == {'attack': 9, 'no_attack': 30, 'unknown': 3}
    assert Counter(r['verdict'] for r in known) == {'attack': 6, 'no_attack': 24, 'unknown': 9}
    assert all(r['truth'] == r['verdict'] for r in known if r['verdict'] != 'unknown')
    print(json.dumps({'stored_truth_matches': len(rows), 'known_truth': len(known),
                      'determinate_verdicts': 30, 'incomplete_verdicts': 9,
                      'scope': 'saved oracle aggregation; no product or signature re-execution'}, indent=2))

if __name__ == '__main__':
    main()
