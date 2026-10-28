from __future__ import annotations

import json
import subprocess
import sys

from experiments.eval.harness import run as harness
from experiments.eval.harness.synth import runs
from tdid.engine import Engine
from tdid.ingest import Gate


def test_synth_valid_and_shaped_like_real_events():
    workload = runs(200, seed=4)
    gate = Gate()
    seqs = []
    for r in workload:
        for ev in r.events:
            assert gate.admit(ev) is True
            seqs.append(ev["producer"]["seq"])
            assert ev["policy"]["params"] == {"allowed_proof_uses": 1}
    assert seqs == list(range(len(seqs)))
    assert workload[0].events[0]["producer"]["stream_start"] is True
    assert gate.stream_complete("walt.id issuer")
    assert len({r.events[0]["refs"]["proof_ref"] for r in workload}) == 200
    assert 0.1 < sum(r.attack for r in workload) / 200 < 0.3
    assert runs(50, seed=4) == workload[:50]


def test_synth_attack_runs_are_the_succeeded_ones():
    workload = runs(100, seed=1)
    events = [ev for r in workload for ev in r.events]
    result = Engine().run(enumerate(events))
    succeeded = {f.workflow_ref for f in result.findings
                 if f.threat_id == "TDID-THR-015" and str(f.verdict) == "succeeded"}
    assert succeeded == {r.events[0]["workflow_ref"] for r in workload if r.attack}
    assert not result.rejections


def test_judge_tdid_protocol():
    workload = runs(30, seed=2)
    data = b"".join(b"".join(r.lines()) for r in workload)
    proc = subprocess.run([sys.executable, "-m", "experiments.eval.harness.judge_tdid"], input=data,
                          capture_output=True, cwd=harness.ROOT, env=harness._env(), timeout=120, check=True)
    lines = [json.loads(x) for x in proc.stdout.splitlines()]
    expected = []
    for r in workload:
        expected.append((r.events[0]["event_id"], "not_succeeded"))
        if r.attack:
            expected.append((r.events[1]["event_id"], "succeeded"))
    assert [(x["event_id"], x["verdict"]) for x in lines] == expected


def test_memory_reports_peak_rss():
    judges = harness.default_judges()
    row = harness.measure_memory("echo", judges, 20)
    assert row["verdicts"] == row["decisions"] and row["peak_rss_kib"] > 1000


def test_latency_open_loop_and_probe():
    judges = harness.default_judges()
    summary, rows = harness.measure_latency("echo", judges, load=20, repeat=0, window=1.5, warmup=0.5, drain=10)
    assert summary["offered_runs"] == 30 and summary["completed"] == 30
    assert summary["sent"] == 30 and summary["backlog_at_end"] <= 1
    assert 0 <= summary["p50_ms"] <= summary["p95_ms"] < 200
    assert len(rows) == sum(len(r.events) for r in runs(31, 0)[1:])  # run 0 primes the judge
    sched = sorted({r["scheduled_ms"] for r in rows})
    assert abs(sched[1] - sched[0] - 50.0) < 0.01          # fixed 1/L spacing
    p = harness.probe("echo", judges, duration=1.5, warmup=0.5)
    assert p["max_runs_per_s"] > 100


def test_judge_cmd_option_registers_external_judge(tmp_path):
    harness.main(["memory", "--judges", "e2", "--judge-cmd",
                  f"e2={sys.executable} -m experiments.eval.harness.echo_judge",
                  "--n", "5", "--repeats", "1", "--out", str(tmp_path)])
    text = (tmp_path / "memory.csv").read_text().splitlines()
    assert text[0].startswith("judge,n_proofs,peak_rss_kib,repeat") and text[1].startswith("e2,5,")


def test_diagnostic_judge_gives_the_same_verdicts_as_the_real_judge():
    import json as _json
    from experiments.eval.harness import judge_tdid_diag
    from experiments.eval.harness.synth import iter_runs
    from tdid.engine import Engine
    from tdid.rules import all_rules
    events = [_json.loads(line) for run in iter_runs(300, seed=5) for line in run.lines()]
    real = Engine(rules=[r for r in all_rules() if r.threat_id == "TDID-THR-015"])
    diag = judge_tdid_diag.make_engine("TDID-THR-015")
    for ev in events:
        a = [(f.trigger_event_id, f.verdict) for f in real.feed(ev)]
        b = [(f.trigger_event_id, f.verdict) for f in diag.feed(ev)]
        assert a == b
    assert not real.result.rejections and not diag.result.rejections


def test_preencoded_sender_keeps_verdicts_and_records_write_completion():
    summaries = []
    verdicts = []
    for preencode in (False, True):
        summary, rows = harness.measure_latency(
            "tdid", harness.default_judges(), load=20, repeat=7,
            window=1.2, warmup=0.2, drain=5, preencode=preencode)
        summaries.append(summary)
        verdicts.append([(r["event_id"], r["verdict"]) for r in rows])
        assert all(r["write_done_ms"] >= r["written_ms"] for r in rows)
        assert all(r["verdict"] not in ("rejected", "no_finding", "") for r in rows)
    assert verdicts[0] == verdicts[1]
    assert all(s["completed"] == s["offered_runs"] == 24 for s in summaries)
