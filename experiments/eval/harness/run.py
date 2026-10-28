"""Replay cost harness: per-judge memory and latency on the same synthetic THR-015 event stream.

Judge protocol: a judge is a command that reads JSONL events on stdin and writes one JSON line per decision
event (``{"event_id": ..., ...}``), flushing after each. Every measurement starts a fresh judge process.

Commands (run from the repository root with PYTHONPATH=src:.):
  python -m experiments.eval.harness.run memory  --judges tdid --n 10 100 1000 --out DIR
  python -m experiments.eval.harness.run latency --judges tdid --loads 50 100 200 --window 10 --out DIR
  python -m experiments.eval.harness.run probe   --judges tdid --duration 5
  extra judges: --judge-cmd 'name=python -m some.module --flag' (repeatable)

Memory: peak RSS of the judge process = ``VmHWM`` in ``/proc/<pid>/status``, read after the last verdict
arrived and before stdin is closed. This is correct only when the Popen pid *is* the judge (a direct
``python -m ...``). For a judge run as ``docker run -i --rm --name <c> ...`` the pid is the docker CLI, so
declare the judge's memory source as ``docker:<c>``: the harness then reads the container's cgroup v2
``memory.peak`` (``/sys/fs/cgroup/system.slice/docker-<id>.scope/memory.peak``, id from ``docker inspect``)
while the container is still running. memory.peak counts the container's page cache and kernel memory as well
as anonymous memory, so it is an upper bound on RSS; report it as such. If it cannot be read (cgroup v1,
other cgroup driver, no permission) the value is null and the reason goes to the ``note`` column.

Latency vs offered load (open loop): run i of a window is scheduled at t0 + i/L, fixed in advance; the
sender thread writes each run at its scheduled time and never waits for verdicts; a reader thread stamps each
verdict line with ``time.perf_counter_ns``. Decision latency = verdict read time - scheduled send time (the
intended time, so a sender delayed by a full pipe still counts the queueing delay); the actual write time is
kept too. ``sent`` = runs actually written by the window end (a saturated judge fills the pipe and blocks
the sender); ``backlog_at_end`` = runs scheduled in the window without a final verdict at the window end
(queued in the sender, the pipe or the judge). A run's latency is that of its last decision. Runs scheduled in the first ``--warmup`` seconds are
excluded from percentiles. Before t0 one priming run is sent and its verdicts awaited, so interpreter start-up
is not measured. After the window the harness waits up to ``--drain`` seconds for outstanding verdicts.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from experiments.eval.harness.synth import Run, iter_runs

ROOT = Path(__file__).resolve().parents[3]
PY = sys.executable


def default_judges() -> dict[str, dict]:
    judges = {
        "tdid": {"argv": [PY, "-m", "experiments.eval.harness.judge_tdid", "--threat", "TDID-THR-015"]},
        "echo": {"argv": [PY, "-m", "experiments.eval.harness.echo_judge"]},
        # diagnostic only: rule and state path without input validation (never used for a verdict)
        "tdid_diag": {"argv": [PY, "-m", "experiments.eval.harness.judge_tdid_diag", "--threat", "TDID-THR-015"]},
    }
    for kind in ("pltl", "ltl3", "fo"):
        judges[kind] = {"argv": [PY, "-m", "experiments.eval.monitors.stream", "--judge", kind,
                                 "--threat", "TDID-THR-015"]}
    return judges


def _tree(pid: int) -> list[int]:
    """pid and all its descendants (from /proc/<pid>/task/*/children)."""
    out, todo = [], [pid]
    while todo:
        p = todo.pop()
        out.append(p)
        for task in Path(f"/proc/{p}/task").glob("*"):
            try:
                todo += [int(c) for c in (task / "children").read_text().split()]
            except OSError:
                pass
    return out


def _env() -> dict[str, str]:
    env = dict(os.environ)
    paths = [str(ROOT / "src"), str(ROOT)]
    if env.get("PYTHONPATH"):
        paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


# ---------------------------------------------------------------------------------------------- judge process
@dataclass
class Judge:
    name: str
    argv: list[str]
    memory: str = "proc"            # "proc" or "docker:<container-name>"
    proc: subprocess.Popen | None = None
    read_ns: dict[str, int] = field(default_factory=dict)
    verdicts: dict[str, object] = field(default_factory=dict)
    count: int = 0
    on_read: object = None          # callable(event_id) from the reader thread
    _cv: threading.Condition = field(default_factory=threading.Condition)
    _reader: threading.Thread | None = None

    def start(self) -> Judge:
        self.proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, cwd=ROOT, env=_env(), bufsize=0)
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        return self

    def _read(self) -> None:
        stream = self.proc.stdout
        for line in iter(stream.readline, b""):
            now = time.perf_counter_ns()
            try:
                msg = json.loads(line)
                eid = msg["event_id"]
            except (ValueError, KeyError, TypeError):
                continue
            self.read_ns.setdefault(eid, now)
            self.verdicts[eid] = msg.get("verdict")
            if self.on_read is not None:
                self.on_read(eid)
            with self._cv:
                self.count += 1
                self._cv.notify_all()
        with self._cv:
            self._cv.notify_all()

    def write(self, data: bytes) -> bool:
        try:
            self.proc.stdin.write(data)
            return True
        except (BrokenPipeError, ValueError, OSError):
            return False

    def wait_count(self, n: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._cv:
            while self.count < n:
                left = deadline - time.monotonic()
                if left <= 0 or self.proc.poll() is not None and self._reader and not self._reader.is_alive():
                    return self.count >= n
                self._cv.wait(min(left, 0.5))
        return True

    def peak_rss_kib(self) -> tuple[int | None, str]:
        if self.memory == "proc":
            try:
                # The judge process and every process it started (e.g. the MonPoly process behind the
                # first-order wrapper): sum of their peak resident sets.
                total, pids = 0, _tree(self.proc.pid)
                for pid in pids:
                    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                        if line.startswith("VmHWM:"):
                            total += int(line.split()[1])
                return total, "VmHWM" if len(pids) == 1 else f"VmHWM sum over {len(pids)} processes"
            except OSError as exc:
                return None, f"cannot read /proc status: {exc}"
            return None, "VmHWM not present"
        if self.memory.startswith("docker:"):
            return docker_memory_peak(self.memory.split(":", 1)[1])
        return None, f"unknown memory source {self.memory}"

    def close(self, timeout: float = 10.0) -> None:
        if self.proc is None:
            return
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        if self._reader:
            self._reader.join(timeout=5)


def docker_memory_peak(container: str) -> tuple[int | None, str]:
    try:
        cid = subprocess.run(["docker", "inspect", "--format", "{{.Id}}", container], capture_output=True,
                             text=True, timeout=10, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"docker inspect failed: {exc}"
    path = Path(f"/sys/fs/cgroup/system.slice/docker-{cid}.scope/memory.peak")
    try:
        return int(path.read_text().strip()) // 1024, "cgroup memory.peak (includes page cache)"
    except OSError as exc:
        return None, f"cannot read {path}: {exc}"


def make_judge(name: str, judges: dict[str, dict]) -> Judge:
    spec = judges[name]
    return Judge(name, list(spec["argv"]), spec.get("memory", "proc"))


# --------------------------------------------------------------------------------------------------- memory
def measure_memory(name: str, judges: dict[str, dict], n_runs: int, seed: int = 0,
                   timeout: float = 600.0) -> dict:
    judge = make_judge(name, judges).start()
    workload = list(iter_runs(n_runs, seed))
    n_dec = sum(len(r.events) for r in workload)

    def send() -> None:
        for run in workload:
            if not judge.write(b"".join(run.lines())):
                return

    sender = threading.Thread(target=send, daemon=True)
    t0 = time.perf_counter_ns()
    sender.start()
    ok = judge.wait_count(n_dec, timeout)
    elapsed = (time.perf_counter_ns() - t0) / 1e9
    peak, note = judge.peak_rss_kib() if ok else (None, f"only {judge.count}/{n_dec} verdicts")
    judge.close()
    return {"judge": name, "n_proofs": n_runs, "peak_rss_kib": peak, "decisions": n_dec,
            "verdicts": judge.count, "elapsed_s": round(elapsed, 3), "note": note}


# -------------------------------------------------------------------------------------------------- latency
def _sleep_until(target_ns: int) -> None:
    while True:
        left = target_ns - time.perf_counter_ns()
        if left <= 0:
            return
        if left > 2_000_000:
            time.sleep((left - 1_000_000) / 1e9)
        elif left > 200_000:
            time.sleep(0)


def _prime(judge: Judge, gen: Iterator[Run], timeout: float) -> None:
    run = next(gen)
    judge.write(b"".join(run.lines()))
    if not judge.wait_count(len(run.events), timeout):
        raise RuntimeError(f"judge {judge.name} produced no verdict for the priming run")


def measure_latency(name: str, judges: dict[str, dict], load: float, repeat: int, window: float = 10.0,
                    warmup: float = 1.0, drain: float = 30.0, seed: int | None = None,
                    start_timeout: float = 120.0, preencode: bool = False) -> tuple[dict, list[dict]]:
    judge = make_judge(name, judges).start()
    gen = iter_runs(None, seed if seed is not None else repeat)
    _prime(judge, gen, start_timeout)
    base = judge.count
    n_sched = int(window * load - 1e-9) + 1 if load > 0 else 0
    schedule = [next(gen) for _ in range(n_sched)]
    # Optional diagnostic control: move JSON serialisation out of the timed sender.
    # Judge inputs and scheduled-to-read latency definition remain unchanged.
    payloads = [b"".join(r.lines()) for r in schedule] if preencode else None
    period = 1e9 / load
    t0 = time.perf_counter_ns() + 50_000_000
    t_end = t0 + int(window * 1e9)
    written: dict[int, int] = {}
    write_done: dict[int, int] = {}

    def send() -> None:
        for i, run in enumerate(schedule):
            _sleep_until(t0 + int(i * period))
            written[i] = time.perf_counter_ns()
            if not judge.write(payloads[i] if payloads is not None else b"".join(run.lines())):
                return
            write_done[i] = time.perf_counter_ns()

    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    _sleep_until(t_end)
    sent_by_end = sum(1 for w in list(write_done.values()) if w <= t_end)
    last_ids = [r.events[-1]["event_id"] for r in schedule]
    done_by_end = sum(1 for eid in last_ids if judge.read_ns.get(eid, t_end + 1) <= t_end)
    judge.wait_count(base + sum(len(r.events) for r in schedule), drain)
    judge.close(timeout=5)
    sender.join(timeout=5)

    rows, run_lat = [], []
    warm_ns = t0 + int(warmup * 1e9)
    achieved = 0
    for i, run in enumerate(schedule):
        sched = t0 + int(i * period)
        for ev in run.events:
            read = judge.read_ns.get(ev["event_id"])
            rows.append({"judge": name, "load": load, "repeat": repeat, "run": i, "attack": int(run.attack),
                         "event_id": ev["event_id"], "scheduled_ms": round((sched - t0) / 1e6, 3),
                         "written_ms": round((written[i] - t0) / 1e6, 3) if i in written else "",
                         "write_done_ms": round((write_done[i] - t0) / 1e6, 3) if i in write_done else "",
                         "read_ms": round((read - t0) / 1e6, 3) if read else "",
                         "latency_ms": round((read - sched) / 1e6, 3) if read else "",
                         "verdict": judge.verdicts.get(ev["event_id"], "")})
        last = judge.read_ns.get(run.events[-1]["event_id"])
        if last is not None and sched >= warm_ns:
            run_lat.append((last - sched) / 1e6)
        if last is not None and warm_ns <= last <= t_end:
            achieved += 1
    run_lat.sort()
    completed = sum(1 for eid in last_ids if eid in judge.read_ns)
    summary = {"judge": name, "load": load, "repeat": repeat, "sent": sent_by_end, "completed": completed,
               "backlog_at_end": n_sched - done_by_end,
               "p50_ms": round(_pct(run_lat, 50), 3) if run_lat else "",
               "p95_ms": round(_pct(run_lat, 95), 3) if run_lat else "",
               "achieved_runs_per_s": round(achieved / max(window - warmup, 1e-9), 2),
               "offered_runs": n_sched, "measured_runs": len(run_lat)}
    return summary, rows


def _pct(sorted_vals: list[float], q: float) -> float:
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * q / 100
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


# ---------------------------------------------------------------------------------------------------- probe
def probe(name: str, judges: dict[str, dict], duration: float = 5.0, warmup: float = 1.0,
          in_flight: int = 1000, start_timeout: float = 120.0) -> dict:
    """Closed loop with a window of `in_flight` outstanding runs, sending as fast as the window allows."""
    judge = make_judge(name, judges).start()
    gen = iter_runs(None, 0)
    _prime(judge, gen, start_timeout)
    slots = threading.Semaphore(in_flight)
    last_ids: set[str] = set()
    done_at: list[int] = []

    def on_read(eid: str) -> None:
        if eid in last_ids:
            done_at.append(time.perf_counter_ns())
            slots.release()

    judge.on_read = on_read
    t0 = time.perf_counter_ns()
    t_end = t0 + int(duration * 1e9)
    stop = threading.Event()

    def send() -> None:
        for run in gen:
            while not slots.acquire(timeout=0.1):
                if stop.is_set():
                    return
            if stop.is_set():
                return
            last_ids.add(run.events[-1]["event_id"])
            if not judge.write(b"".join(run.lines())):
                return

    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    _sleep_until(t_end)
    stop.set()
    judge.proc.kill()
    judge.close(timeout=5)
    sender.join(timeout=5)
    warm = t0 + int(warmup * 1e9)
    n = sum(1 for t in done_at if warm <= t <= t_end)
    return {"judge": name, "max_runs_per_s": round(n / (duration - warmup), 1), "runs_completed": len(done_at),
            "duration_s": duration}


# ------------------------------------------------------------------------------------------------------ CLI
def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=["memory", "latency", "probe"])
    ap.add_argument("--judges", nargs="+", default=["tdid"])
    ap.add_argument("--judge-cmd", action="append", default=[],
                    help="name=command line (shlex-split); optional ' @docker:<container>' suffix")
    ap.add_argument("--n", type=int, nargs="+", default=[10, 32, 100, 316, 1000, 3162, 10000])
    ap.add_argument("--loads", type=float, nargs="+", default=[10, 30, 100, 300])
    ap.add_argument("--repeats", type=int, default=None, help="default: memory 3, latency 5")
    ap.add_argument("--window", type=float, default=10.0)
    ap.add_argument("--warmup", type=float, default=1.0)
    ap.add_argument("--drain", type=float, default=30.0)
    ap.add_argument("--preencode", action="store_true",
                    help="diagnostic control: serialise runs before the timed sender starts")
    ap.add_argument("--duration", type=float, default=5.0)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    judges = default_judges()
    for spec in args.judge_cmd:
        name, _, cmd = spec.partition("=")
        memory = "proc"
        if " @docker:" in cmd:
            cmd, _, container = cmd.rpartition(" @docker:")
            memory = f"docker:{container}"
        judges[name] = {"argv": shlex.split(cmd), "memory": memory}

    if args.mode == "memory":
        rows = []
        for name in args.judges:
            for n in args.n:
                for r in range(args.repeats or 3):
                    row = measure_memory(name, judges, n, seed=r)
                    row = {"judge": row["judge"], "n_proofs": n, "peak_rss_kib": row["peak_rss_kib"],
                           "repeat": r, "elapsed_s": row["elapsed_s"], "note": row["note"]}
                    print(json.dumps(row), flush=True)
                    rows.append(row)
        if args.out:
            _write_csv(args.out / "memory.csv", rows)
    elif args.mode == "latency":
        summaries, events = [], []
        for name in args.judges:
            for load in args.loads:
                for r in range(args.repeats or 5):
                    s, ev_rows = measure_latency(name, judges, load, r, args.window, args.warmup, args.drain,
                                                preencode=args.preencode)
                    print(json.dumps(s), flush=True)
                    summaries.append(s)
                    events.extend(ev_rows)
        if args.out:
            _write_csv(args.out / "latency_summary.csv", summaries)
            _write_csv(args.out / "latency_events.csv", events)
    else:
        rows = []
        for name in args.judges:
            row = probe(name, judges, args.duration, args.warmup)
            print(json.dumps(row), flush=True)
            rows.append(row)
        if args.out:
            _write_csv(args.out / "probe.csv", rows)


if __name__ == "__main__":
    main()
