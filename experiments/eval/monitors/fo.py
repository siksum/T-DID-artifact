"""First-order temporal monitor with data: MonPoly (Metric First-Order Temporal Logic).

Basin, Klaedtke, Mueller, Zalinescu, "Monitoring Metric First-Order Temporal Properties", JACM 62(2), 2015;
Basin, Klaedtke, Zalinescu, "The MonPoly Monitoring Tool", RV-CuBES 2017. MonPoly reads a timestamped log
of relational events and outputs, at each time point, the valuations of the formula's free variables that
satisfy it. We monitor the ATTACK formula (mfotl/thr0xx.mfotl): an output is an attack decision; a
decision with no output is no attack. mfotl/thr0xx.verdict.mfotl outputs (e, verdict) at every decision
(used by the online stream for latency measurement).

Data are first-class (variables over proof/output/request/session values), so no grounding is needed.
Missing information: MonPoly is two-valued over the log it is given (public MonPoly has no incomplete-log
or three-valued mode). An absent field is encoded as a fresh constant unique to its event and field, so
any equality with it is false (absent equals nothing), i.e. the atom is false, as in the other monitors.

Binary: MonPoly 1.4.3 (docker image infsec/monpoly:1.4.3, amd64) copied to vendor/monpoly with its musl
loader and libgmp (vendor/musl), run on the host through the loader. Fallback: the docker image.
Time stamps: the replay position (one time point per event), so ONCE[1,*) means "at an earlier event".
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from experiments.eval.monitors import atoms as A

HERE = Path(__file__).resolve().parent
VENDOR = HERE / "vendor"
MFOTL = HERE / "mfotl"
FILES = {A.THR015: "thr015", A.THR019: "thr019"}
IMAGE = "infsec/monpoly:1.4.3"


def monpoly_cmd() -> list[str]:
    loader, binary = VENDOR / "musl" / "ld-musl-x86_64.so.1", VENDOR / "monpoly"
    if os.environ.get("MONPOLY_DOCKER") != "1" and loader.exists() and binary.exists():
        return [str(loader), "--library-path", str(VENDOR / "musl"), str(binary)]
    if shutil.which("docker"):
        return ["docker", "run", "--rm", "-i", "-v", f"{MFOTL}:/mfotl:ro", IMAGE]
    raise RuntimeError("MonPoly not available (vendor binary or docker image)")


def _spec_paths(threat: str, verdict: bool, general: bool = False) -> tuple[str, str]:
    """``general``: THR-015 with any policy limit (CNT aggregation over the unbounded past, quadratic in
    MonPoly). Default: the limit-1 form, identical outputs when every decision states limit 1."""
    base = FILES[threat]
    formula = f"{base}.verdict.mfotl" if verdict else f"{base}.mfotl"
    if general and threat == "TDID-THR-015":
        formula = "general/thr015_cnt.verdict.mfotl" if verdict else "general/thr015_cnt.mfotl"
    if monpoly_cmd()[0] == "docker":
        return f"/mfotl/{base}.sig", f"/mfotl/{formula}"
    return str(MFOTL / f"{base}.sig"), str(MFOTL / formula)


def command(threat: str, verdict: bool = False, general: bool = False) -> list[str]:
    sig, formula = _spec_paths(threat, verdict, general)
    return monpoly_cmd() + ["-sig", sig, "-formula", formula]


def _s(value: Any, absent: str) -> str:
    """A MonPoly string constant; an absent value becomes a constant unique to its event and field."""
    text = absent if value is None else str(value)
    return '"' + text.replace('"', "'").replace("\\", "/") + '"'


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value) if float(value).is_integer() else None


def tuples(ev: dict[str, Any], threat: str, pos: int) -> list[str]:
    """Relational events observed in one T-DID event."""
    kind = ev.get("event_type")
    eid = ev.get("event_id")
    nul = f"<absent:{pos}:"
    e = _s(eid, nul + "event_id>")
    refs = ev.get("refs") if isinstance(ev.get("refs"), dict) else {}
    results = ((ev.get("checks") or {}).get("results") or {})
    outcome = (ev.get("decision") or {}).get("outcome")
    out: list[str] = []
    if threat == A.THR015:
        if kind != "ISSUANCE_DECISION":
            return out
        out.append(f"dec({e},{_s(refs.get('proof_ref'), nul + 'proof>')},{_s(refs.get('output_ref'), nul + 'output>')})")
        if results.get(A.KEY_PROOF_CHECK) == "pass":
            out.append(f"pass({e})")
        if outcome == "issue":
            out.append(f"issue({e})")
        n = _int(A.allowed(ev))
        if n is not None:
            out.append(f"allowed({e},{n})")
        return out
    if kind == "PRESENTATION_REQUESTED":
        mode = (ev.get("facts") or {}).get("vp_response_mode") if isinstance(ev.get("facts"), dict) else None
        out.append(f"preq({_s(refs.get('request_ref'), nul + 'request>')},"
                   f"{_s(refs.get('frontend_session_ref'), nul + 'session>')},{_s(mode, nul + 'mode>')})")
    elif kind == "WALLET_RESPONSE_SENT":
        if outcome == "none":
            out.append(f"wsent({_s(refs.get('request_ref'), nul + 'request>')})")
    elif kind == "RELYING_AUTHENTICATION_DECISION":
        out.append(f"rpd({e},{_s(refs.get('request_ref'), nul + 'request>')},"
                   f"{_s(refs.get('frontend_session_ref'), nul + 'session>')})")
        code = results.get(A.CODE_CHECK)
        if code is not None:
            out.append(f"code({e},{_s(code, '')})")
        if outcome == "accept":
            out.append(f"accept({e})")
        # notuser(e): InitiatorIsNotWalletUser is recorded by no component, so it is never emitted.
    return out


def log_line(ev: dict[str, Any], threat: str, pos: int) -> str:
    return f"@{pos} " + " ".join(tuples(ev, threat, pos)) + ";\n"


_TUPLE = re.compile(r'\(([^()]*)\)')


def parse_output(text: str) -> list[tuple[str, ...]]:
    """MonPoly output lines '@ts (time point i): ("e1","x") ("e2","y")' -> tuples."""
    rows = []
    for line in text.splitlines():
        if "(time point" not in line:
            continue
        body = line.split("):", 1)[1]
        for inner in _TUPLE.findall(body):
            rows.append(tuple(x.strip().strip('"') for x in inner.split(",")) if inner else ())
    return rows


def judge(events: list[dict[str, Any]], threat: str) -> list[dict[str, Any]]:
    log = "".join(log_line(ev, threat, i) for i, ev in enumerate(events))
    limits = {((ev.get("policy") or {}).get("params") or {}).get("allowed_proof_uses")
              for ev in events if ev.get("event_type") == "ISSUANCE_DECISION"}
    general = bool(limits - {1, None})
    proc = subprocess.run(command(threat, general=general), input=log, capture_output=True, text=True,
                          check=True)
    attacks = {t[0] for t in parse_output(proc.stdout)}
    return [{"event_id": events[k].get("event_id"), "workflow_ref": events[k].get("workflow_ref"),
             "verdict": "attack" if events[k].get("event_id") in attacks else "no_attack"}
            for k in A.decision_positions(events, threat)]


class Online:
    """One MonPoly process; one log time point per event; reads the verdict of each decision."""

    def __init__(self, threat: str) -> None:
        self.threat = threat
        self.pos = 0
        self.proc = subprocess.Popen(command(threat, verdict=True), stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    def feed(self, ev: dict[str, Any]) -> str | None:
        """Send one event; for a decision return its verdict ("attack"/"no_attack"), else None."""
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(log_line(ev, self.threat, self.pos))
        self.proc.stdin.flush()
        self.pos += 1
        if ev.get("event_type") != A.DECISION[self.threat]:
            return None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("MonPoly ended: " + (self.proc.stderr.read() if self.proc.stderr else ""))
            rows = parse_output(line)
            if rows:
                return rows[-1][1]

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=10)
