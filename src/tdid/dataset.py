"""Run datasets: everything one execution produced, kept apart by who wrote it, plus the T-DID result.

Layout (one directory per run)::

    MANIFEST.json            run information, file classes and SHA-256 of every file
    records/<product>/       written by the product: default logs, native callbacks/SDK events, added
                             collection-point records. The only input of the collectors.
    client/<product>/        written by the test client or the run controller (HTTP view, launch/stop)
    truth/<product>/         ground truth and case design, computed apart from the detector
    meta/                    run plan as written before execution
    events/<product>.<level>.jsonl     converted T-DID events
    verdicts/<product>.<level>.json    T-DID result for those events

``verify`` re-hashes every file and re-derives events and verdicts from ``records/`` alone, so a
reader can check that the published verdicts follow from the product records and nothing else.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from tdid import __version__, spec
from tdid.collectors import LEVELS, collect
from tdid.engine import Engine, final_findings, replay_order, workflow_summary

FORMAT = "tdid-dataset/1"
TRUTH = frozenset({"oracle.jsonl", "oracle.json", "case-design.jsonl"})
CLIENT = frozenset({"http.jsonl", "session-queries.jsonl", "launch.json", "ready.json", "completion.json",
                    "stop.json", "stop", "stdout.receipt.json", "stderr.receipt.json", "receipt.json",
                    "console.txt"})
META = frozenset({"plan.json", "seal.json"})

# Material that must never be published: compact JWS/JWT, PEM private keys, a JWK private component.
_SECRET = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
                     rb"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
                     rb'|\\?"d\\?"\s*:\s*\\?"[A-Za-z0-9_-]{20,}')


# Absolute paths under a user's home directory reveal the account name; packed copies keep them relative
# to that home directory (e.g. /home/<user>/tdid-build/x -> tdid-build/x). Recorded in the manifest.
_HOME = re.compile(rb"/(?:home|Users)/[A-Za-z0-9._-]+/|\\/(?:home|Users)\\/[A-Za-z0-9._-]+\\/")
_HOME_BARE = re.compile(rb"\\?/(?:home|Users)\\?/[A-Za-z0-9._-]+\b")   # a home directory itself -> ~
PATH_NOTE = ("absolute paths under the run host's home directory were rewritten relative to it "
             "(prefix /home/<user>/ or /Users/<user>/ removed, a bare home directory written as ~) in every "
             "packed text file; "
             "hashes are of the rewritten files")


class DatasetError(ValueError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _class_of(name: str) -> str:
    if name in TRUTH:
        return "truth"
    if name in CLIENT:
        return "client"
    return "records"


def _copy_tree(src: Path, dst: Path) -> int:
    """Copy one file; text files get home-relative paths. Returns the number of rewritten paths."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        shutil.copy2(src, dst)
        return 0
    rewritten, count = _HOME.subn(b"", data)
    rewritten, bare = _HOME_BARE.subn(b"~", rewritten)
    count += bare
    dst.write_bytes(rewritten)
    return count


def run_result(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic T-DID result for a list of events (no paths, no clock)."""
    result = Engine().run(replay_order(enumerate(events, start=1)))
    return {
        "tdid_version": __version__,
        "schema_version": spec.envelope()["schema_version"],
        "accepted_events": result.accepted_events,
        "duplicate_events": result.duplicate_events,
        "rejected_records": [r.__dict__ for r in result.rejections],
        "incomplete_streams": result.incomplete_streams,
        "workflows": workflow_summary(result.findings),
        "findings": [f.as_dict() for f in final_findings(result.findings)],
    }


def _dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def _derive(out: Path, products: list[str], policy: dict[str, Any] | None,
            fresh: bool) -> dict[str, list[str]]:
    notes: dict[str, list[str]] = {}
    for product in products:
        for level in LEVELS:
            collected = collect(product, out / "records" / product, level, policy, fresh)
            notes[f"{product}.{level}"] = collected.notes
            _write_jsonl(out / "events" / f"{product}.{level}.jsonl", collected.events)
            _dump(out / "verdicts" / f"{product}.{level}.json", run_result(collected.events))
    return notes


def pack(run: Path, out: Path, *, products: list[str], info: dict[str, Any],
         policy: dict[str, Any] | None, fresh: bool) -> dict[str, Any]:
    """Copy one run into the dataset layout, convert, judge and write MANIFEST.json."""
    run, out = Path(run), Path(out)
    if out.exists():
        raise DatasetError(f"{out} already exists")
    for path in sorted(run.rglob("*")):
        if path.is_file() and _SECRET.search(path.read_bytes()):
            raise DatasetError(f"{path.relative_to(run)} contains key or token material; remove it first")
    rewritten = 0
    for path in sorted(run.iterdir()):
        if path.is_file():
            if path.name not in META:
                raise DatasetError(f"unclassified run-level file {path.name}")
            rewritten += _copy_tree(path, out / "meta" / path.name)
    for product in products:
        folder = run / product
        if not folder.is_dir():
            raise DatasetError(f"no records for {product} in {run}")
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                rel = path.relative_to(folder)
                rewritten += _copy_tree(path, out / _class_of(rel.name) / product / rel)
    notes = _derive(out, products, policy, fresh)
    manifest = {
        "format": FORMAT,
        "tdid_version": __version__,
        "products": {p: info.get(p, {}) for p in products},
        "policy": policy,
        "fresh_start": fresh,
        "levels": list(LEVELS),
        "collector_notes": notes,
        "path_normalization": {"note": PATH_NOTE, "rewritten_paths": rewritten},
        "files": {str(p.relative_to(out)): _sha256(p) for p in sorted(out.rglob("*")) if p.is_file()},
    }
    _dump(out / "MANIFEST.json", manifest)
    return manifest


def verify(folder: Path) -> list[str]:
    """Problems found; empty when every hash matches and events/verdicts re-derive identically."""
    folder = Path(folder)
    manifest = json.loads((folder / "MANIFEST.json").read_text(encoding="utf-8"))
    problems = []
    if manifest.get("format") != FORMAT:
        problems.append(f"unknown format {manifest.get('format')!r}")
    listed = manifest["files"]
    present = {str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file()} - {"MANIFEST.json"}
    problems += [f"file not in manifest: {p}" for p in sorted(present - set(listed))]
    for rel, digest in sorted(listed.items()):
        path = folder / rel
        if not path.exists():
            problems.append(f"missing: {rel}")
        elif _sha256(path) != digest:
            problems.append(f"changed: {rel}")
    scratch = folder.parent / f".{folder.name}.verify"
    if scratch.exists():
        shutil.rmtree(scratch)
    try:
        shutil.copytree(folder / "records", scratch / "records")
        products = list(manifest["products"])
        _derive(scratch, products, manifest["policy"], manifest["fresh_start"])
        for kind in ("events", "verdicts"):
            for path in sorted((scratch / kind).iterdir()):
                if path.read_bytes() != (folder / kind / path.name).read_bytes():
                    problems.append(f"{kind}/{path.name} does not re-derive from records/")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return problems
