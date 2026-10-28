"""Command line: ``tdid run`` turns input records into final threat verdicts in one step."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tdid import __version__, spec
from tdid.engine import Engine, read_jsonl, replay_order, workflow_summary


def _cmd_run(args: argparse.Namespace) -> int:
    if args.product:
        from tdid.collectors import convert  # noqa: PLC0415 - optional path

        policy = json.loads(Path(args.policy).read_text(encoding="utf-8")) if args.policy else None
        events = convert(args.product, Path(args.input), level=args.level, policy=policy,
                         fresh=args.fresh_start)
        records = ((i, ev) for i, ev in enumerate(events, start=1))
    else:
        handle = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")  # noqa: SIM115
        records = read_jsonl(handle)
    producers = None
    if args.producers:
        producers = frozenset(json.loads(Path(args.producers).read_text(encoding="utf-8")))
    engine = Engine(producers=producers)
    result = engine.run(replay_order(records))
    report = {
        "tdid_version": __version__,
        "schema_version": spec.envelope()["schema_version"],
        "input": args.input,
        "product": args.product,
        "accepted_events": result.accepted_events,
        "duplicate_events": result.duplicate_events,
        "rejected_records": [r.__dict__ for r in result.rejections],
        "incomplete_streams": result.incomplete_streams,
        "workflows": workflow_summary(result.findings),
        "findings": [f.as_dict() for f in result.findings],
    }
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _print_table(report)
    return 0


def _print_table(report: dict) -> None:
    print(f"T-DID {report['tdid_version']}  accepted={report['accepted_events']} "
          f"duplicates={report['duplicate_events']} rejected={len(report['rejected_records'])}")
    for stream, why in report["incomplete_streams"].items():
        print(f"  incomplete history: {stream}: {why}")
    for r in report["rejected_records"]:
        print(f"  rejected line {r['line']} ({r['event_id']}): {r['reason']}")
    shown = [w for w in report["workflows"] if not w["no_relevant_record"]]
    print(f"{'threat':<14} {'workflow':<28} {'verdict':<14} unknown conditions")
    for w in shown:
        unknown = ", ".join(w["unknown_conditions"])
        print(f"{w['threat_id']:<14} {w['workflow_ref']:<28} {w['verdict']:<14} {unknown}")
    silent: dict[str, int] = {}
    for w in report["workflows"]:
        if w["no_relevant_record"]:
            silent[w["threat_id"]] = silent.get(w["threat_id"], 0) + 1
    if silent:
        counts = ", ".join(f"{t.replace('TDID-', '')}x{n}" for t, n in sorted(silent.items()))
        print(f"incomplete, input carries no record about the threat (workflows): {counts}")


def _cmd_pack(args: argparse.Namespace) -> int:
    from tdid import dataset  # noqa: PLC0415

    policy = json.loads(Path(args.policy).read_text(encoding="utf-8")) if args.policy else None
    info = json.loads(Path(args.info).read_text(encoding="utf-8")) if args.info else {}
    manifest = dataset.pack(Path(args.run), Path(args.out), products=args.product, info=info,
                            policy=policy, fresh=args.fresh_start)
    print(f"packed {len(manifest['files'])} files into {args.out}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from tdid import dataset  # noqa: PLC0415

    problems = dataset.verify(Path(args.dataset))
    for p in problems:
        print(p)
    print("dataset verified" if not problems else f"{len(problems)} problem(s)")
    return 0 if not problems else 1


def _cmd_schema(args: argparse.Namespace) -> int:
    print(json.dumps(spec.json_schema(), indent=2))
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    from tdid.rules import all_rules  # noqa: PLC0415

    readers = spec.rule_users()
    reg = spec.registry()
    rows = []
    for rule in all_rules():
        reads = sorted(n for n, users in readers.items() if rule.threat_id in users)
        rows.append({
            "threat_id": rule.threat_id, "title": rule.title,
            "records_from": "one component" if rule.locality == "local" else "several components",
            "triggers": sorted(rule.triggers), "conditions": list(rule.conditions),
            "decision_conditions": sorted(rule.decision_conditions),
            "policy_params": [n for n in reads if n in reg["policy_params"]],
            "fields": [n for n in reads if n not in reg["policy_params"] and n not in reg["event_types"]],
            "limits": rule.limits,
        })
    if args.format == "json":
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    for r in rows:
        print(f"## {r['threat_id']} {r['title']}\n")
        print(f"- Records from: {r['records_from']}; judged on: {', '.join(r['triggers'])}")
        conds = [f"{c} (decision)" if c in r["decision_conditions"] else c for c in r["conditions"]]
        print(f"- Success conditions (all must hold): {', '.join(conds)}")
        print(f"- Fields read: {', '.join(r['fields'])}")
        print(f"- Policy parameters: {', '.join(r['policy_params']) or 'none'}")
        if r["limits"]:
            print(f"- Limits: {r['limits']}")
        print()
    return 0


def _cmd_fields(args: argparse.Namespace) -> int:
    rows = spec.field_dictionary()
    if args.format == "json":
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    print("| section | field | produced by | meaning | what it reveals | threats |")
    print("|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['section']} | {r['name']} | {', '.join(r['produced_by'])} | {r['meaning']} | "
              f"{r['reveals']} | {', '.join(t.replace('TDID-', '') for t in r['used_by'])} |")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tdid", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="detect threats in T-DID events (JSONL) or in raw product records")
    run.add_argument("input", help="events.jsonl, '-' for stdin, or a raw-record directory with --product")
    run.add_argument("--product", choices=["waltid", "credo", "credo-vp"], help="convert raw product records first")
    run.add_argument("--level", choices=["native", "added"], default="added",
                     help="with --product: use only native product records, or native plus added records")
    run.add_argument("--policy",
                     help="with --product: JSON policy {id, version, params} the deployment enforces")
    run.add_argument("--fresh-start", action="store_true",
                     help="with --product: the product instance started with empty state for these records")
    run.add_argument("--producers", help="JSON list of registered producer instances; others are rejected")
    run.add_argument("--out", help="write the full JSON report here")
    run.add_argument("--format", choices=["table", "json"], default="table")
    run.set_defaults(func=_cmd_run)

    ds = sub.add_parser("dataset", help="pack a run into a dataset, or verify one")
    ds_sub = ds.add_subparsers(dest="action", required=True)
    pk = ds_sub.add_parser("pack", help="copy a run, separate product records from client and truth, judge")
    pk.add_argument("run", help="run directory with one sub-directory per product")
    pk.add_argument("out", help="new dataset directory")
    pk.add_argument("--product", action="append", required=True, choices=["waltid", "credo", "credo-vp"])
    pk.add_argument("--policy", help="JSON policy {id, version, params} the deployment enforced")
    pk.add_argument("--info", help="JSON {product: {implementation, source_commit, ...}}")
    pk.add_argument("--fresh-start", action="store_true",
                    help="product instances started with empty state for this run")
    pk.set_defaults(func=_cmd_pack)
    vf = ds_sub.add_parser("verify", help="re-hash files and re-derive events and verdicts from records/")
    vf.add_argument("dataset")
    vf.set_defaults(func=_cmd_verify)

    sch = sub.add_parser("schema", help="print the generated JSON Schema of the event structure")
    sch.set_defaults(func=_cmd_schema)

    rl = sub.add_parser("rules", help="print the rule dictionary (conditions, fields, limits per threat)")
    rl.add_argument("--format", choices=["markdown", "json"], default="markdown")
    rl.set_defaults(func=_cmd_rules)

    fld = sub.add_parser("fields", help="print the field dictionary (what each field reveals)")
    fld.add_argument("--format", choices=["markdown", "json"], default="markdown")
    fld.set_defaults(func=_cmd_fields)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
