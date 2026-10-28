"""Project principles checked over all rules at once (one place, plain pytest)."""

import ast
from importlib import resources

from tdid import spec

FORBIDDEN = ("scenario", "oracle", "ground_truth", "expected_verdict", "session_controller", "case_id")


def _rule_sources():
    for entry in sorted(resources.files("tdid.rules").iterdir(), key=lambda p: p.name):
        if entry.name.startswith("thr") and entry.name.endswith(".py"):
            yield entry.name, ast.parse(entry.read_text(encoding="utf-8"))

# Required checks of a decision: the envelope invariant needs them on accept/issue decisions, but no
# threat condition reads them.
REQUIRED_CHECK_ONLY = {"rp_verification_result_check", "transaction_code_validation"}


def test_every_field_is_read_by_a_rule():
    unused = [r["name"] for r in spec.field_dictionary()
              if not r["used_by"] and r["name"] not in REQUIRED_CHECK_ONLY]
    assert unused == []


def test_threat_specific_fields_are_read_by_their_own_rule():
    reg = spec.registry()
    readers = spec.rule_users()
    stray = []
    for key, declared_by in reg["used_by"].items():
        name = key.split(".", 1)[1]
        for threat in declared_by:
            if threat != "COMMON" and name not in REQUIRED_CHECK_ONLY and threat not in readers.get(name, []):
                stray.append((threat, name))
    assert stray == []


def test_every_field_says_who_produces_it_and_what_it_means():
    for r in spec.field_dictionary():
        assert r["meaning"], r["name"]
        if r["section"] != "policy_params":   # set by the deployment's policy, not by a component
            assert r["produced_by"], r["name"]


def test_refs_and_facts_say_what_they_reveal():
    for r in spec.field_dictionary():
        if r["section"] in ("refs", "facts"):
            assert r["reveals"], r["name"]


def test_no_rule_assumes_a_policy_value():
    """param(ev, name, default) must not supply a non-None default."""
    offenders = []
    for name, tree in _rule_sources():
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "param"
                    and len(node.args) > 2 and not (isinstance(node.args[2], ast.Constant)
                                                    and node.args[2].value is None)):
                offenders.append((name, node.lineno))
    assert offenders == []


def test_no_rule_reads_apparatus_or_scenario_values():
    """No string literal in rule code (docstrings excluded) names test apparatus or scenarios."""
    offenders = []
    for name, tree in _rule_sources():
        docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                      if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef)) and n.body
                      and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings
                    and any(word in node.value.lower() for word in FORBIDDEN)):
                offenders.append((name, node.lineno, node.value))
    assert offenders == []


def test_every_threat_has_one_rule():
    from tdid.rules import all_rules
    assert sorted(r.threat_id for r in all_rules()) == [f"TDID-THR-{n:03d}" for n in range(1, 22)]


def test_rules_declare_their_conditions_and_decision_conditions_are_among_them():
    from tdid.rules import all_rules
    for rule in all_rules():
        assert rule.conditions and len(set(rule.conditions)) == len(rule.conditions), rule.threat_id
        assert rule.decision_conditions <= set(rule.conditions), rule.threat_id


def test_rule_dictionary_lists_every_threat(capsys):
    import json

    from tdid.cli import main
    assert main(["rules", "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 21 and all(r["conditions"] and r["fields"] for r in rows)
