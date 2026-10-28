import json

import pytest

from tdid.collectors import IGNORED, collect, convert
from tdid.engine import Engine, final_findings
from tdid.model import Verdict


def _write(folder, name, rows):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text("".join(json.dumps(r) + "\n" for r in rows))


def _added(seq, proof, cred, decision="issue", validation="pass", status=200):
    return {"schema_version": "tdid-product-observation/v1", "implementation": "x", "sequence": seq,
            "event_id": f"e{seq}", "policy_scope": "single-use-key-proof", "proof_ref": proof,
            "proof_validation_result": validation, "credential_artifact_ref": cred,
            "final_decision": decision, "terminal_status": status, "producer_monotonic_ns": str(1000 + seq)}


POLICY = {"id": "single-use", "version": "1", "params": {"allowed_proof_uses": 1}}


def _verdicts(events):
    result = Engine().run(enumerate(events, start=1))
    assert not result.rejections, result.rejections
    return [f.verdict for f in final_findings(result.findings) if f.threat_id == "TDID-THR-015"]


@pytest.mark.parametrize("product", ["waltid", "credo"])
def test_added_records_detect_replay(tmp_path, product):
    _write(tmp_path, "augmented.jsonl", [_added(0, "prf:a", "cred:1"), _added(1, "prf:a", "cred:2")])
    events = convert(product, tmp_path, policy=POLICY, fresh=True)
    assert _verdicts(events) == [Verdict.NOT_SUCCEEDED, Verdict.SUCCEEDED]


def test_without_operator_policy_the_use_limit_is_unknown(tmp_path):
    _write(tmp_path, "augmented.jsonl", [_added(0, "prf:a", "cred:1"), _added(1, "prf:a", "cred:2")])
    # First use is settled (no earlier use); the reuse cannot be judged without the limit.
    assert _verdicts(convert("waltid", tmp_path, fresh=True)) == [Verdict.NOT_SUCCEEDED, Verdict.INCOMPLETE]


def test_server_error_is_not_read_as_rejection(tmp_path):
    error = _added(1, None, None, decision="reject", validation=None, status=500)
    rows = [_added(0, "prf:a", "cred:1"), error]
    _write(tmp_path, "augmented.jsonl", rows)
    events = convert("credo", tmp_path, policy=POLICY, fresh=True)
    assert events[1]["decision"]["outcome"] == "error"
    assert _verdicts(events)[1] == Verdict.INCOMPLETE


def test_ground_truth_and_client_files_cannot_change_the_output(tmp_path):
    _write(tmp_path, "augmented.jsonl", [_added(0, "prf:a", "cred:1"), _added(1, "prf:a", "cred:2")])
    before = convert("waltid", tmp_path)
    for name in IGNORED:
        (tmp_path / name).write_text('{"outcome": "duplicate_delivery", "scenario": "attack"}\n')
    after = collect("waltid", tmp_path)
    assert after.events == before
    assert set(after.skipped) == IGNORED
    assert not set(after.read) & IGNORED


def test_native_walt_status_callbacks_lack_proof_identity(tmp_path):
    rows = [{"source": "existing_statusCallbackUri", "t_ns": 1, "type": "jwt_issue", "session_ref": "s1",
             "credential_refs": ["c1"]},
            {"source": "existing_statusCallbackUri", "t_ns": 2, "type": "issuance_status",
             "session_ref": "s1", "status": "SUCCESSFUL", "closed": True, "credential_refs": []}]
    _write(tmp_path, "callbacks.jsonl", rows)
    events = convert("waltid", tmp_path, level="native")
    assert events[0]["refs"] == {"output_ref": "c1"}
    assert {"field": "refs.proof_ref", "owner": "issuer"} in events[0]["missing"]
    assert _verdicts(events) == [Verdict.INCOMPLETE]


def test_native_credo_error_state_is_unknown_effect(tmp_path):
    state = "existing_IssuanceSessionStateChanged"
    rows = [{"t_ns": "1", "source": state, "session_ref": "s1", "state": "CredentialRequestReceived",
             "previous_state": "AccessTokenCreated"},
            {"t_ns": "2", "source": state, "session_ref": "s1", "state": "Error",
             "previous_state": "CredentialRequestReceived"}]
    _write(tmp_path, "sdk.jsonl", rows)
    events = convert("credo", tmp_path, level="native")
    assert events[0]["decision"]["outcome"] == "error"


def test_unknown_product_and_level_are_refused(tmp_path):
    with pytest.raises(ValueError):
        convert("acapy", tmp_path)
    with pytest.raises(ValueError):
        convert("waltid", tmp_path, level="everything")


def test_without_declared_fresh_start_earlier_use_cannot_be_ruled_out(tmp_path):
    _write(tmp_path, "augmented.jsonl", [_added(0, "prf:a", "cred:1")])
    assert _verdicts(convert("waltid", tmp_path, policy=POLICY)) == [Verdict.INCOMPLETE]


def _run(tmp_path):
    from tdid import dataset

    run = tmp_path / "run"
    _write(run / "waltid", "augmented.jsonl", [_added(0, "prf:a", "cred:1"), _added(1, "prf:a", "cred:2")])
    _write(run / "waltid", "oracle.jsonl", [{"outcome": "x"}])
    _write(run / "waltid", "http.jsonl", [{"status": 200}])
    out = tmp_path / "ds"
    dataset.pack(run, out, products=["waltid"], info={}, policy=POLICY, fresh=True)
    return dataset, run, out


def test_dataset_separates_who_wrote_what_and_verifies(tmp_path):
    dataset, _, out = _run(tmp_path)
    assert (out / "records/waltid/augmented.jsonl").exists()
    assert (out / "truth/waltid/oracle.jsonl").exists() and (out / "client/waltid/http.jsonl").exists()
    assert dataset.verify(out) == []


def test_dataset_verify_catches_edited_records(tmp_path):
    dataset, _, out = _run(tmp_path)
    path = out / "records/waltid/augmented.jsonl"
    path.write_text(path.read_text().replace("cred:2", "cred:1"))
    problems = dataset.verify(out)
    assert "changed: records/waltid/augmented.jsonl" in problems
    assert any("does not re-derive" in p for p in problems)


def test_dataset_refuses_token_material(tmp_path):
    from tdid import dataset

    run = tmp_path / "run"
    jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4eXoxMjMifQ.c2lnbmF0dXJlMTIz"
    _write(run / "waltid", "stdout.log", [{"line": f"token {jwt}"}])
    with pytest.raises(dataset.DatasetError):
        dataset.pack(run, tmp_path / "ds", products=["waltid"], info={}, policy=None, fresh=False)


def test_added_collection_points_pass_tdid_events_through(tmp_path):
    from .helpers import Stream

    s = Stream()
    ev = s.event("ISSUANCE_DECISION", checks={"credential_key_proof_validation": "pass"},
                 refs={"proof_ref": "p", "output_ref": "c"}, params={"allowed_proof_uses": 1})
    _write(tmp_path, "tdid-events.jsonl", [ev])
    _write(tmp_path, "augmented.jsonl", [_added(0, "prf:x", "cred:y")])
    assert convert("credo", tmp_path) == [ev]


def test_native_credo_partial_issuance_is_a_decision(tmp_path):
    state = "existing_IssuanceSessionStateChanged"
    rows = [{"t_ns": "1", "source": state, "session_ref": "s1", "state": "CredentialsPartiallyIssued",
             "previous_state": "CredentialRequestReceived"},
            {"t_ns": "2", "source": state, "session_ref": "s1", "state": "Completed",
             "previous_state": "CredentialRequestReceived"}]
    _write(tmp_path, "sdk.jsonl", rows)
    outcomes = [e["decision"]["outcome"] for e in convert("credo", tmp_path, level="native")]
    assert outcomes == ["issue", "issue"]


def test_dataset_keeps_paths_relative_to_the_home_directory(tmp_path):
    from tdid import dataset

    run = tmp_path / "run"
    _write(run / "waltid", "augmented.jsonl", [_added(0, "prf:a", "cred:1")])
    (run / "waltid" / "stdout.log").write_text("loaded /home/alice/build/x and /Users/bob/y\n")
    out = tmp_path / "ds"
    manifest = dataset.pack(run, out, products=["waltid"], info={}, policy=POLICY, fresh=True)
    assert (out / "records/waltid/stdout.log").read_text() == "loaded build/x and y\n"
    assert manifest["path_normalization"]["rewritten_paths"] == 2
    assert dataset.verify(out) == []


def test_unreadable_raw_line_leaves_history_incomplete(tmp_path):
    _write(tmp_path, "augmented.jsonl", [_added(0, "prf:a", "cred:1"), _added(1, "prf:b", "cred:2")])
    with (tmp_path / "augmented.jsonl").open("a") as handle:
        handle.write('{"cut in half\n')
    collected = collect("waltid", tmp_path, policy=POLICY, fresh=True)
    assert collected.unreadable_lines == 1
    assert all("stream_start" not in ev["producer"] for ev in collected.events)
    assert _verdicts(collected.events)[0] == Verdict.INCOMPLETE


def _vp_run(folder, name, action="accepted", code_generated=False, controller="ctl-a"):
    run = folder / name
    run.mkdir(parents=True)
    product = {"response_mode": "direct_post", "request_transaction": f"tx-{name}",
               "result_transaction": f"tx-{name}", "sdk_record": {"authorizationRequestJwt": f"req-{name}"}}
    application = {"sessions": [{"id": f"s-{name}", "controller": controller}],
                   "relay_capture": {"source_context": controller}}
    (run / "native.json").write_text(json.dumps({"product": product, "application": application}))
    stages = [
        {"sequence": 2, "stage_id": "request_initiated", "facts": {"initiating_context_ref": controller}},
        {"sequence": 3, "stage_id": "delivery_observed", "facts": {"request_delivery_path": "relayed"}},
        {"sequence": 5, "stage_id": "wallet_submitted", "facts": {"submission_accepted": True}},
        {"sequence": 8, "stage_id": "result_returned", "facts": {"final_session_state": "ResponseVerified",
                                                                 "proof_validated": True, "query_validated": True}},
        {"sequence": 11, "stage_id": "result_consumed", "facts": {"completion_value_generated": code_generated,
                                                                  "completion_value_supplied": code_generated,
                                                                  "completion_value_matches": code_generated}},
        {"sequence": 12, "stage_id": "relying_decision", "facts": {"relying_action": action}},
    ]
    binding = {"result_session_ref": f"s-{name}", "consumer_session_ref": f"s-{name}",
               "request_source_ref": f"req-{name}", "request_wallet_ref": f"req-{name}",
               "result_transaction_ref": f"tx-{name}"}
    (run / "augmented.json").write_text(json.dumps({"stage_events": stages, "binding_evidence": binding}))


def _vp_verdicts(events):
    from tdid.engine import replay_order, workflow_summary
    result = Engine().run(replay_order(enumerate(events, start=1)))
    assert not result.rejections, result.rejections
    return {w["workflow_ref"]: w for w in workflow_summary(result.findings) if w["threat_id"] == "TDID-THR-019"}


def test_credo_vp_relying_decisions(tmp_path):
    _vp_run(tmp_path, "a", "accepted")
    _vp_run(tmp_path, "b", "rejected")
    _vp_run(tmp_path, "c", "accepted", code_generated=True)
    rows = _vp_verdicts(convert("credo-vp", tmp_path, level="added", fresh=True))
    # accepted without a Response Code: only the context and the blind initiator condition stay unknown
    assert rows["vp-transaction:tx-a"]["verdict"] == "incomplete"
    assert rows["vp-transaction:tx-a"]["unknown_conditions"] == ["CompletingContextDiffers",
                                                                 "InitiatorIsNotWalletUser"]
    assert rows["vp-transaction:tx-b"]["verdict"] == "not_succeeded"
    assert rows["vp-transaction:tx-c"]["verdict"] == "not_succeeded"   # Response Code binding upheld
    native = _vp_verdicts(convert("credo-vp", tmp_path, level="native", fresh=True))
    assert {w["verdict"] for w in native.values()} == {"incomplete"}


def test_credo_vp_never_reads_application_bookkeeping(tmp_path):
    _vp_run(tmp_path / "x", "a", controller="ctl-a")
    _vp_run(tmp_path / "y", "a", controller="ctl-zzz")
    assert convert("credo-vp", tmp_path / "x") == convert("credo-vp", tmp_path / "y")
