from tdid.engine import Engine, final_findings, workflow_summary
from tdid.model import Verdict

from .helpers import Stream

T = "TDID-THR-001"


def mine(eng):
    return [f for f in eng.result.findings if f.threat_id == T]


def run(events):
    eng = Engine()
    for i, ev in enumerate(events):
        eng.feed(ev, i)
    assert not eng.result.rejections, eng.result.rejections
    return [f.verdict for f in mine(eng)], eng


def bind(s, did, rel, *, pairwise=True, svc_ok=False, holder="holder-1", wf="wf-1"):
    params = {}
    if pairwise is not None:
        params["pairwise_separation_required"] = pairwise
    if svc_ok is not None:
        params["pairwise_shared_service_permitted"] = svc_ok
    refs = {"did_ref": did, "relationship_ref": rel}
    if holder:
        refs["holder_ref"] = holder
    return s.event("PAIRWISE_CONTEXT_BOUND", workflow=wf, outcome="none", refs=refs, params=params or None)


def resolve(s, did, vm=None, svc=None, *, wf="wf-1", **extra):
    refs = {"did_ref": did}
    if vm:
        refs["verification_material_ref"] = vm
    if svc:
        refs["service_material_ref"] = svc
    return s.event("RESOLUTION_DECISION", workflow=wf, outcome="resolve", refs=refs, **extra)


def test_same_material_across_pairwise_contexts_succeeds():
    h, r = Stream("wallet"), Stream("resolver")
    v, _ = run([bind(h, "d1", "rel-a"), bind(h, "d2", "rel-b"),
                resolve(r, "d1", "m1"), resolve(r, "d2", "m1", wf="wf-2")])
    assert v[-1] == Verdict.SUCCEEDED


def test_resolution_before_binding_is_joined_at_binding():
    h, r = Stream("wallet"), Stream("resolver")
    v, _ = run([resolve(r, "d1", "m1"), resolve(r, "d2", "m1"),
                bind(h, "d1", "rel-a"), bind(h, "d2", "rel-b")])
    assert v[-1] == Verdict.SUCCEEDED


def test_public_correlation_policy_is_not_success():
    h, r = Stream("wallet"), Stream("resolver")
    v, _ = run([bind(h, "d1", "rel-a", pairwise=False), bind(h, "d2", "rel-b", pairwise=False),
                resolve(r, "d1", "m1"), resolve(r, "d2", "m1")])
    assert v[-1] == Verdict.NOT_SUCCEEDED


def test_same_relationship_is_not_success():
    h, r = Stream("wallet"), Stream("resolver")
    v, _ = run([bind(h, "d1", "rel-a"), bind(h, "d2", "rel-a"),
                resolve(r, "d1", "m1"), resolve(r, "d2", "m1")])
    assert v[-1] == Verdict.NOT_SUCCEEDED


def test_same_did_resolved_twice_in_its_one_context_is_incomplete_not_success():
    # one context only: no second context of this holder is recorded, so nothing could match yet
    h, r = Stream("wallet"), Stream("resolver")
    v, eng = run([bind(h, "d1", "rel-a"), resolve(r, "d1", "m1"), resolve(r, "d1", "m1")])
    assert v[-1] == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["SameHolder", "DistinctRelationshipContexts", "DesignatedMaterialEqual"]


def test_one_did_bound_to_two_pairwise_relationships_succeeds():
    h, r = Stream("wallet"), Stream("resolver")
    v, _ = run([bind(h, "d1", "rel-a"), bind(h, "d1", "rel-b"), resolve(r, "d1", "m1")])
    assert v[-1] == Verdict.SUCCEEDED


def test_different_material_is_not_success():
    h, r = Stream("wallet"), Stream("resolver")
    v, _ = run([bind(h, "d1", "rel-a"), bind(h, "d2", "rel-b"),
                resolve(r, "d1", "m1", "s1"), resolve(r, "d2", "m2", "s2")])
    assert v[-2:] == [Verdict.NOT_SUCCEEDED, Verdict.NOT_SUCCEEDED]


def test_permitted_shared_service_endpoint_is_not_success():
    h, r = Stream("wallet"), Stream("resolver")
    v, _ = run([bind(h, "d1", "rel-a", svc_ok=True), bind(h, "d2", "rel-b", svc_ok=True),
                resolve(r, "d1", "m1", "s1"), resolve(r, "d2", "m2", "s1")])
    assert v[-1] == Verdict.NOT_SUCCEEDED


def test_unpermitted_shared_service_endpoint_succeeds():
    h, r = Stream("wallet"), Stream("resolver")
    v, _ = run([bind(h, "d1", "rel-a"), bind(h, "d2", "rel-b"),
                resolve(r, "d1", "m1", "s1"), resolve(r, "d2", "m2", "s1")])
    assert v[-1] == Verdict.SUCCEEDED


def test_unavailable_comparison_is_incomplete():
    h, r = Stream("wallet"), Stream("resolver")
    v, eng = run([bind(h, "d1", "rel-a"), bind(h, "d2", "rel-b"), resolve(r, "d1", "m1"),
                  resolve(r, "d2", provenance={"refs.verification_material_ref": "Unavailable"})])
    assert v[-1] == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["SameHolder", "DistinctRelationshipContexts", "DesignatedMaterialEqual"]


def test_resolver_side_only_is_incomplete():
    r = Stream("resolver")
    v, eng = run([resolve(r, "d1", "m1"), resolve(r, "d2", "m1")])
    assert v[-1] == Verdict.INCOMPLETE
    assert mine(eng)[-1].unknown == ["PairwiseSeparationRequired", "SameHolder",
                                     "DistinctRelationshipContexts"]


def test_holder_side_only_is_incomplete():
    h = Stream("wallet")
    v, eng = run([bind(h, "d1", "rel-a"), bind(h, "d2", "rel-b")])
    assert v == [Verdict.INCOMPLETE, Verdict.INCOMPLETE]
    assert "DesignatedMaterialEqual" in mine(eng)[-1].unknown


def test_missing_did_ref_is_incomplete():
    r = Stream("resolver")
    v, _ = run([r.event("RESOLUTION_DECISION", outcome="resolve", refs={"verification_material_ref": "m1"})])
    assert v == [Verdict.INCOMPLETE]


def test_history_gap_withholds_different_material_but_keeps_found_equality():
    h, r = Stream("wallet"), Stream("resolver")
    a, b = bind(h, "d1", "rel-a"), bind(h, "d2", "rel-b")
    c = resolve(r, "d1", "m1")
    r.seq += 2  # resolver records lost
    d = resolve(r, "d2", "m2")
    e = resolve(r, "d3", "m1")
    f = bind(h, "d3", "rel-c")
    v, eng = run([a, b, c, d, e, f])
    assert v[3] == Verdict.INCOMPLETE and mine(eng)[3].unknown == [
        "SameHolder", "DistinctRelationshipContexts", "DesignatedMaterialEqual"]
    assert v[-1] == Verdict.SUCCEEDED


def test_workflow_summary():
    h, r = Stream("wallet"), Stream("resolver")
    _, eng = run([bind(h, "d1", "rel-a", wf="bind-a"), bind(h, "d2", "rel-b", wf="bind-b"),
                  resolve(r, "d1", "m1", wf="res-a"), resolve(r, "d2", "m1", wf="res-b")])
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows["res-b"] == "succeeded"


def test_binding_supersedes_resolver_side_only_verdict_for_both_dids():
    # the later binding of d2 links it to d1: d1 is judged again and its final verdict is a success too
    h, r = Stream("wallet"), Stream("resolver")
    _, eng = run([bind(h, "d1", "rel-a"), resolve(r, "d1", "m1"),
                  resolve(r, "d2", "m1"), bind(h, "d2", "rel-b")])
    final = {f.subject: f.verdict for f in final_findings(mine(eng))}
    assert final == {"did:d1": Verdict.SUCCEEDED, "did:d2": Verdict.SUCCEEDED}


# ---- regression tests for the review of 2026-10-20 ------------------------------------------------

def test_different_holders_sharing_a_mediator_endpoint_are_not_success():
    # one cloud agent instance, two users, both DIDs list the same mediator endpoint
    h, r = Stream("wallet"), Stream("resolver")
    _, eng = run([bind(h, "d1", "rel-a", holder="alice"), bind(h, "d2", "rel-b", holder="bob"),
                  resolve(r, "d1", "m1", "s-mediator"), resolve(r, "d2", "m2", "s-mediator")])
    final = final_findings(mine(eng))
    assert final and all(f.verdict != Verdict.SUCCEEDED for f in final)


def test_holder_identity_not_recorded_is_incomplete():
    h, r = Stream("wallet"), Stream("resolver")
    v, eng = run([bind(h, "d1", "rel-a", holder=None), bind(h, "d2", "rel-b", holder=None),
                  resolve(r, "d1", "m1"), resolve(r, "d2", "m1")])
    assert v[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["SameHolder"]


def test_holder_refs_from_different_wallets_are_not_compared():
    h1, h2, r = Stream("wallet"), Stream("wallet"), Stream("resolver")
    v, eng = run([bind(h1, "d1", "rel-a"), bind(h2, "d2", "rel-b"),
                  resolve(r, "d1", "m1"), resolve(r, "d2", "m1")])
    assert v[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["SameHolder"]


def test_first_did_is_not_final_negative_before_its_pair_arrives():
    h, r = Stream("wallet"), Stream("resolver")
    v, eng = run([bind(h, "d1", "rel-a", wf="wf-a"), resolve(r, "d1", "m1", wf="wf-a")])
    assert v[-1] == Verdict.INCOMPLETE  # no second context recorded: nothing could match yet
    _, eng = run([bind(h, "d1", "rel-a", wf="wf-a"), resolve(r, "d1", "m1", wf="wf-a"),
                  bind(h, "d2", "rel-b", wf="wf-b"), resolve(r, "d2", "m1", wf="wf-b")])
    final = {f.subject: (f.verdict, f.workflow_ref) for f in final_findings(mine(eng))}
    assert final == {"did:d1": (Verdict.SUCCEEDED, "wf-a"), "did:d2": (Verdict.SUCCEEDED, "wf-b")}
    rows = {x["workflow_ref"]: x["verdict"] for x in workflow_summary(mine(eng))}
    assert rows == {"wf-a": "succeeded", "wf-b": "succeeded"}


def test_earlier_negative_is_rejudged_when_a_later_context_matches():
    h, r = Stream("wallet"), Stream("resolver")
    _, eng = run([bind(h, "d1", "rel-a"), bind(h, "d2", "rel-b"),
                  resolve(r, "d1", "m1"), resolve(r, "d2", "m2"),
                  bind(h, "d3", "rel-c", wf="wf-3"), resolve(r, "d3", "m1", wf="wf-3")])
    final = {f.subject: f.verdict for f in final_findings(mine(eng))}
    assert final == {"did:d1": Verdict.SUCCEEDED, "did:d2": Verdict.NOT_SUCCEEDED,
                     "did:d3": Verdict.SUCCEEDED}


def test_unset_separation_policy_is_incomplete():
    h, r = Stream("wallet"), Stream("resolver")
    v, eng = run([bind(h, "d1", "rel-a", pairwise=None), bind(h, "d2", "rel-b", pairwise=None),
                  resolve(r, "d1", "m1"), resolve(r, "d2", "m1")])
    assert v[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["PairwiseSeparationRequired"]


def test_unset_service_sharing_policy_is_incomplete():
    h, r = Stream("wallet"), Stream("resolver")
    v, eng = run([bind(h, "d1", "rel-a", svc_ok=None), bind(h, "d2", "rel-b", svc_ok=None),
                  resolve(r, "d1", "m1", "s1"), resolve(r, "d2", "m2", "s1")])
    assert v[-1] == Verdict.INCOMPLETE and mine(eng)[-1].unknown == ["DesignatedMaterialEqual"]


def test_wallet_history_started_before_collection_withholds_different_material():
    h, r = Stream("wallet", fresh=False), Stream("resolver")
    v, eng = run([bind(h, "d1", "rel-a"), bind(h, "d2", "rel-b"),
                  resolve(r, "d1", "m1"), resolve(r, "d2", "m2")])
    assert v[-1] == Verdict.INCOMPLETE and "DesignatedMaterialEqual" in mine(eng)[-1].unknown
