"""TDID-THR-009 Resolver denial of service through attacker-requested cache bypass.

Success (OBS-GAP THR-009 success_predicate; CH6-THR-009 reaffirms the same definition): within one rate
window, an untrusted requester bucket has noCache requests admitted that actually bypass an enabled cache,
more of them than the policy rate allows, their uncached upstream work reaches the work threshold, the
resolver's availability objective is broken, and that bucket's bypass work is at least the policy share of
all upstream work in the window.

The source checks cache_bypass_rate_threshold and cache_bypass_degradation_attribution are conclusions; here
they are computed from per-request facts kept in history (admission, cache state, upstream request count) and
the resolver's total upstream work in the window. Availability is the shared check resolver_availability_slo
(the same check THR-004 reads), which the source predicate names directly: on a RESOLUTION_DECISION it is the
resolver's comparison of its trailing-window latency, error and denial rates with its configured objective,
so the measurement already covers the bypasses before this decision. Raw latency or error numbers and
author-chosen objectives are not used. Authorization of noCache is a separate obligation and only noted.

The share condition is T-DID's operational detection criterion (decision 2026-10-20), not a causal proof;
the paper reports it as a threshold criterion with a sensitivity analysis.
Every threshold (rate window, rate, work, attribution share) is the deployment's policy; an unset parameter
leaves the dependent condition unknown.

Not success (negative controls, OBS-GAP THR-009): rejected bypass; authorized maintenance or test use;
globally disabled cache; one or below-rate admitted bypass; admitted bypass below the work threshold;
degradation attributable to unrelated load. Unknown when the requester bucket, class, availability check or a
policy parameter is missing; with a gap in the resolver's history (including history that began before
collection), counts are lower bounds, so only crossing a threshold is established.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, param, ref
from tdid.state import Delta, View

NS = "thr009"
_NEEDED = ("admission", "cache_enabled", "bypassed", "upstream")


def _ts(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _at_least(value: float, bound: float | None, exact: bool, strict: bool = False) -> Tri:
    """value is a lower bound unless exact; an unset bound leaves the comparison unknown."""
    if bound is None:
        return None
    hit = value > bound if strict else value >= bound
    if hit:
        return True
    return False if exact else None


class Thr009(Rule):
    threat_id = "TDID-THR-009"
    title = "Resolver denial of service through attacker-requested cache bypass"
    locality = "local"
    triggers = frozenset({"RESOLUTION_DECISION"})
    conditions = (
        "UntrustedRequester",
        "NoCacheAdmitted",
        "CacheBypassApplied",
        "BypassRateExceeded",
        "UncachedWorkThreshold",
        "ServiceDegraded",
        "BypassShareAtPolicyThreshold",
    )
    limits = (
        'BypassShareAtPolicyThreshold is a deployment-threshold criterion (attributed_work_share_min), '
        'not a causal proof; unset thresholds -> unknown.'
    )

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation:
        facts = ev.get("facts") or {}
        stream = ev["producer"]["instance"]
        now = _ts(ev["occurred_at"])
        window_param = param(ev, "rate_window_seconds", None)
        window = None if window_param is None else float(window_param)
        bucket = ref(ev, "requester_scoped_ref")

        record = {
            "t": now, "bucket": bucket, "event_id": ev["event_id"],
            "admission": facts.get("no_cache_admission"),
            "cache_enabled": facts.get("cache_enabled"),
            "bypassed": facts.get("cache_bypassed"),
            "upstream": facts.get("upstream_requests"),
        }
        stored = view.get(NS, stream, [])
        # Without a window nothing else can be counted with this request.
        history = ([r for r in stored if r["t"] > now - window] if window is not None else []) + [record]

        cls = facts.get("requester_scope_class")
        untrusted = None if cls is None else cls == "untrusted"

        if bucket is None:
            admitted = applied = rate = work = attributed = None
            evidence: tuple[str, ...] = (ev["event_id"],)
        else:
            mine = [r for r in history if r["bucket"] == bucket]
            exact = (window is not None and view.stream_complete(stream)
                     and all(r[k] is not None for r in mine for k in _NEEDED))
            adm = [r for r in mine if r["admission"] == "admitted"]
            app = [r for r in adm if r["cache_enabled"] is True and r["bypassed"] is True]
            bypass_work = sum(r["upstream"] or 0 for r in app)
            admitted = _at_least(len(adm), 1, exact)
            applied = _at_least(len(app), 1, exact)
            rate = _at_least(len(app), param(ev, "max_bypass_requests_per_window", None), exact, strict=True)
            work = _at_least(bypass_work, param(ev, "bypass_work_threshold", None), exact)
            total = facts.get("window_upstream_requests")
            if not total:
                attributed = None
            else:
                share_min = param(ev, "attributed_work_share_min", None)
                attributed = _at_least(bypass_work / total, share_min, exact)
            prior = tuple(r["event_id"] for r in app if r["event_id"] != ev["event_id"])
            evidence = prior + (ev["event_id"],)

        slo = ev["checks"]["results"].get("resolver_availability_slo")
        degraded: Tri = True if slo == "fail" else (False if slo == "pass" else None)

        predicates = {
            "UntrustedRequester": untrusted,
            "NoCacheAdmitted": admitted,
            "CacheBypassApplied": applied,
            "BypassRateExceeded": rate,
            "UncachedWorkThreshold": work,
            "ServiceDegraded": degraded,
            "BypassShareAtPolicyThreshold": attributed,
        }
        notes: list[str] = []
        authz = ev["checks"]["results"].get("no_cache_authorization")
        if record["admission"] == "admitted" and authz == "fail":
            notes.append("noCache admitted although the requester is not authorized for it "
                         "(obligation violation, not threat success)")

        kept = [r for r in history if r["t"] > now - window] if window is not None else stored + [record]
        return Evaluation(predicates, evidence, (Delta(NS, stream, kept),), tuple(notes))


RULE = Thr009()
