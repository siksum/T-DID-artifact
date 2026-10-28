"""TDID-THR-004 Resolver cache exhaustion through logically equivalent DID URL variants.

Success (CAND-20260908-CH6-THR-004-REAFFIRMED, discriminating_predicate, with the attribution requirement of
the OBS-GAP THR-004 row): within a preregistered window, requests for one canonical DID URL identity allocate
more distinct cache entries than the policy allows, a health measurement in that window shows the resource
threshold exceeded and the availability objective missed, and the degradation is attributed to those
allocations. canonical_identity_count == 1 AND distinct_cache_key_count > limit AND resource_pressure >=
threshold AND availability == degraded AND attribution.

The OBS-GAP row expressed attribution as a producer verdict (variant_allocation_degradation_attribution); that
concludes the attack, so here it is computed: the identity's distinct allocations in the window divided by the
cache entry count reported at the failing measurement must reach attribution_min_share. This is T-DID's
operational detection criterion (decision 2026-10-20): a deployment threshold on an observable share, as in
rate- and share-based DoS detection. It is not a causal proof that the variants caused the degradation; the
paper reports it as a threshold criterion with a sensitivity analysis. Unset share -> unknown.

Canonical identity is did_url_ref, which the resolver must compute under the policy's versioned
canonicalization profile independently of the cache-key construction.

Pairing: a health measurement can only show the effect of allocations made before it, so it is paired only
with the allocations in the window ending at the measurement; excess is always counted in that window. A
request is never paired with a measurement taken before it: its finding is provisional (health conditions
unknown, subject request:<event_id>) unless a measurement taken at or after it within the window is already
known. The first measurement inside a provisional request's window settles it (same subject); a request whose
window closes with no measurement in it keeps its incomplete verdict, because no measurement taken later can
show the state of that window. Each measurement also judges every identity with allocations in its window
that no open request covers (subject identity:<did_url_ref>:<measurement event_id>).

Not success (negative controls, OBS-GAP THR-004): variants collapsed to one entry; high legitimate cardinality
across distinct identities; no measured degradation (or degradation not attributable to the variant entries).
Unknown: limits or window not preregistered, missing cache facts, no health measurement after the
allocations, unavailable health checks, or an incomplete history when the limit is not reached.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from tdid.model import Tri
from tdid.rules.base import Evaluation, Rule, param, ref
from tdid.state import Delta, View

NS = "thr004"

def _at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _exceeded(ev: dict[str, Any], name: str) -> Tri:
    """For threshold checks: fail -> exceeded (True); pass -> False; anything else -> unknown."""
    value = ev["checks"]["results"].get(name)
    return True if value == "fail" else (False if value == "pass" else None)


class Thr004(Rule):
    threat_id = "TDID-THR-004"
    title = "Resolver cache exhaustion through logically equivalent DID URL variants"
    locality = "local"
    triggers = frozenset({"RESOLUTION_DECISION", "RESOLVER_HEALTH_MEASURED"})
    conditions = (
        "ExcessDistinctAllocations",
        "ResourceThresholdExceeded",
        "AvailabilityDegraded",
        "VariantShareAtPolicyThreshold",
    )
    limits = (
        'VariantShareAtPolicyThreshold is a deployment-threshold criterion (attribution_min_share), not a '
        'causal proof that the variants caused the degradation; unset threshold -> unknown.'
    )

    def evaluate(self, ev: dict[str, Any], view: View) -> Evaluation | list[Evaluation]:
        book = view.get(NS, "book", {"alloc": {}, "uncertain": [], "health": [], "streams": [], "open": []})
        stream = ev["producer"]["instance"]
        if stream not in book["streams"]:
            book["streams"].append(stream)
        now = _at(ev["occurred_at"])
        limit = param(ev, "variant_allocation_limit", None)
        window_s = param(ev, "variant_window_seconds", None)
        share_min = param(ev, "attribution_min_share", None)
        # a non-positive window is not a usable policy: treat it as unset (unknown), never as empty
        window = timedelta(seconds=window_s) if isinstance(window_s, int | float) and window_s > 0 else None
        complete = all(view.stream_complete(s) for s in book["streams"])

        if ev["event_type"] == "RESOLUTION_DECISION":
            identity = ref(ev, "did_url_ref")
            key = ref(ev, "cache_key_ref")
            allocation = (ev.get("facts") or {}).get("cache_allocation")
            if identity and allocation == "allocated" and key:
                entry = {"at": ev["occurred_at"], "key": key,
                         "workflow": ev["workflow_ref"], "event": ev["event_id"]}
                book["alloc"].setdefault(identity, []).append(entry)
            elif identity and allocation in (None, "allocated") and identity not in book["uncertain"]:
                book["uncertain"].append(identity)
            # Only a measurement taken at or after this request can show its effect; a lost record could
            # hold such a measurement, so an incomplete history withholds it.
            health = self._health_after(book, now, window) if complete else None
            at = _at(health["at"]) if health else now
            predicates, events = self._judge(book, identity, at, window, limit, share_min, health, complete)
            # Without a later measurement the finding is provisional: the first measurement inside this
            # request's window supersedes it (same subject), so a later "no degradation" settles it.
            subject = None
            if identity and health is None:
                subject = f"request:{ev['event_id']}"
                book["open"].append({"identity": identity, "at": ev["occurred_at"], "event": ev["event_id"],
                                     "workflow": ev["workflow_ref"]})
            return Evaluation(predicates, tuple(events) + (ev["event_id"],), (Delta(NS, "book", book),),
                              subject=subject)

        measurement = {"at": ev["occurred_at"], "event": ev["event_id"],
                       "resource": _exceeded(ev, "resolver_resource_threshold"),
                       "slo": _exceeded(ev, "resolver_availability_slo"),
                       "entries": (ev.get("facts") or {}).get("cache_entry_count")}
        book["health"] = (book["health"] + [measurement])[-16:]
        covered: list[dict[str, Any]] = []
        if window is not None:
            still_open = []
            for request in book["open"]:
                taken = _at(request["at"])
                if now - window <= taken <= now:
                    covered.append(request)      # this measurement lies in the request's window
                elif taken > now:
                    still_open.append(request)   # measurement predates the request: not paired
                # else: the request's window closed with no measurement in it; it stays incomplete
            book["open"] = still_open
        out: list[Evaluation] = []
        for request in covered:
            predicates, events = self._judge(book, request["identity"], now, window, limit, share_min,
                                             measurement, complete)
            out.append(Evaluation(predicates, tuple(events) + (request["event"], ev["event_id"]),
                                  notes=("measurement inside this request's window",),
                                  subject=f"request:{request['event']}", workflow_ref=request["workflow"]))
        settled = {r["identity"] for r in covered}
        others = [i for i in book["alloc"] if i not in settled and self._keys(book, i, now, window)] \
            if window is not None else []
        for identity in sorted(others):
            predicates, events = self._judge(book, identity, now, window, limit, share_min, measurement,
                                             complete)
            allocations = book["alloc"][identity]
            workflow = max(allocations, key=lambda a: _at(a["at"]))["workflow"]
            out.append(Evaluation(predicates, tuple(events) + (ev["event_id"],),
                                  notes=("measurement joined to this identity's allocations in its window",),
                                  subject=f"identity:{identity}:{ev['event_id']}", workflow_ref=workflow))
        if not out:
            predicates, events = self._judge(book, None, now, window, limit, share_min, measurement, complete)
            if window is not None:
                # no allocation in the window at all
                predicates["ExcessDistinctAllocations"] = False if complete else None
            return Evaluation(predicates, tuple(events) + (ev["event_id"],), (Delta(NS, "book", book),))
        first = out[0]
        out[0] = Evaluation(first.predicates, first.evidence_event_ids, (Delta(NS, "book", book),),
                            first.notes, subject=first.subject, workflow_ref=first.workflow_ref)
        return out

    @staticmethod
    def _keys(book: dict[str, Any], identity: str, now: datetime, window: timedelta) -> dict[str, str]:
        keys: dict[str, str] = {}
        for a in book["alloc"].get(identity, []):
            if now - window <= _at(a["at"]) <= now:
                keys.setdefault(a["key"], a["event"])
        return keys

    @staticmethod
    def _health_after(book: dict[str, Any], now: datetime,
                      window: timedelta | None) -> dict[str, Any] | None:
        """Earliest known measurement taken at or after this request and within its window."""
        if window is None:
            return None
        after = [h for h in book["health"] if now <= _at(h["at"]) <= now + window]
        return min(after, key=lambda h: _at(h["at"])) if after else None

    def _judge(self, book: dict[str, Any], identity: str | None, now: datetime, window: timedelta | None,
               limit: int | None, share_min: float | None, health: dict[str, Any] | None,
               complete: bool) -> tuple[dict[str, Tri], list[str]]:
        events: list[str] = []
        count: int | None = None
        if identity is None or window is None:
            excess: Tri = None
        else:
            keys = self._keys(book, identity, now, window)
            events.extend(keys.values())
            count = len(keys)
            if limit is None:
                excess = None
            elif count > limit:
                excess = True
            else:
                excess = False if complete and identity not in book["uncertain"] else None

        if health is None:
            resource: Tri = None
            slo: Tri = None
            attributed: Tri = None
        else:
            events.append(health["event"])
            resource, slo = health["resource"], health["slo"]
            entries = health["entries"]
            if share_min is None or count is None or not entries:
                attributed = None
            else:
                attributed = count / entries >= share_min
        return {
            "ExcessDistinctAllocations": excess,
            "ResourceThresholdExceeded": resource,
            "AvailabilityDegraded": slo,
            "VariantShareAtPolicyThreshold": attributed,
        }, events


RULE = Thr004()
