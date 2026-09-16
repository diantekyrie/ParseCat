"""Claim / investigation walks for verified_facts collection."""
from __future__ import annotations

from app.services.citations_core import _fact
from app.services.citations_walks_device import _collect_device_wide_facts
from app.services.fact_id import stamp_fact_id


def _capture_identity(event: dict | None, bundle: dict) -> tuple[int | None, str | None]:
    """Prefer event capture identity; fall back to capture/bundle fields."""
    src = event if isinstance(event, dict) else {}
    capture_id = src.get("capture_id")
    if capture_id is None:
        capture_id = bundle.get("capture_id")
    original_filename = src.get("original_filename")
    if not original_filename:
        original_filename = bundle.get("original_filename")
    return capture_id, original_filename


def collect_verified_facts(bundle: dict) -> list[dict]:
    """Flatten parser-backed evidence into citation-ready rows for the UI.

    Investigation bundles nest per-capture bundles under ``captures``; those
    are flattened here too so one Verified band can render the answer.
    """
    if not isinstance(bundle, dict):
        return []

    # Investigation-shaped: one entry per linked capture.
    if isinstance(bundle.get("captures"), list) and "claims" not in bundle:
        out: list[dict] = []
        for cap in bundle["captures"]:
            if not isinstance(cap, dict):
                continue
            device_label = cap.get("device_label")
            cap_id = cap.get("capture_id")
            cap_name = cap.get("original_filename")
            for fact in collect_verified_facts(cap):
                updates: dict = {}
                if device_label:
                    updates["device_label"] = device_label
                # Safety net when nested claim walks missed capture identity.
                if cap_id is not None and fact.get("capture_id") is None:
                    updates["capture_id"] = cap_id
                if cap_name and not fact.get("original_filename"):
                    updates["original_filename"] = cap_name
                if updates:
                    fact = stamp_fact_id({**fact, **updates})
                out.append(fact)
        return out

    facts: list[dict] = []

    for claim in bundle.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        pkg = claim.get("package") or "unknown package"
        claim_conf = claim.get("confidence")
        ent_id, ent_name = _capture_identity(claim, bundle)
        facts.append(_fact(
            category="entity",
            summary=f"Independently verified package {pkg}",
            confidence=claim_conf,
            detail=claim.get("corroboration") or claim.get("matched_how"),
            capture_id=ent_id,
            original_filename=ent_name,
        ))
        vs = claim.get("verified_state") or {}
        for c in vs.get("crash_events") or []:
            if not isinstance(c, dict):
                continue
            crash_id, crash_name = _capture_identity(c, bundle)
            facts.append(_fact(
                category="crash",
                summary=(
                    f"Java crash in {c.get('package') or pkg}: "
                    f"{c.get('exception_class') or 'exception'}"
                ),
                confidence=claim_conf,
                source=c.get("source"),
                timestamp=c.get("timestamp"),
                capture_id=crash_id,
                original_filename=crash_name,
                detail=c.get("message") or c.get("root_cause_message"),
            ))
        for a in vs.get("anrs") or []:
            if not isinstance(a, dict):
                continue
            anr_id, anr_name = _capture_identity(a, bundle)
            facts.append(_fact(
                category="anr",
                summary=f"ANR in {a.get('package') or pkg}",
                confidence=claim_conf,
                source=a.get("source"),
                timestamp=a.get("timestamp"),
                capture_id=anr_id,
                original_filename=anr_name,
                detail=a.get("reason"),
            ))
        for t in vs.get("native_crashes") or []:
            if not isinstance(t, dict):
                continue
            nat_id, nat_name = _capture_identity(t, bundle)
            who = t.get("package") or t.get("executable") or pkg
            facts.append(_fact(
                category="native_crash",
                summary=f"Native crash in {who}",
                confidence=claim_conf,
                source=t.get("source"),
                timestamp=t.get("timestamp"),
                capture_id=nat_id,
                original_filename=nat_name,
                detail=t.get("signal_name"),
            ))

    facts.extend(_collect_device_wide_facts(bundle))
    return facts
