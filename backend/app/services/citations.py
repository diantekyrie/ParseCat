"""Citation-ready verified facts for the Diagnose/Scan Verified-from-log band.

Parsers are ground truth; LLM narration may only restate these facts. This
module flattens already-assembled evidence into a stable UI/API shape with
SourceRef (section + line range) and code-owned confidence labels. It never
invents prose, confidence, or causal claims.
"""
from __future__ import annotations

from typing import Any

_CONFIDENCE_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNCONFIRMED": 3}
VALID_CONFIDENCE = frozenset(_CONFIDENCE_RANK)


def code_owned_confidence(raw: Any) -> str:
    """UI/API confidence chips come only from code -- never from the model.

    Missing or unexpected values become UNCONFIRMED rather than looking
    confident by accident.
    """
    if isinstance(raw, str) and raw in VALID_CONFIDENCE:
        return raw
    return "UNCONFIRMED"


def _source_ref(raw: Any) -> dict | None:
    if not isinstance(raw, dict):
        return None
    section = raw.get("section")
    line_start = raw.get("line_start")
    line_end = raw.get("line_end")
    if not section or not isinstance(line_start, int) or line_start < 1:
        return None
    if not isinstance(line_end, int) or line_end < line_start:
        line_end = line_start
    return {"section": section, "line_start": line_start, "line_end": line_end}


def _fact(
    *,
    category: str,
    summary: str,
    confidence: Any,
    source: Any = None,
    timestamp: str | None = None,
    capture_id: int | None = None,
    original_filename: str | None = None,
    detail: str | None = None,
) -> dict:
    return {
        "category": category,
        "summary": summary,
        "detail": detail,
        "confidence": code_owned_confidence(confidence),
        "source": _source_ref(source),
        "timestamp": timestamp,
        "capture_id": capture_id,
        "original_filename": original_filename,
    }


def _block_confidence(block: dict | None) -> Any:
    if not isinstance(block, dict):
        return None
    return block.get("confidence")


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
            for fact in collect_verified_facts(cap):
                if device_label and not fact.get("original_filename"):
                    fact = {**fact, "device_label": device_label}
                elif device_label:
                    fact = {**fact, "device_label": device_label}
                out.append(fact)
        return out

    facts: list[dict] = []

    for claim in bundle.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        pkg = claim.get("package") or "unknown package"
        claim_conf = claim.get("confidence")
        facts.append(_fact(
            category="entity",
            summary=f"Independently verified package {pkg}",
            confidence=claim_conf,
            detail=claim.get("corroboration") or claim.get("matched_how"),
        ))
        vs = claim.get("verified_state") or {}
        for c in vs.get("crash_events") or []:
            if not isinstance(c, dict):
                continue
            facts.append(_fact(
                category="crash",
                summary=(
                    f"Java crash in {c.get('package') or pkg}: "
                    f"{c.get('exception_class') or 'exception'}"
                ),
                confidence=claim_conf,
                source=c.get("source"),
                timestamp=c.get("timestamp"),
                detail=c.get("message") or c.get("root_cause_message"),
            ))
        for a in vs.get("anrs") or []:
            if not isinstance(a, dict):
                continue
            facts.append(_fact(
                category="anr",
                summary=f"ANR in {a.get('package') or pkg}",
                confidence=claim_conf,
                source=a.get("source"),
                timestamp=a.get("timestamp"),
                detail=a.get("reason"),
            ))
        for t in vs.get("native_crashes") or []:
            if not isinstance(t, dict):
                continue
            who = t.get("package") or t.get("executable") or pkg
            facts.append(_fact(
                category="native_crash",
                summary=f"Native crash in {who}",
                confidence=claim_conf,
                source=t.get("source"),
                timestamp=t.get("timestamp"),
                detail=t.get("signal_name"),
            ))

    crash = bundle.get("device_wide_crash_evidence") or {}
    crash_conf = _block_confidence(crash)
    for c in crash.get("java_crashes") or []:
        if not isinstance(c, dict):
            continue
        facts.append(_fact(
            category="crash",
            summary=(
                f"Java crash in {c.get('package') or 'unknown package'}: "
                f"{c.get('exception_class') or 'exception'}"
            ),
            confidence=c.get("confidence", crash_conf),
            source=c.get("source"),
            timestamp=c.get("timestamp"),
            capture_id=c.get("capture_id"),
            original_filename=c.get("original_filename"),
            detail=c.get("message") or c.get("root_cause_message"),
        ))
    for t in crash.get("native_crashes") or []:
        if not isinstance(t, dict):
            continue
        who = t.get("package") or t.get("executable") or "unattributed process"
        facts.append(_fact(
            category="native_crash",
            summary=f"Native crash in {who}",
            confidence=t.get("confidence", crash_conf),
            source=t.get("source"),
            timestamp=t.get("timestamp"),
            capture_id=t.get("capture_id"),
            original_filename=t.get("original_filename"),
            detail=t.get("signal_name"),
        ))
    for a in crash.get("anrs") or []:
        if not isinstance(a, dict):
            continue
        facts.append(_fact(
            category="anr",
            summary=f"ANR in {a.get('package') or 'unknown package'}",
            confidence=a.get("confidence", crash_conf),
            source=a.get("source"),
            timestamp=a.get("timestamp"),
            capture_id=a.get("capture_id"),
            original_filename=a.get("original_filename"),
            detail=a.get("reason"),
        ))

    wifi = bundle.get("device_wide_wifi_evidence") or {}
    wifi_conf = _block_confidence(wifi)
    for w in wifi.get("disconnections") or []:
        if not isinstance(w, dict):
            continue
        reason = w.get("reason_name") or w.get("reason_code") or "unspecified reason"
        facts.append(_fact(
            category="wifi",
            summary=f"Wi-Fi disconnection ({reason})",
            confidence=w.get("confidence", wifi_conf),
            source=w.get("source"),
            timestamp=w.get("timestamp"),
            capture_id=w.get("capture_id"),
            original_filename=w.get("original_filename"),
            detail=(
                "locally generated" if w.get("locally_generated") is True
                else "not locally generated" if w.get("locally_generated") is False
                else None
            ),
        ))

    battery = bundle.get("device_wide_battery_evidence") or {}
    battery_conf = _block_confidence(battery)
    for b in battery.get("top_consumers") or []:
        if not isinstance(b, dict):
            continue
        who = b.get("package") or b.get("uid_token") or "unknown UID"
        mah = b.get("total_mah")
        mah_bit = f"{mah} mAh" if mah is not None else "mAh unknown"
        facts.append(_fact(
            category="battery",
            summary=f"Battery consumer {who}: {mah_bit}",
            confidence=b.get("confidence", battery_conf),
            source=b.get("source"),
            capture_id=b.get("capture_id"),
            original_filename=b.get("original_filename"),
        ))

    memory = bundle.get("device_wide_memory_evidence") or {}
    memory_conf = _block_confidence(memory)
    for k in memory.get("kills") or memory.get("events") or []:
        if not isinstance(k, dict):
            continue
        who = k.get("process") or k.get("package") or "unknown process"
        facts.append(_fact(
            category="memory",
            summary=f"Process kill: {who}",
            confidence=k.get("confidence", memory_conf),
            source=k.get("source"),
            timestamp=k.get("timestamp"),
            capture_id=k.get("capture_id"),
            original_filename=k.get("original_filename"),
            detail=k.get("reason"),
        ))

    selinux = bundle.get("device_wide_selinux_evidence") or {}
    selinux_conf = _block_confidence(selinux)
    for d in selinux.get("denials") or []:
        if not isinstance(d, dict):
            continue
        perms = d.get("permissions") or "?"
        who = d.get("app") or d.get("comm") or d.get("source_domain") or "unknown"
        facts.append(_fact(
            category="selinux",
            summary=f"SELinux denial {{{perms}}} for {who}",
            confidence=d.get("confidence", selinux_conf),
            source=d.get("source"),
            timestamp=d.get("timestamp"),
            capture_id=d.get("capture_id"),
            original_filename=d.get("original_filename"),
            detail=f"{d.get('source_domain')} -> {d.get('target_type')}",
        ))

    pairing = bundle.get("device_wide_pairing_evidence") or {}
    pairing_conf = _block_confidence(pairing)
    for e in pairing.get("events") or []:
        if not isinstance(e, dict):
            continue
        facts.append(_fact(
            category="pairing",
            summary=f"Pairing/CDM event: {e.get('kind') or e.get('tag') or 'event'}",
            confidence=e.get("confidence", pairing_conf),
            source=e.get("source"),
            timestamp=e.get("timestamp"),
            capture_id=e.get("capture_id"),
            original_filename=e.get("original_filename"),
            detail=_truncate_for_fact(e.get("detail")),
        ))
    for a in pairing.get("current_associations") or []:
        if not isinstance(a, dict):
            continue
        name = a.get("display_name") or a.get("mac_address") or "association"
        facts.append(_fact(
            category="pairing",
            summary=f"CDM association present: {name}",
            confidence=a.get("confidence", pairing_conf),
            source=a.get("source"),
            capture_id=a.get("capture_id"),
            original_filename=a.get("original_filename"),
            detail=(
                f"connected={a.get('currently_connected')}, "
                f"package={a.get('package_name')}"
            ),
        ))

    # Scan path: ranked_findings are already code-owned severity+confidence.
    # Include any that are not already represented by the walks above only
    # when the bundle is a scan -- for diagnose, evidence walks are enough.
    if bundle.get("scan") and bundle.get("ranked_findings"):
        existing = {(f.get("summary"), f.get("timestamp"), f.get("category")) for f in facts}
        for rf in bundle["ranked_findings"]:
            if not isinstance(rf, dict):
                continue
            key = (rf.get("title"), rf.get("timestamp"), rf.get("category"))
            if key in existing:
                continue
            facts.append(_fact(
                category=rf.get("category") or "finding",
                summary=rf.get("title") or "Finding",
                confidence=rf.get("confidence"),
                source=rf.get("source"),
                timestamp=rf.get("timestamp") or rf.get("first_timestamp"),
                capture_id=rf.get("capture_id"),
                original_filename=rf.get("original_filename"),
                detail=rf.get("detail"),
            ))

    return facts


def _truncate_for_fact(detail: Any, limit: int = 240) -> str | None:
    if detail is None:
        return None
    text = str(detail)
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def answer_confidence_from_facts(facts: list[dict]) -> str:
    """Highest code-owned confidence among facts; empty => UNCONFIRMED."""
    if not facts:
        return "UNCONFIRMED"
    best = min(
        (code_owned_confidence(f.get("confidence")) for f in facts),
        key=lambda c: _CONFIDENCE_RANK[c],
    )
    return best


def attach_verified_facts(bundle: dict) -> dict:
    """Mutate bundle with verified_facts / has_verified_facts / answer_confidence."""
    facts = collect_verified_facts(bundle)
    bundle["verified_facts"] = facts
    bundle["has_verified_facts"] = len(facts) > 0
    bundle["answer_confidence"] = answer_confidence_from_facts(facts)
    return bundle
