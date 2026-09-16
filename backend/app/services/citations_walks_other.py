"""Device-wide battery/memory/selinux/pairing/scan walks for verified_facts."""
from __future__ import annotations

from app.services.citations_core import (
    _block_confidence,
    _fact,
    _truncate_for_fact,
)


def _collect_other_device_facts(bundle: dict) -> list[dict]:
    """Flatten battery/memory/selinux/pairing (+ optional scan) evidence."""
    facts: list[dict] = []

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
