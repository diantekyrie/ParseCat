"""Device-wide crash/wifi evidence walks for verified_facts."""
from __future__ import annotations

from app.services.citations_core import (
    _block_confidence,
    _fact,
)


def _collect_crash_wifi_facts(bundle: dict) -> list[dict]:
    """Flatten crash + wifi device-wide evidence."""
    facts: list[dict] = []

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

    return facts
