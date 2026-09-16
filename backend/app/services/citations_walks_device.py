"""Device-wide evidence walks for verified_facts collection."""
from __future__ import annotations

from app.services.citations_walks_crash_wifi import _collect_crash_wifi_facts
from app.services.citations_walks_other import _collect_other_device_facts


def _collect_device_wide_facts(bundle: dict) -> list[dict]:
    """Flatten all device-wide evidence blocks (+ optional scan findings)."""
    facts: list[dict] = []
    facts.extend(_collect_crash_wifi_facts(bundle))
    facts.extend(_collect_other_device_facts(bundle))
    return facts
