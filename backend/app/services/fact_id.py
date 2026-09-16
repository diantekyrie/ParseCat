"""Stable deterministic fact_id for verified_facts (issue #49)."""
from __future__ import annotations

import hashlib
import json
from typing import Any

_FACT_ID_FIELDS = (
    "category",
    "summary",
    "detail",
    "source",
    "timestamp",
    "capture_id",
    "original_filename",
    "device_label",
)


def compute_fact_id(fact: dict) -> str:
    """Stable deterministic id: same identity fields → same id across runs.

    Uses a canonical JSON of identity-bearing fields (sorted keys, no
    whitespace) hashed with SHA-256. Prefixed ``vf_`` + 16 hex chars.
    Confidence is not part of the hash.
    """
    identity = {key: fact.get(key) for key in _FACT_ID_FIELDS}
    for key in ("category", "summary", "detail", "timestamp", "original_filename", "device_label"):
        if identity.get(key) is None:
            identity[key] = ""
    blob = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    return f"vf_{digest}"


def stamp_fact_id(fact: dict) -> dict:
    """Set or refresh ``fact_id`` from the fact's current identity fields."""
    fact["fact_id"] = compute_fact_id(fact)
    return fact
