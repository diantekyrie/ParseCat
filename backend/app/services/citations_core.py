"""Core helpers for citation-ready verified facts."""
from __future__ import annotations

from typing import Any

from app.services.fact_id import compute_fact_id, stamp_fact_id

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
    fact = {
        "category": category,
        "summary": summary,
        "detail": detail,
        "confidence": code_owned_confidence(confidence),
        "source": _source_ref(source),
        "timestamp": timestamp,
        "capture_id": capture_id,
        "original_filename": original_filename,
    }
    return stamp_fact_id(fact)


def _block_confidence(block: dict | None) -> Any:
    if not isinstance(block, dict):
        return None
    return block.get("confidence")


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
