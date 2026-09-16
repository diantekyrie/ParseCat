"""Citation-ready verified facts for the Diagnose/Scan Verified-from-log band.

Parsers are ground truth; LLM narration may only restate these facts. This
module flattens already-assembled evidence into a stable UI/API shape with
SourceRef (section + line range), code-owned confidence labels, and a
deterministic ``fact_id`` for Arch causal-chain RCA edges. It never invents
prose, confidence, or causal claims.

RCA contract: every verified fact has a stable ``fact_id``; causal-chain
edges may only cite facts with non-null ``source``. Entity facts without
SourceRef remain band-only.
"""
from __future__ import annotations

from app.services.citations_core import (
    VALID_CONFIDENCE,
    _CONFIDENCE_RANK,
    _block_confidence,
    _fact,
    _source_ref,
    _truncate_for_fact,
    answer_confidence_from_facts,
    code_owned_confidence,
)
from app.services.citations_walks_claims import collect_verified_facts
from app.services.fact_id import compute_fact_id, stamp_fact_id


def attach_verified_facts(bundle: dict) -> dict:
    """Mutate bundle with verified_facts / has_verified_facts / answer_confidence."""
    facts = collect_verified_facts(bundle)
    bundle["verified_facts"] = facts
    bundle["has_verified_facts"] = len(facts) > 0
    bundle["answer_confidence"] = answer_confidence_from_facts(facts)
    return bundle


__all__ = [
    "VALID_CONFIDENCE",
    "answer_confidence_from_facts",
    "attach_verified_facts",
    "code_owned_confidence",
    "collect_verified_facts",
    "compute_fact_id",
    "stamp_fact_id",
]
