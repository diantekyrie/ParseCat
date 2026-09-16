"""Ask-over-log mandatory citations (issue #47).

Verified-from-log facts are citation-ready (SourceRef + code-owned confidence).
Empty evidence must stay empty — never speculative RCA filler.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import Session, SQLModel, create_engine

from app.services.citations import (
    VALID_CONFIDENCE,
    answer_confidence_from_facts,
    attach_verified_facts,
    code_owned_confidence,
    collect_verified_facts,
)
from app.services.ingestion import parse_bugreport_zip
from app.services.persistence import persist_capture
from app.services.reasoning import diagnose, scan_capture

FIX = Path(__file__).parent / "fixtures"
CAPTURE_1 = FIX / "bugreport_2026-08-13.zip"


pytestmark = pytest.mark.skipif(not CAPTURE_1.exists(), reason="real bugreport fixtures not present")


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _ingest(session, label, path):
    parsed = parse_bugreport_zip(path)
    return persist_capture(session, label, path.name, parsed)


def test_code_owned_confidence_never_invents_a_label():
    assert code_owned_confidence("HIGH") == "HIGH"
    assert code_owned_confidence("MEDIUM") == "MEDIUM"
    assert code_owned_confidence("LOW") == "LOW"
    assert code_owned_confidence("UNCONFIRMED") == "UNCONFIRMED"
    assert code_owned_confidence(None) == "UNCONFIRMED"
    assert code_owned_confidence("looks confident") == "UNCONFIRMED"
    assert code_owned_confidence(99) == "UNCONFIRMED"


def test_collect_verified_facts_includes_sourceref_on_crash_evidence():
    bundle = {
        "claims": [],
        "device_wide_crash_evidence": {
            "confidence": "HIGH",
            "java_crashes": [
                {
                    "package": "com.android.systemui",
                    "exception_class": "DeadSystemException",
                    "message": "boom",
                    "timestamp": "08-13 12:00:00.000",
                    "confidence": "HIGH",
                    "source": {"section": "system_log", "line_start": 100, "line_end": 120},
                    "capture_id": 1,
                    "original_filename": "bugreport.txt",
                }
            ],
            "native_crashes": [],
            "anrs": [],
        },
    }
    facts = collect_verified_facts(bundle)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["category"] == "crash"
    assert "systemui" in fact["summary"]
    assert fact["confidence"] == "HIGH"
    assert fact["source"] == {"section": "system_log", "line_start": 100, "line_end": 120}
    attached = attach_verified_facts(dict(bundle))
    assert attached["has_verified_facts"] is True
    assert attached["answer_confidence"] == "HIGH"
    assert attached["verified_facts"][0]["source"]["section"] == "system_log"


def test_empty_evidence_bundle_stays_honest():
    bundle = attach_verified_facts({"claims": [], "question": "Should I be worried about that?"})
    assert bundle["verified_facts"] == []
    assert bundle["has_verified_facts"] is False
    assert bundle["answer_confidence"] == "UNCONFIRMED"
    assert answer_confidence_from_facts([]) == "UNCONFIRMED"


def test_diagnose_crash_question_exposes_citation_ready_verified_facts(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Was there a crash on this device?")
    bundle = result["bundle"]
    assert "verified_facts" in bundle
    assert bundle["has_verified_facts"] is True
    assert bundle["answer_confidence"] in VALID_CONFIDENCE
    assert bundle["answer_confidence"] != "UNCONFIRMED"
    crash_facts = [f for f in bundle["verified_facts"] if f["category"] in {"crash", "native_crash", "anr"}]
    assert crash_facts, "expected crash-family verified facts from fixture"
    sourced = [f for f in crash_facts if f.get("source")]
    assert sourced, "at least one crash fact must carry a SourceRef"
    for f in bundle["verified_facts"]:
        assert f["confidence"] in VALID_CONFIDENCE


def test_diagnose_vague_followup_has_empty_verified_facts(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    first = diagnose(session, capture.id, "frankel-pixel", "Was there a crash on this device?")
    followup = diagnose(
        session, capture.id, "frankel-pixel", "Should I be worried about that?",
        history=[{"question": first["bundle"]["question"], "report": first["report"]}],
    )
    bundle = followup["bundle"]
    assert bundle["evidence_sources"] == []
    assert bundle["verified_facts"] == []
    assert bundle["has_verified_facts"] is False
    assert bundle["answer_confidence"] == "UNCONFIRMED"


def test_scan_attaches_verified_facts_with_confidence(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = scan_capture(session, capture.id, "frankel-pixel")
    bundle = result["bundle"]
    assert bundle.get("scan") is True
    assert bundle["has_verified_facts"] is True
    assert len(bundle["verified_facts"]) >= 1
    assert bundle["answer_confidence"] in VALID_CONFIDENCE
    for f in bundle["verified_facts"]:
        assert f["confidence"] in VALID_CONFIDENCE
