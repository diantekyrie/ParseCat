"""Stable deterministic fact_id on verified_facts (issue #49 / #54).

Every verified_facts entry gets vf_<sha256[:16]>; empty stays empty;
same bundle → same ids across runs. Entity facts without SourceRef still
get fact_id but remain band-only for Arch RCA edges.
"""
from __future__ import annotations

from app.services.citations import (
    attach_verified_facts,
    collect_verified_facts,
    compute_fact_id,
    stamp_fact_id,
)


def test_verified_facts_with_sourceref_get_fact_id():
    """Facts with SourceRef always carry a stable fact_id (Arch RCA edges)."""
    bundle = {
        "claims": [],
        "device_wide_crash_evidence": {
            "confidence": "HIGH",
            "java_crashes": [
                {
                    "package": "com.example.app",
                    "exception_class": "NullPointerException",
                    "message": "npe",
                    "timestamp": "08-13 12:00:00.000",
                    "confidence": "HIGH",
                    "source": {"section": "system_log", "line_start": 10, "line_end": 20},
                    "capture_id": 7,
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
    assert fact["source"] is not None
    assert fact["fact_id"].startswith("vf_")
    assert len(fact["fact_id"]) == len("vf_") + 16
    # Entity-style claim without SourceRef still gets fact_id (band-only).
    with_entity = {
        "claims": [
            {
                "package": "com.example.app",
                "confidence": "MEDIUM",
                "corroboration": "seen in dumpsys",
                "verified_state": {"crash_events": [], "anrs": [], "native_crashes": []},
            }
        ],
    }
    entity_facts = collect_verified_facts(with_entity)
    assert len(entity_facts) == 1
    entity = entity_facts[0]
    assert entity["category"] == "entity"
    assert entity["source"] is None
    assert entity["fact_id"].startswith("vf_")
    assert entity["fact_id"] != fact["fact_id"]


def test_empty_verified_facts_still_honest_with_fact_id():
    """Empty evidence stays empty — no invented fact_ids or filler rows."""
    bundle = attach_verified_facts({"claims": [], "question": "Anything wrong?"})
    assert bundle["verified_facts"] == []
    assert bundle["has_verified_facts"] is False
    assert bundle["answer_confidence"] == "UNCONFIRMED"


def test_fact_id_is_deterministic_same_bundle_same_ids():
    """Same input → same fact_id across collect runs (Arch RCA stability)."""
    bundle = {
        "claims": [
            {
                "package": "com.android.systemui",
                "confidence": "HIGH",
                "matched_how": "package match",
                "verified_state": {
                    "crash_events": [
                        {
                            "package": "com.android.systemui",
                            "exception_class": "DeadSystemException",
                            "message": "boom",
                            "timestamp": "08-13 12:00:00.000",
                            "source": {
                                "section": "system_log",
                                "line_start": 100,
                                "line_end": 120,
                            },
                        }
                    ],
                    "anrs": [],
                    "native_crashes": [],
                },
            }
        ],
        "device_wide_wifi_evidence": {
            "confidence": "MEDIUM",
            "disconnections": [
                {
                    "reason_name": "UNSPECIFIED",
                    "confidence": "MEDIUM",
                    "timestamp": "08-13 11:00:00.000",
                    "source": {"section": "wifi", "line_start": 5, "line_end": 5},
                    "capture_id": 1,
                    "original_filename": "bugreport.txt",
                    "locally_generated": True,
                }
            ],
        },
    }
    first = collect_verified_facts(bundle)
    second = collect_verified_facts(bundle)
    assert len(first) >= 2
    assert [f["fact_id"] for f in first] == [f["fact_id"] for f in second]
    assert len({f["fact_id"] for f in first}) == len(first)
    twin = dict(first[0])
    twin["confidence"] = "LOW"
    assert compute_fact_id(twin) == first[0]["fact_id"]
    labeled = stamp_fact_id({**first[0], "device_label": "pixel-a"})
    assert labeled["fact_id"] != first[0]["fact_id"]
    assert labeled["fact_id"] == compute_fact_id(labeled)


def _claim_cap(capture_id: int, original_filename: str) -> dict:
    """Minimal capture with an identical claim signature (no device_label)."""
    return {
        "capture_id": capture_id,
        "original_filename": original_filename,
        "claims": [
            {
                "package": "com.example.app",
                "confidence": "HIGH",
                "corroboration": "seen in dumpsys",
                "verified_state": {
                    "crash_events": [
                        {
                            "package": "com.example.app",
                            "exception_class": "NullPointerException",
                            "message": "npe",
                            "timestamp": "08-13 12:00:00.000",
                            "source": {
                                "section": "system_log",
                                "line_start": 10,
                                "line_end": 20,
                            },
                        }
                    ],
                    "anrs": [
                        {
                            "package": "com.example.app",
                            "reason": "Input dispatching timed out",
                            "timestamp": "08-13 12:01:00.000",
                            "source": {
                                "section": "system_log",
                                "line_start": 30,
                                "line_end": 40,
                            },
                        }
                    ],
                    "native_crashes": [
                        {
                            "package": "com.example.app",
                            "executable": "com.example.app",
                            "signal_name": "SIGSEGV",
                            "timestamp": "08-13 12:02:00.000",
                            "source": {
                                "section": "tombstones",
                                "line_start": 1,
                                "line_end": 50,
                            },
                        }
                    ],
                },
            }
        ],
    }


def test_claim_facts_distinct_across_captures_without_device_label():
    """Issue #54: multi-capture + no device_label must not collide on fact_id.

    Claims-path historically omitted capture_id/original_filename; without a
    per-capture discriminator, identical claim signatures across two captures
    hashed to the same vf_… id and broke the #49 identity contract.
    Covers all four claims-path _fact() sites: entity, crash, anr, native_crash.
    """
    bundle = {
        "captures": [
            _claim_cap(1, "bugreport-a.zip"),
            _claim_cap(2, "bugreport-b.zip"),
        ],
    }
    facts = collect_verified_facts(bundle)
    # Two captures × (entity + crash + anr + native_crash) = 8 claim-derived facts
    claim_cats = ("entity", "crash", "anr", "native_crash")
    claim_facts = [f for f in facts if f["category"] in claim_cats]
    assert len(claim_facts) == 8
    ids = [f["fact_id"] for f in claim_facts]
    assert len(set(ids)) == len(ids), f"collision: {ids}"

    by_capture = {}
    for f in claim_facts:
        by_capture.setdefault(f["capture_id"], []).append(f)
    assert set(by_capture) == {1, 2}
    for cap_id, cap_facts in by_capture.items():
        assert {f["category"] for f in cap_facts} == set(claim_cats)
        for f in cap_facts:
            assert f["capture_id"] == cap_id
            assert f["original_filename"] in ("bugreport-a.zip", "bugreport-b.zip")

    # Determinism: same investigation → same ids
    again = collect_verified_facts(bundle)
    assert [f["fact_id"] for f in again] == [f["fact_id"] for f in facts]


def test_claim_facts_single_capture_dict_captures_unchanged_identity():
    """Single-capture diagnose/scan shape: captures is a dict, not a list.

    build_diagnosis_bundle uses {id: filename}; the investigation fold must
    not run. Claim facts still get capture_id from the bundle via
    _capture_identity; fact_ids stay stable across runs.
    """
    bundle = {
        "capture_id": 42,
        "original_filename": "pixel-bugreport.zip",
        "captures": {"42": "pixel-bugreport.zip"},  # dict shape, not list
        "claims": [
            {
                "package": "com.example.app",
                "confidence": "HIGH",
                "corroboration": "seen in dumpsys",
                "verified_state": {
                    "crash_events": [
                        {
                            "package": "com.example.app",
                            "exception_class": "NullPointerException",
                            "message": "npe",
                            "timestamp": "08-13 12:00:00.000",
                            "source": {
                                "section": "system_log",
                                "line_start": 10,
                                "line_end": 20,
                            },
                        }
                    ],
                    "anrs": [
                        {
                            "package": "com.example.app",
                            "reason": "Input dispatching timed out",
                            "timestamp": "08-13 12:01:00.000",
                            "source": {
                                "section": "system_log",
                                "line_start": 30,
                                "line_end": 40,
                            },
                        }
                    ],
                    "native_crashes": [
                        {
                            "package": "com.example.app",
                            "signal_name": "SIGSEGV",
                            "timestamp": "08-13 12:02:00.000",
                            "source": {
                                "section": "tombstones",
                                "line_start": 1,
                                "line_end": 50,
                            },
                        }
                    ],
                },
            }
        ],
    }
    facts = collect_verified_facts(bundle)
    claim_cats = ("entity", "crash", "anr", "native_crash")
    claim_facts = [f for f in facts if f["category"] in claim_cats]
    assert len(claim_facts) == 4
    assert {f["category"] for f in claim_facts} == set(claim_cats)
    for f in claim_facts:
        assert f["capture_id"] == 42
        assert f["original_filename"] == "pixel-bugreport.zip"
        assert f["fact_id"].startswith("vf_")
    # Stable across runs (corpus identity contract)
    again = collect_verified_facts(bundle)
    assert [f["fact_id"] for f in again] == [f["fact_id"] for f in facts]
