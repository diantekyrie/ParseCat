"""The verification pass: given a natural-language question that names
specific apps, independently pull each named app's own parsed state before
any narrative gets constructed. This is what would have caught "YouTube
Music didn't pause" being false -- its own MediaSession history showed it
had already paused for an unrelated reason before the incident window.

The user's framing of a question is never treated as a fact. Every package
name mentioned gets its own state pulled and reported, whether or not it
supports the story the question implies.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from sqlmodel import Session, select

from app.models.db_models import (
    AnrRow,
    BatteryUidStatRow,
    Capture,
    CrashEventRow,
    FocusEventRow,
    FocusStackEntryRow,
    ForegroundServiceRow,
    FreezeSummaryRow,
    MediaSessionRow,
    PackageFactRow,
    TombstoneRow,
)

PACKAGE_ID_RE = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,})\b", re.IGNORECASE)

# Segments too generic to count as an app-identifying word on their own
# (they appear in hundreds of packages, and short common English words like
# "and"/"the" can otherwise substring-match into "android").
GENERIC_SEGMENTS = {
    "com", "org", "net", "android", "google", "apps", "app", "service",
    "services", "android_", "gms", "google_apps",
}
STOPWORDS = {
    "the", "and", "for", "was", "did", "has", "have", "not", "with", "that",
    "this", "when", "what", "why", "how", "app", "apps",
    # Diagnostic topic words (mirrors reasoning.py's *_TRIGGER_RE keyword
    # sets): a question using these is almost always talking ABOUT a
    # symptom category, not naming a brand -- but they can coincidentally
    # exact-match some installed app's package id anyway. Real case found
    # live: "battery" (from "was the battery drained...") is the one
    # unique, non-generic segment of com.oceanwing.battery.cam, which the
    # single-word-uniqueness rule then trusted as a real match even though
    # the user never meant that app.
    "battery", "drain", "drained", "draining", "power", "mah",
    "crash", "crashed", "crashing", "anr", "fatal", "tombstone",
    "wifi", "wlan", "disconnect", "disconnected", "dropped", "drop", "roam",
}


@dataclass
class EntityVerification:
    package: str
    matched_how: str                          # "literal_package_id" | "name_fragment_match"
    is_top_of_focus_stack: bool
    media_session_active: bool | None
    media_session_playback_state: str | None
    media_session_position_ms: int | None
    media_session_source: dict | None
    latest_focus_event: dict | None            # {"event_type", "timestamp", "detail", "source"}
    target_sdk: int | None
    target_sdk_source: dict | None
    crash_events: list[dict]           # Java FATAL EXCEPTION crashes attributed to this package
    freeze_count: int
    unfreeze_count: int
    tombstones: list[dict]             # native crashes attributed to this package
    anrs: list[dict]                   # ANRs attributed to this package
    battery: dict | None               # per-app battery attribution (mAh), if any
    corroborating_fact_count: int


def _known_packages(session: Session, capture_id: int) -> list[str]:
    rows = session.exec(
        select(PackageFactRow.package).where(PackageFactRow.capture_id == capture_id)
    ).all()
    return list(rows)


def extract_candidate_packages(question: str, known_packages: list[str]) -> list[str]:
    found: set[str] = set()

    for m in PACKAGE_ID_RE.finditer(question):
        candidate = m.group(1).lower()
        if candidate in known_packages:
            found.add(candidate)

    # Fallback: fuzzy match on brand words, e.g. "YouTube Music" -> a package
    # whose dotted segments exactly equal "youtube" and "music". Matching is
    # exact-segment only (not substring) and skips generic segments/stop
    # words -- substring matching let three-letter words like "and" falsely
    # match inside "android", which is exactly the kind of unverified
    # inference this pass exists to avoid.
    #
    # Two separate word lists on purpose, found live via "Pokemon Go" (issue
    # #39): "the Pokemon Go app...", "The Pokemon app..." both matched ZERO
    # installed packages even though com.nianticlabs.pokemongo was on the
    # capture. Root cause: the len>2 floor dropped "Go" before adjacency was
    # ever tried, so "pokemon"+"go" -> "pokemongo" (the package's real
    # segment) never got attempted. `words` (fed into the single-word/2-hit
    # paths below) deliberately keeps that len>2 floor -- those paths trust a
    # much weaker signal and short tokens there risk noisy accidental
    # matches. `concat_words` has no length floor, only the digit/letter and
    # stopword filters, because concatenation is inherently a stronger
    # signal already (it still requires an EXACT full-segment match) -- a
    # short token can only ever match by forming a real, exact, meaningful
    # segment together with its neighbor(s), the same reasoning that already
    # justified trusting a 2-word concat match on its own.
    #
    # `[A-Za-z0-9]+` (not `[A-Za-z]+`) also keeps digits, so a brand like
    # "8 Ball Pool" can reconstruct a segment like "8ball" -- the old
    # letters-only regex silently dropped the "8" before matching started.
    concat_words = [
        w.lower() for w in re.findall(r"[A-Za-z0-9]+", question)
        if w.lower() not in STOPWORDS
    ]
    words = {w for w in concat_words if len(w) > 2}

    # Two-word brand names often collapse into a single package segment with
    # no separator ("Disney Plus" -> "disneyplus", "Proton VPN" ->
    # "protonvpn") -- a real gap found live: "Disney Plus" and "Proton VPN"
    # both matched zero installed packages even though both were installed,
    # because neither word alone reaches the >=2-distinct-segment-hits bar
    # below. Adjacent question words get concatenated and checked against
    # segments too; a single such match is trusted on its own (concatenating
    # two specific words and landing on an exact real segment is not the
    # kind of coincidence three-letter substring matching produced).
    #
    # Three-word concatenation too -- the pairwise-only version had no path
    # at all for a brand needing three words to reconstruct its segment.
    adjacent_concat = {
        concat_words[i] + concat_words[i + 1] for i in range(len(concat_words) - 1)
    }
    adjacent_concat |= {
        concat_words[i] + concat_words[i + 1] + concat_words[i + 2]
        for i in range(len(concat_words) - 2)
    }

    all_segments = [
        {s for s in pkg.lower().split(".") if s not in GENERIC_SEGMENTS}
        for pkg in known_packages
    ]

    for pkg, segments in zip(known_packages, all_segments):
        hits = words & segments
        if len(hits) >= 2 or (adjacent_concat & segments):
            found.add(pkg)
            continue
        # A single-word exact match is also trusted, but only when that
        # segment is unique to this one package among everything installed.
        # Real gap found live: "ProtonVPN" (no space) is one word that
        # exactly equals ch.protonvpn.android's one non-generic segment,
        # but the >=2-hit rule discarded it as a lone match. Requiring
        # uniqueness (rather than just "any single hit") keeps generic
        # single words like "music" -- which legitimately appears in
        # multiple installed packages' segments -- from over-matching every
        # app that happens to share it; a real brand token that only one
        # app's package id contains is not that kind of coincidence.
        if hits:
            hit = next(iter(hits))
            owners = sum(1 for other in all_segments if hit in other)
            if owners == 1:
                found.add(pkg)

    return sorted(found)


def verify_entity(session: Session, capture_id: int, package: str, matched_how: str) -> EntityVerification:
    focus_top = session.exec(
        select(FocusStackEntryRow).where(
            FocusStackEntryRow.capture_id == capture_id,
            FocusStackEntryRow.package == package,
            FocusStackEntryRow.is_top_of_stack == True,  # noqa: E712
        )
    ).first()

    media = session.exec(
        select(MediaSessionRow).where(
            MediaSessionRow.capture_id == capture_id, MediaSessionRow.package == package
        )
    ).first()

    latest_event = session.exec(
        select(FocusEventRow)
        .where(FocusEventRow.capture_id == capture_id, FocusEventRow.package == package)
        .order_by(FocusEventRow.id.desc())
    ).first()

    pkg_fact = session.exec(
        select(PackageFactRow).where(
            PackageFactRow.capture_id == capture_id, PackageFactRow.package == package
        )
    ).first()

    crash_rows = session.exec(
        select(CrashEventRow).where(
            CrashEventRow.capture_id == capture_id, CrashEventRow.package == package
        )
    ).all()

    freeze_summary = session.exec(
        select(FreezeSummaryRow).where(
            FreezeSummaryRow.capture_id == capture_id, FreezeSummaryRow.package == package
        )
    ).first()

    tombstone_rows = session.exec(
        select(TombstoneRow).where(
            TombstoneRow.capture_id == capture_id, TombstoneRow.package == package
        )
    ).all()

    anr_rows = session.exec(
        select(AnrRow).where(
            AnrRow.capture_id == capture_id, AnrRow.package == package
        )
    ).all()

    battery_row = session.exec(
        select(BatteryUidStatRow).where(
            BatteryUidStatRow.capture_id == capture_id, BatteryUidStatRow.package == package
        )
    ).first()

    corroborating = sum(x is not None for x in (focus_top, media, latest_event, pkg_fact, battery_row))
    corroborating += len(crash_rows) + len(tombstone_rows) + len(anr_rows)
    if freeze_summary is not None:
        corroborating += 1

    return EntityVerification(
        package=package,
        matched_how=matched_how,
        is_top_of_focus_stack=focus_top is not None,
        media_session_active=media.active if media else None,
        media_session_playback_state=media.playback_state if media else None,
        media_session_position_ms=media.position_ms if media else None,
        media_session_source=(
            {"section": media.source_section, "line_start": media.source_line_start, "line_end": media.source_line_end}
            if media else None
        ),
        latest_focus_event=(
            {"event_type": latest_event.event_type, "timestamp": latest_event.timestamp, "detail": latest_event.detail,
             "source": {"section": latest_event.source_section, "line_start": latest_event.source_line_start, "line_end": latest_event.source_line_end}}
            if latest_event else None
        ),
        target_sdk=pkg_fact.target_sdk if pkg_fact else None,
        target_sdk_source=(
            {"section": pkg_fact.source_section, "line_start": pkg_fact.source_line_start, "line_end": pkg_fact.source_line_end}
            if pkg_fact else None
        ),
        crash_events=[
            {
                "timestamp": c.timestamp, "exception_class": c.exception_class, "message": c.message,
                "root_cause_class": c.root_cause_class, "root_cause_message": c.root_cause_message,
                "root_cause_frame": c.root_cause_frame,
                "source": {"section": c.source_section, "line_start": c.source_line_start, "line_end": c.source_line_end},
            }
            for c in crash_rows
        ],
        freeze_count=freeze_summary.freeze_count if freeze_summary else 0,
        unfreeze_count=freeze_summary.unfreeze_count if freeze_summary else 0,
        tombstones=[
            {
                "filename": t.filename, "timestamp": t.timestamp, "signal_name": t.signal_name,
                "signal_code": t.signal_code, "fault_addr": t.fault_addr, "top_frame": t.top_frame,
            }
            for t in tombstone_rows
        ],
        anrs=[
            {"filename": a.filename, "timestamp": a.timestamp, "reason": a.reason, "subject": a.subject}
            for a in anr_rows
        ],
        battery=(
            {
                "total_mah": battery_row.total_mah, "fg_mah": battery_row.fg_mah,
                "bg_mah": battery_row.bg_mah, "fgs_mah": battery_row.fgs_mah,
                "cached_mah": battery_row.cached_mah,
                "components_mah": json.loads(battery_row.components_mah_json),
                "source": {"section": battery_row.source_section, "line_start": battery_row.source_line_start, "line_end": battery_row.source_line_end},
            } if battery_row else None
        ),
        corroborating_fact_count=corroborating,
    )


def verify_question_entities(session: Session, capture_id: int, question: str) -> list[EntityVerification]:
    known = _known_packages(session, capture_id)

    literal_hits = {m.group(1).lower() for m in PACKAGE_ID_RE.finditer(question)} & set(known)
    fragment_hits = set(extract_candidate_packages(question, known)) - literal_hits

    results = [verify_entity(session, capture_id, pkg, "literal_package_id") for pkg in sorted(literal_hits)]
    results += [verify_entity(session, capture_id, pkg, "name_fragment_match") for pkg in sorted(fragment_hits)]
    return results
