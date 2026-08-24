"""Deterministic parsers for known-structured bugreport dumpsys sections.

These are ground truth. The LLM reasoning layer (see app/llm) only ever
reasons over what these parsers produce -- it never does semantic retrieval
over raw section text. Adding a new fact type means adding a parser here,
not a new prompt.
"""
from app.parsers.base import (
    ForegroundServiceFacts,
    FocusEvent,
    FocusStackEntry,
    MediaSessionFacts,
    PackageFacts,
    ParsedCapture,
    SourceRef,
)

WANTED_SECTIONS = {
    "audio", "package", "media_session", "activity", "system_log",
    "system_properties", "preamble", "wifi", "batterystats", "companiondevice",
    # SELinux AVC denials are logged by auditd, which writes to the EVENT
    # LOG buffer, not SYSTEM LOG. Found live: a real capture had 20 denials,
    # 19 of them here and only 1 in SYSTEM LOG -- parsing only SYSTEM LOG
    # would have silently missed 95% of them.
    "event_log",
    # `dumpsys meminfo` -- the per-process blocks run 15,000+ lines, but
    # only the summary tables at the end are parsed.
    "meminfo",
}

__all__ = [
    "ForegroundServiceFacts",
    "FocusEvent",
    "FocusStackEntry",
    "MediaSessionFacts",
    "PackageFacts",
    "ParsedCapture",
    "SourceRef",
    "WANTED_SECTIONS",
]
