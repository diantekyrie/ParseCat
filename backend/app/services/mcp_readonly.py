"""Read-only ParseCat DB access for the MCP server.

Hands agents deterministic verified_facts (parser ground truth), never LLM
narration. Opens SQLite in mode=ro. Applies the same LLM-bundle identifier
strip (#22 / PC-narration-008/009) via ``_llm_safe_evidence_row``.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sqlalchemy.exc import OperationalError
from sqlmodel import Session, create_engine, select

from app.models.db_models import Capture, Device, PacketCaptureSummaryRow
from app.services.citations import attach_verified_facts
from app.services.reasoning import (
    LLM_EVIDENCE_REDACT_KEYS,
    _llm_safe_evidence_row,
    build_diagnosis_bundle,
    rank_findings,
)
from app.services.summary import capture_severity

# Hard caps so an agent cannot dump the whole DB in one call.
DEFAULT_FACT_LIMIT = 100
MAX_FACT_LIMIT = 500

# Extra keys that must never leave via MCP even if a future walk adds them.
# Serial is excluded from DEVICE_CONTEXT_LLM_FIELDS; keep the same bar here.
_MCP_EXTRA_REDACT_KEYS = frozenset({
    "serial",
    "latitude",
    "longitude",
    "address",  # BT framework BD_ADDR-shaped field
})

_MCP_REDACT_KEYS = LLM_EVIDENCE_REDACT_KEYS | _MCP_EXTRA_REDACT_KEYS


class CaptureNotFoundError(LookupError):
    """Unknown capture, or capture belongs to an archived (soft-hidden) device."""


class FactNotFoundError(LookupError):
    """No verified fact with this fact_id (in scope)."""


def default_db_path() -> Path:
    """Resolve the SQLite file the FastAPI app uses by default.

    Matches ``app.db.DATABASE_URL`` (``sqlite:///./parsecat.db``) relative to
    the process cwd. Override with ``PARSECAT_DB_PATH``.
    """
    override = os.environ.get("PARSECAT_DB_PATH")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.cwd() / "parsecat.db").resolve()


def open_readonly_engine(db_path: Path | str | None = None):
    """Create a SQLAlchemy engine that refuses writes (sqlite URI mode=ro)."""
    path = Path(db_path) if db_path is not None else default_db_path()
    path = path.resolve()
    if not path.exists():
        raise FileNotFoundError(f"ParseCat DB not found: {path}")
    # Absolute path as a SQLite URI. Both mode=ro and uri=true must live in
    # the URL string for pysqlite (connect_args alone is ignored for mode).
    uri = f"sqlite:///file:{path.as_posix()}?mode=ro&uri=true"
    return create_engine(uri, connect_args={"check_same_thread": False})


def assert_engine_is_readonly(engine) -> None:
    """Raise if a write against this engine succeeds (test / startup guard)."""
    with engine.connect() as conn:
        try:
            conn.exec_driver_sql(
                "CREATE TABLE _parsecat_mcp_ro_probe (id INTEGER PRIMARY KEY)"
            )
            conn.commit()
        except OperationalError:
            return
        raise RuntimeError("expected read-only SQLite engine; write succeeded")


def _mcp_safe_row(row: dict) -> dict:
    """Drop network/device identifier keys from one MCP-bound fact row."""
    cleaned = _llm_safe_evidence_row(row)
    return {k: v for k, v in cleaned.items() if k not in _MCP_EXTRA_REDACT_KEYS}


def _active_capture(session: Session, capture_id: int) -> tuple[Capture, Device]:
    capture = session.get(Capture, capture_id)
    if capture is None:
        raise CaptureNotFoundError(f"capture_id={capture_id} not found")
    device = session.get(Device, capture.device_id)
    if device is None or device.archived:
        # Treat archived-device captures as soft-hidden (PR #42); hard-delete
        # for captures themselves is still an open #95 policy call.
        raise CaptureNotFoundError(f"capture_id={capture_id} not found")
    return capture, device


def _capture_kind(session: Session, capture_id: int) -> str:
    pcap = session.exec(
        select(PacketCaptureSummaryRow).where(
            PacketCaptureSummaryRow.capture_id == capture_id
        )
    ).first()
    return "pcap" if pcap is not None else "bugreport"


def list_captures(session: Session) -> list[dict[str, Any]]:
    """List non-archived-device captures with cheap severity counts.

    Fields are only ones that exist on Capture/Device (+ derived kind/counts).
    No serial, no raw paths beyond original_filename (user-supplied name).
    """
    rows = session.exec(
        select(Capture, Device)
        .join(Device, Capture.device_id == Device.id)
        .where(Device.archived == False)  # noqa: E712
        .order_by(Capture.id)
    ).all()
    out: list[dict[str, Any]] = []
    for capture, device in rows:
        counts = capture_severity(session, capture.id)
        out.append({
            "id": capture.id,
            "label": device.label,
            "kind": _capture_kind(session, capture.id),
            "original_filename": capture.original_filename,
            "captured_at": capture.captured_at.isoformat() if capture.captured_at else None,
            "ingested_at": capture.ingested_at.isoformat() if capture.ingested_at else None,
            "counts": counts,
        })
    return out


def _verified_facts_for_capture(session: Session, capture_id: int) -> list[dict]:
    capture, device = _active_capture(session, capture_id)
    # include_all_evidence gathers every parser category with no LLM call.
    question = "Full automatic scan: what problems are present on this device?"
    bundle = build_diagnosis_bundle(
        session, capture_id, device.label, question, include_all_evidence=True,
    )
    bundle["capture_id"] = capture.id
    bundle["original_filename"] = capture.original_filename
    bundle["ranked_findings"] = rank_findings(bundle)
    attach_verified_facts(bundle)
    facts = bundle.get("verified_facts") or []
    # Stamp device_label for fact_id stability when walks omit it.
    cleaned: list[dict] = []
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        row = dict(fact)
        row.setdefault("device_label", device.label)
        row.setdefault("capture_id", capture.id)
        cleaned.append(_mcp_safe_row(row))
    return cleaned


def get_verified_facts(
    session: Session,
    capture_id: int,
    *,
    category: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Return redacted verified_facts for one capture (parser ground truth)."""
    lim = DEFAULT_FACT_LIMIT if limit is None else int(limit)
    if lim < 1:
        lim = 1
    if lim > MAX_FACT_LIMIT:
        lim = MAX_FACT_LIMIT

    facts = _verified_facts_for_capture(session, capture_id)
    if category:
        want = category.strip().lower()
        facts = [
            f for f in facts
            if str(f.get("category") or "").lower() == want
        ]
    total = len(facts)
    truncated = total > lim
    return {
        "capture_id": capture_id,
        "category": category,
        "total": total,
        "returned": min(total, lim),
        "truncated": truncated,
        "limit": lim,
        "facts": facts[:lim],
    }


def get_fact(
    session: Session,
    fact_id: str,
    *,
    capture_id: int | None = None,
) -> dict[str, Any]:
    """Look up one verified fact by fact_id.

    When ``capture_id`` is set, only that capture is searched. Otherwise every
    non-archived capture is scanned until a match (small local DBs only).
    """
    if not fact_id or not str(fact_id).startswith("vf_"):
        raise FactNotFoundError(f"fact_id={fact_id!r} not found")

    if capture_id is not None:
        for fact in _verified_facts_for_capture(session, capture_id):
            if fact.get("fact_id") == fact_id:
                return fact
        raise FactNotFoundError(f"fact_id={fact_id!r} not found")

    for row in list_captures(session):
        for fact in _verified_facts_for_capture(session, row["id"]):
            if fact.get("fact_id") == fact_id:
                return fact
    raise FactNotFoundError(f"fact_id={fact_id!r} not found")


# Re-export for tests that assert the redact key set without importing reasoning.
MCP_REDACT_KEYS = _MCP_REDACT_KEYS
