from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlmodel import Session, select

from app.db import get_session
from app.llm import list_providers
from app.models.db_models import Capture, Device, Investigation, InvestigationCaptureLink
from app.services.ingestion import parse_capture_file
from app.services.persistence import persist_capture
from app.services.reasoning import diagnose, diagnose_investigation, scan_capture
from app.services.summary import build_capture_summary, build_merged_summary, capture_severity

router = APIRouter()

SUPPORTED_UPLOAD_SUFFIXES = {".zip", ".txt", ".pcap", ".pcapng"}


def _parse_history(raw: str | None) -> list[dict] | None:
    """The `history` form field is a JSON-encoded list of prior
    {question, report} turns from the same follow-up thread -- see
    reasoning.py's _format_history(). Malformed/absent input degrades to
    "no history" rather than a 400, since history is for conversational
    continuity only, never a source of facts (SYSTEM_PROMPT rule 14)."""
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, list) else None


@router.post("/captures")
# Deliberately `def`, not `async def`. parse_capture_file() is a blocking,
# CPU-bound call (~8s on a 188MB bugreport) -- inside an async route it
# blocks the whole event loop, stalling every other request on the server.
# Measured before this change: a trivial /api/health call went from 116ms
# to 7,266ms while one upload was parsing. FastAPI runs sync routes in a
# threadpool instead, so concurrent uploads no longer freeze each other.
# (For real multi-tenant scale this still wants a job queue with workers --
# a threadpool bounds concurrency, it doesn't make parsing free.)
def upload_capture(
    device_label: str = Form(...),
    investigation_label: str | None = Form(None),
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in SUPPORTED_UPLOAD_SUFFIXES:
        raise HTTPException(400, "Expected one of: .zip, .txt, .pcap, .pcapng")

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = Path(tmp.name)

    try:
        parsed = parse_capture_file(tmp_path, file.filename)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, f"Failed to parse upload: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    clean_investigation_label = investigation_label.strip() if investigation_label else None
    capture = persist_capture(
        session, device_label, file.filename, parsed,
        investigation_label=clean_investigation_label or None,
    )

    return {
        "capture_id": capture.id,
        "device_label": device_label,
        "investigation_label": clean_investigation_label,
        "parse_warnings": parsed.parse_warnings,
        "facts_found": {
            "focus_stack_entries": len(parsed.focus_stack),
            "focus_events": len(parsed.focus_events),
            "packages": len(parsed.packages),
            "media_sessions": len(parsed.media_sessions),
            "foreground_services": len(parsed.foreground_services),
            "packet_capture": parsed.packet_capture_summary is not None,
        },
    }


@router.get("/llm/providers")
def get_llm_providers():
    return list_providers()


@router.get("/devices")
def list_devices(session: Session = Depends(get_session)):
    devices = session.exec(select(Device)).all()
    return devices


@router.get("/investigations")
def list_investigations(session: Session = Depends(get_session)):
    return session.exec(select(Investigation)).all()


@router.get("/investigations/{investigation_label}/captures")
def list_investigation_captures(investigation_label: str, session: Session = Depends(get_session)):
    investigation = session.exec(
        select(Investigation).where(Investigation.label == investigation_label)
    ).first()
    if investigation is None:
        raise HTTPException(404, "Unknown investigation")
    captures = session.exec(
        select(Capture)
        .join(InvestigationCaptureLink, InvestigationCaptureLink.capture_id == Capture.id)
        .where(InvestigationCaptureLink.investigation_id == investigation.id)
    ).all()
    return [{**c.model_dump(), "severity": capture_severity(session, c.id)} for c in captures]


@router.get("/investigations/{investigation_label}/summary")
def investigation_merged_summary(investigation_label: str, session: Session = Depends(get_session)):
    investigation = session.exec(
        select(Investigation).where(Investigation.label == investigation_label)
    ).first()
    if investigation is None:
        raise HTTPException(404, "Unknown investigation")
    capture_ids = session.exec(
        select(Capture.id)
        .join(InvestigationCaptureLink, InvestigationCaptureLink.capture_id == Capture.id)
        .where(InvestigationCaptureLink.investigation_id == investigation.id)
    ).all()
    return build_merged_summary(session, capture_ids)


@router.get("/devices/{device_label}/captures")
def list_captures(device_label: str, session: Session = Depends(get_session)):
    device = session.exec(select(Device).where(Device.label == device_label)).first()
    if device is None:
        raise HTTPException(404, "Unknown device")
    captures = session.exec(select(Capture).where(Capture.device_id == device.id)).all()
    return [{**c.model_dump(), "severity": capture_severity(session, c.id)} for c in captures]


@router.get("/devices/{device_label}/summary")
def device_merged_summary(device_label: str, session: Session = Depends(get_session)):
    device = session.exec(select(Device).where(Device.label == device_label)).first()
    if device is None:
        raise HTTPException(404, "Unknown device")
    capture_ids = session.exec(select(Capture.id).where(Capture.device_id == device.id)).all()
    return build_merged_summary(session, capture_ids)


@router.get("/captures/{capture_id}/summary")
def capture_summary(capture_id: int, session: Session = Depends(get_session)):
    capture = session.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(404, "Unknown capture")
    return build_capture_summary(session, capture_id)


@router.post("/captures/{capture_id}/diagnose")
def diagnose_capture(
    capture_id: int,
    question: str = Form(...),
    provider: str | None = Form(None),
    history: str | None = Form(None),
    session: Session = Depends(get_session),
):
    capture = session.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(404, "Unknown capture")
    device = session.get(Device, capture.device_id)

    result = diagnose(
        session, capture_id, device.label, question,
        provider=provider, history=_parse_history(history),
    )
    return result


@router.post("/captures/{capture_id}/scan")
def scan_capture_route(
    capture_id: int,
    provider: str | None = Form(None),
    session: Session = Depends(get_session),
):
    """Auto-scan -- no question required. Gathers every evidence category
    and returns severity-ranked findings plus a narrated summary."""
    capture = session.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(404, "Unknown capture")
    device = session.get(Device, capture.device_id)
    return scan_capture(session, capture_id, device.label, provider=provider)


@router.post("/investigations/{investigation_label}/diagnose")
def diagnose_investigation_route(
    investigation_label: str,
    question: str = Form(...),
    provider: str | None = Form(None),
    history: str | None = Form(None),
    session: Session = Depends(get_session),
):
    investigation = session.exec(
        select(Investigation).where(Investigation.label == investigation_label)
    ).first()
    if investigation is None:
        raise HTTPException(404, "Unknown investigation")

    result = diagnose_investigation(
        session, investigation.id, question,
        provider=provider, history=_parse_history(history),
    )
    return result
