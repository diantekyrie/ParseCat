from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlmodel import Session, select

from app.auth import get_current_user_id
from app.db import get_session
from app.llm import byok_allowed, list_providers
from app.models.db_models import Capture, Device, Investigation, InvestigationCaptureLink, User
from app.services.ingestion import empty_bugreport_rejection_message, parse_capture_file
from app.services.persistence import (
    DeviceIdentityMismatchError,
    persist_capture,
    UNVERIFIED_DEVICE_IDENTITY_WARNING,
)
from app.services.reasoning import diagnose, diagnose_investigation, scan_capture
from app.services.summary import build_capture_summary, build_merged_summary, capture_severity

router = APIRouter()

SUPPORTED_UPLOAD_SUFFIXES = {".zip", ".txt", ".pcap", ".pcapng"}

# Real bugreport .zips seen in this repo's own test fixtures run 100-290MB
# (see e.g. the Portkey bug threads), so this can't be a tiny cap -- but
# nothing enforced ANY limit before this, on an endpoint that will be public
# and unauthenticated: a single oversized or repeated upload could fill the
# host's disk via the NamedTemporaryFile below, with nothing to stop it.
# Override via env without a code change if a real device's bugreport ever
# needs more headroom. Read at request time via _max_upload_bytes() so tests
# (and ops) can change PARSECAT_MAX_UPLOAD_BYTES without reloading the module.
_DEFAULT_MAX_UPLOAD_BYTES = 500 * 1024 * 1024
MAX_UPLOAD_BYTES = _DEFAULT_MAX_UPLOAD_BYTES  # documented default; prefer helper


def _max_upload_bytes() -> int:
    return int(os.environ.get("PARSECAT_MAX_UPLOAD_BYTES", str(_DEFAULT_MAX_UPLOAD_BYTES)))


def _resolve_byok(
    byok_api_key: str | None, byok_model: str | None, user: User | None,
) -> tuple[str | None, str | None]:
    """A one-off key typed into this request always wins (lets anyone
    override their saved key, or use BYOK without saving one at all); the
    user's saved account key (see /api/account/byok below) is the fallback
    so narration works without retyping a key on every call.
    """
    key = (byok_api_key or "").strip()
    if key:
        return key, ((byok_model or "").strip() or None)
    if user is not None and user.byok_api_key:
        return user.byok_api_key, user.byok_model
    return None, None


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
    current_user_id: int = Depends(get_current_user_id),
):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in SUPPORTED_UPLOAD_SUFFIXES:
        raise HTTPException(400, "Expected one of: .zip, .txt, .pcap, .pcapng")

    # Bounded chunked copy, not shutil.copyfileobj(file.file, tmp) -- that
    # trusts the client to stop sending, which an unauthenticated public
    # endpoint cannot assume. Content-Length is advisory (absent on chunked
    # transfer-encoding, and nothing stops a client from lying about it), so
    # this counts actual bytes written and aborts mid-stream rather than
    # buffering an unbounded upload to disk first and checking after.
    # Single try/finally so every failure path (413, disconnect, OSError,
    # parse error) and the success path unlink the NamedTemporaryFile.
    written = 0
    tmp_path: Path | None = None
    max_bytes = _max_upload_bytes()
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp_path = Path(tmp.name)
            while chunk := file.file.read(1024 * 1024):
                written += len(chunk)
                if written > max_bytes:
                    raise HTTPException(
                        413,
                        f"Upload exceeds the {max_bytes // (1024 * 1024)}MB limit.",
                    )
                tmp.write(chunk)

        try:
            parsed = parse_capture_file(tmp_path, file.filename)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(422, f"Failed to parse upload: {exc}") from exc
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    # PC-ux-003 / #31: empty .txt (or plain logcat with no bugreport sections)
    # must not become a successful capture row — surface as upload failure so
    # the UI blocking .error banner fires. Parser still produced the diagnostic
    # warning; we refuse to persist it.
    reject = empty_bugreport_rejection_message(parsed)
    if reject:
        raise HTTPException(status_code=422, detail=reject)

    clean_investigation_label = investigation_label.strip() if investigation_label else None
    try:
        capture = persist_capture(
            session, device_label, file.filename, parsed,
            investigation_label=clean_investigation_label or None,
            owner_user_id=current_user_id,
        )
    except DeviceIdentityMismatchError as exc:
        raise HTTPException(status_code=409, detail=exc.as_api_detail()) from exc

    identity_warning = next(
        (w for w in parsed.parse_warnings if w == UNVERIFIED_DEVICE_IDENTITY_WARNING),
        None,
    )
    return {
        "capture_id": capture.id,
        "device_label": device_label,
        "investigation_label": clean_investigation_label,
        "parse_warnings": parsed.parse_warnings,
        "identity_warning": identity_warning,
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


@router.get("/llm/byok_status")
def get_byok_status(
    session: Session = Depends(get_session), current_user_id: int = Depends(get_current_user_id),
):
    # Separate endpoint, not folded into list_providers()'s array response,
    # so existing callers of that endpoint are untouched. Lets the frontend
    # hide/disable the BYOK panel instead of letting a visitor type in a key
    # that will just come back "disabled on this deployment" -- see
    # app.llm.get_byok_client for why this is off by default. `configured`
    # is this user's own saved key (never the key itself -- see
    # /api/account/byok below), separate from `available` (whether the
    # deployment allows BYOK at all).
    user = session.get(User, current_user_id)
    return {
        "available": byok_allowed(),
        "configured": bool(user and user.byok_api_key),
        "model": user.byok_model if user else None,
    }


class ByokSettings(BaseModel):
    api_key: str
    model: str | None = None


@router.put("/account/byok")
def set_account_byok(
    body: ByokSettings,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    """Saves this user's own OpenRouter key to their account so it's used
    automatically on diagnose/scan calls that don't include a one-off key
    (see _resolve_byok above) -- no more retyping it every request. Write
    -only from the client's perspective: this is the only route that
    accepts the raw key; nothing ever echoes it back (see get_byok_status
    and the User model's docstring for why that boundary is the real
    protection here, not encryption at rest).
    """
    key = body.api_key.strip()
    if not key:
        raise HTTPException(400, "api_key is required (use DELETE /api/account/byok to clear it)")
    user = session.get(User, current_user_id)
    if user is None:
        raise HTTPException(404, "Unknown account")
    user.byok_api_key = key
    user.byok_model = (body.model or "").strip() or None
    session.add(user)
    session.commit()
    return {"configured": True, "model": user.byok_model}


@router.delete("/account/byok")
def clear_account_byok(
    session: Session = Depends(get_session), current_user_id: int = Depends(get_current_user_id),
):
    user = session.get(User, current_user_id)
    if user is None:
        raise HTTPException(404, "Unknown account")
    user.byok_api_key = None
    user.byok_model = None
    session.add(user)
    session.commit()
    return {"configured": False, "model": None}


@router.get("/devices")
def list_devices(
    include_archived: bool = False,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    query = select(Device).where(Device.owner_user_id == current_user_id)
    if not include_archived:
        query = query.where(Device.archived == False)  # noqa: E712
    return session.exec(query).all()


@router.post("/devices/{device_label}/archive")
def archive_device(
    device_label: str,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    return _set_device_archived(session, device_label, True, current_user_id)


@router.post("/devices/{device_label}/unarchive")
def unarchive_device(
    device_label: str,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    return _set_device_archived(session, device_label, False, current_user_id)


def _set_device_archived(session: Session, device_label: str, archived: bool, owner_user_id: int):
    device = session.exec(
        select(Device).where(Device.label == device_label, Device.owner_user_id == owner_user_id)
    ).first()
    if device is None:
        raise HTTPException(404, "Unknown device")
    # Archiving only hides a device from GET /devices (and the frontend's
    # device-picker <datalist>) by default -- it is not deleted, and every
    # existing route that looks it up directly by label still works exactly
    # as before, so nothing breaks for a user who still has it typed in.
    device.archived = archived
    session.add(device)
    session.commit()
    session.refresh(device)
    return device


@router.get("/investigations")
def list_investigations(
    include_archived: bool = False,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    query = select(Investigation).where(Investigation.owner_user_id == current_user_id)
    if not include_archived:
        query = query.where(Investigation.archived == False)  # noqa: E712
    return session.exec(query).all()


@router.post("/investigations/{investigation_label}/archive")
def archive_investigation(
    investigation_label: str,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    return _set_investigation_archived(session, investigation_label, True, current_user_id)


@router.post("/investigations/{investigation_label}/unarchive")
def unarchive_investigation(
    investigation_label: str,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    return _set_investigation_archived(session, investigation_label, False, current_user_id)


def _set_investigation_archived(
    session: Session, investigation_label: str, archived: bool, owner_user_id: int,
):
    investigation = session.exec(
        select(Investigation).where(
            Investigation.label == investigation_label, Investigation.owner_user_id == owner_user_id,
        )
    ).first()
    if investigation is None:
        raise HTTPException(404, "Unknown investigation")
    investigation.archived = archived
    session.add(investigation)
    session.commit()
    session.refresh(investigation)
    return investigation


@router.get("/investigations/{investigation_label}/captures")
def list_investigation_captures(
    investigation_label: str,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    investigation = session.exec(
        select(Investigation).where(
            Investigation.label == investigation_label, Investigation.owner_user_id == current_user_id,
        )
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
def investigation_merged_summary(
    investigation_label: str,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    investigation = session.exec(
        select(Investigation).where(
            Investigation.label == investigation_label, Investigation.owner_user_id == current_user_id,
        )
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
def list_captures(
    device_label: str,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    device = session.exec(
        select(Device).where(Device.label == device_label, Device.owner_user_id == current_user_id)
    ).first()
    if device is None:
        raise HTTPException(404, "Unknown device")
    captures = session.exec(select(Capture).where(Capture.device_id == device.id)).all()
    return [{**c.model_dump(), "severity": capture_severity(session, c.id)} for c in captures]


@router.get("/devices/{device_label}/summary")
def device_merged_summary(
    device_label: str,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    device = session.exec(
        select(Device).where(Device.label == device_label, Device.owner_user_id == current_user_id)
    ).first()
    if device is None:
        raise HTTPException(404, "Unknown device")
    capture_ids = session.exec(select(Capture.id).where(Capture.device_id == device.id)).all()
    return build_merged_summary(session, capture_ids)


def _owned_capture(session: Session, capture_id: int, owner_user_id: int) -> Capture | None:
    """Capture has no owner column of its own -- ownership is inherited
    through its Device (see Device.owner_user_id). 404 (not 403) for a
    capture that exists but belongs to someone else, same as a capture_id
    that doesn't exist at all -- doesn't confirm to a guesser which ids are
    real on this instance.
    """
    capture = session.get(Capture, capture_id)
    if capture is None:
        return None
    device = session.get(Device, capture.device_id)
    if device is None or device.owner_user_id != owner_user_id:
        return None
    return capture


@router.get("/captures/{capture_id}/summary")
def capture_summary(
    capture_id: int,
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    capture = _owned_capture(session, capture_id, current_user_id)
    if capture is None:
        raise HTTPException(404, "Unknown capture")
    return build_capture_summary(session, capture_id)


@router.post("/captures/{capture_id}/diagnose")
def diagnose_capture(
    capture_id: int,
    question: str = Form(...),
    provider: str | None = Form(None),
    history: str | None = Form(None),
    # Visitor-supplied OpenRouter key, used for exactly this one call and
    # never persisted (not logged, not written to .env, not stored in the
    # DB -- see app.llm.get_byok_client). Lets a public deploy with no
    # server-side key configured still offer real narration to anyone who
    # brings their own, while defaulting everyone else to Stub.
    byok_api_key: str | None = Form(None),
    byok_model: str | None = Form(None),
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    capture = _owned_capture(session, capture_id, current_user_id)
    if capture is None:
        raise HTTPException(404, "Unknown capture")
    device = session.get(Device, capture.device_id)
    resolved_key, resolved_model = _resolve_byok(
        byok_api_key, byok_model, session.get(User, current_user_id),
    )

    result = diagnose(
        session, capture_id, device.label, question,
        provider=provider, history=_parse_history(history),
        byok_api_key=resolved_key, byok_model=resolved_model,
    )
    return result


@router.post("/captures/{capture_id}/scan")
def scan_capture_route(
    capture_id: int,
    provider: str | None = Form(None),
    byok_api_key: str | None = Form(None),
    byok_model: str | None = Form(None),
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    """Auto-scan -- no question required. Gathers every evidence category
    and returns severity-ranked findings plus a narrated summary."""
    capture = _owned_capture(session, capture_id, current_user_id)
    if capture is None:
        raise HTTPException(404, "Unknown capture")
    device = session.get(Device, capture.device_id)
    resolved_key, resolved_model = _resolve_byok(
        byok_api_key, byok_model, session.get(User, current_user_id),
    )
    return scan_capture(
        session, capture_id, device.label, provider=provider,
        byok_api_key=resolved_key, byok_model=resolved_model,
    )


@router.post("/investigations/{investigation_label}/diagnose")
def diagnose_investigation_route(
    investigation_label: str,
    question: str = Form(...),
    provider: str | None = Form(None),
    history: str | None = Form(None),
    byok_api_key: str | None = Form(None),
    byok_model: str | None = Form(None),
    session: Session = Depends(get_session),
    current_user_id: int = Depends(get_current_user_id),
):
    investigation = session.exec(
        select(Investigation).where(
            Investigation.label == investigation_label, Investigation.owner_user_id == current_user_id,
        )
    ).first()
    if investigation is None:
        raise HTTPException(404, "Unknown investigation")
    resolved_key, resolved_model = _resolve_byok(
        byok_api_key, byok_model, session.get(User, current_user_id),
    )

    result = diagnose_investigation(
        session, investigation.id, question,
        provider=provider, history=_parse_history(history),
        byok_api_key=resolved_key, byok_model=resolved_model,
    )
    return result
