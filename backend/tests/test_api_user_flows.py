"""HTTP-level user-journey tests for the ParseCat API.

Every other test file in this directory calls internal service functions
directly (persist_capture(), diagnose(), build_capture_summary(), ...).
None of them go through an actual HTTP request the way the frontend (or any
other real client) does -- routing, form parsing, status codes, and error
response shapes are all untested at that layer. This file closes that gap
using FastAPI's TestClient, matching the user-journey cases catalogued in
docs/test-cases.md (search for the case IDs in the docstrings below).

No real bugreport fixtures needed -- every capture here is a synthetic
in-memory .txt/.zip built inline, same convention as test_capture_formats.py
and test_device_label_identity.py.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.api.routes import SUPPORTED_UPLOAD_SUFFIXES  # noqa: F401 (documents the contract this file tests against)
from app.db import get_session
from app.main import app


@pytest.fixture
def client():
    # StaticPool -- an in-memory sqlite DB otherwise vanishes as soon as its
    # one connection closes, and TestClient opens a fresh connection (via
    # get_session) per request, so the tables from create_all() below would
    # be invisible to every request after the first without this.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _override_session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# A real "------ SECTION ------" header/footer pair, not just plain
# threadtime-shaped lines -- since #31/#32, a .txt with NO recognized
# bugreport section marker (including a bare plain-logcat dump) is
# rejected with 422 at upload time rather than persisted with a warning.
# This is the minimal shape that clears empty_bugreport_rejection_message().
_MINIMAL_BUGREPORT_TXT = """\
------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------
09-02 01:31:53.866  1145  1145 D keystore2: debug line 0
09-02 01:31:54.866  1145  1145 D keystore2: debug line 1
------ 0.326s was the duration of 'SYSTEM LOG' ------
"""


def _upload_txt(client, label, filename="logcat.txt", body=None, investigation_label=None):
    body = body if body is not None else _MINIMAL_BUGREPORT_TXT
    data = {"device_label": label}
    if investigation_label:
        data["investigation_label"] = investigation_label
    return client.post(
        "/api/captures",
        data=data,
        files={"file": (filename, body.encode(), "text/plain")},
    )


# --- 1. Upload & parse -------------------------------------------------

def test_upload_valid_txt_returns_capture_id_and_facts(client):
    # Case 1.1
    resp = _upload_txt(client, "Pixel")
    assert resp.status_code == 200
    body = resp.json()
    assert body["capture_id"] is not None
    assert body["device_label"] == "Pixel"
    assert "facts_found" in body


def test_upload_unsupported_extension_is_rejected(client):
    # Case 1.2
    resp = client.post(
        "/api/captures",
        data={"device_label": "Pixel"},
        files={"file": ("notes.pdf", b"whatever", "application/pdf")},
    )
    assert resp.status_code == 400
    assert ".zip" in resp.json()["detail"]


def test_upload_unrecognizable_txt_is_rejected_not_silently_persisted(client):
    # Case 1.3 -- superseded by #31/#32: this used to assert a silent 200
    # with a soft warning, but the deliberate fix for #31 made this a
    # blocking upload error instead (PC-ux-003). Updated to match the new,
    # intended contract rather than the old one.
    resp = _upload_txt(client, "Pixel", body="just some random notes, not a log file")
    assert resp.status_code == 422
    assert "No recognized bugreport section markers" in resp.json()["detail"]


def test_upload_corrupt_zip_returns_422(client):
    # Case 1.4
    resp = client.post(
        "/api/captures",
        data={"device_label": "Pixel"},
        files={"file": ("bugreport.zip", b"not actually a zip file", "application/zip")},
    )
    assert resp.status_code == 422
    assert "Failed to parse upload" in resp.json()["detail"]


def test_upload_with_investigation_label_links_capture(client):
    # Case 1.7
    resp = _upload_txt(client, "Pixel", investigation_label="case-42")
    assert resp.status_code == 200
    assert resp.json()["investigation_label"] == "case-42"

    listing = client.get("/api/investigations/case-42/captures")
    assert listing.status_code == 200
    assert len(listing.json()) == 1


# Case 1.8 (device identity mismatch -> 409, not a silent merge) is NOT
# repeated here: building a synthetic bugreport zip whose DeviceInfo
# section actually parses is significantly heavier than testing the same
# rule at the service level, and test_device_label_identity.py already
# covers it thoroughly (PC-ingestion-001 and friends) by constructing
# ParsedCapture/DeviceInfo objects directly. That leaves the HTTP route's
# own exception -> 409 translation (routes.py's `except
# DeviceIdentityMismatchError`) as the one sliver still untested at this
# layer -- worth adding if that translation logic itself ever changes.


# --- 2. Device & investigation browsing ---------------------------------

def test_unknown_device_returns_404(client):
    # Case 2.2
    resp = client.get("/api/devices/does-not-exist/captures")
    assert resp.status_code == 404


def test_unknown_investigation_returns_404(client):
    # Case 2.3
    resp = client.get("/api/investigations/does-not-exist/captures")
    assert resp.status_code == 404


def test_unknown_capture_summary_returns_404(client):
    # Case 2.4
    resp = client.get("/api/captures/999999/summary")
    assert resp.status_code == 404


# --- 4. Scan for problems ------------------------------------------------

def test_scan_unknown_capture_returns_404(client):
    # Case 4.2
    resp = client.post("/api/captures/999999/scan")
    assert resp.status_code == 404


# --- 5. Diagnose (single capture) ----------------------------------------

def test_diagnose_unknown_capture_returns_404(client):
    # Case 5.4
    resp = client.post("/api/captures/999999/diagnose", data={"question": "why did it crash?"})
    assert resp.status_code == 404


def test_diagnose_unknown_provider_degrades_with_llm_error_not_a_silent_fallback(client):
    # Case 5.8 -- get_llm_client() itself raises ValueError for an unknown
    # provider (test_end_to_end.py::test_unknown_provider_raises_rather_than_
    # silently_falling_back covers that lower level directly). At the HTTP
    # layer, diagnose() catches that and degrades the same way it does for
    # any other narration failure: 200, verified facts bundle intact,
    # report=null, llm_error naming the exact bad provider, and the
    # requested (not silently substituted) provider echoed back. This
    # documents that contract, not a raised 4xx/5xx.
    upload = _upload_txt(client, "Pixel")
    capture_id = upload.json()["capture_id"]
    resp = client.post(
        f"/api/captures/{capture_id}/diagnose",
        data={"question": "why did it crash?", "provider": "not-a-real-provider"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["report"] is None
    assert "not-a-real-provider" in body["llm_error"]
    assert body["provider"] == "not-a-real-provider"
    assert "bundle" in body  # verified facts still returned despite narration failure


# --- 6. Follow-up diagnosis -----------------------------------------------

def test_diagnose_malformed_history_degrades_to_no_history_not_400(client):
    # Case 6.2
    upload = _upload_txt(client, "Pixel")
    capture_id = upload.json()["capture_id"]
    resp = client.post(
        f"/api/captures/{capture_id}/diagnose",
        data={"question": "any follow-up?", "history": "{not valid json"},
    )
    assert resp.status_code == 200


# --- 7. Investigation-scope diagnosis -------------------------------------

def test_diagnose_investigation_unknown_label_returns_404(client):
    # Case 7.4
    resp = client.post(
        "/api/investigations/does-not-exist/diagnose",
        data={"question": "anything?"},
    )
    assert resp.status_code == 404


def test_diagnose_investigation_with_one_capture_is_not_gated_server_side(client):
    # Case 7.3 -- documents CURRENT behavior, not necessarily desired
    # behavior. The frontend disables investigation-scope diagnose below
    # 2 linked captures (App.jsx: `captures.length < 2`), but the API
    # route itself applies no such check. Calling it directly with a
    # single linked capture succeeds today. If product decides this
    # should be a 400 at the API layer too, this test is the one to flip.
    upload = _upload_txt(client, "Pixel", investigation_label="solo-case")
    assert upload.status_code == 200
    resp = client.post(
        "/api/investigations/solo-case/diagnose",
        data={"question": "anything?"},
    )
    assert resp.status_code == 200


# --- 9. Cross-cutting ------------------------------------------------------

def test_llm_providers_endpoint_reports_unavailable_not_error_when_unconfigured(client, monkeypatch):
    # Case 9.2
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    resp = client.get("/api/llm/providers")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
