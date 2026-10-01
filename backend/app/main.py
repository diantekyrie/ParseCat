from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()  # picks up backend/.env (gitignored) for OPENAI_API_KEY / ANTHROPIC_API_KEY

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.db import init_db
from app.parsers import WANTED_SECTIONS

_STARTED_AT = datetime.now(timezone.utc).isoformat()

app = FastAPI(title="ParseCat", description="Device log diagnosis API")

# Vite's dev server proxies /api to here directly (see frontend/vite.config.js),
# so CORS only matters for `npm run dev` against a separately-running backend.
# In production the built frontend is served from THIS process (below), so
# every request is same-origin and CORS is a no-op -- extra origins can still
# be added via PARSECAT_EXTRA_CORS_ORIGINS (comma-separated) without touching
# code, for a frontend hosted on a different domain.
_extra_origins = [
    o.strip() for o in os.environ.get("PARSECAT_EXTRA_CORS_ORIGINS", "").split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", *_extra_origins],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.on_event("startup")
def on_startup():
    init_db()


def _source_fingerprint() -> str:
    """A hash of every parser/service source file this process has loaded.

    Exists because a stale server silently produced a WRONG ANSWER twice
    during development: a running process kept serving code from before a
    parser was added, so a question about GPS came back "no evidence found"
    while the evidence sat in the database schema the same process had just
    created. A false negative from a diagnosis tool is worse than an error,
    because nothing looks broken.

    Comparing this value against the working tree turns that silent
    staleness into a visible mismatch -- see scripts/check_server_fresh.py.
    """
    h = hashlib.sha256()
    root = Path(__file__).resolve().parent
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        h.update(path.relative_to(root).as_posix().encode())
        h.update(path.read_bytes())
    return h.hexdigest()[:16]


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "started_at": _STARTED_AT,
        # Lets a caller prove the running process matches the code on disk.
        "source_fingerprint": _source_fingerprint(),
        # The authoritative list of what this build can even see. A section
        # absent here can never produce evidence, no matter how the question
        # is worded -- which is the difference between "nothing happened"
        # and "this build cannot look".
        "parsed_sections": sorted(WANTED_SECTIONS),
    }


# ---------------------------------------------------------------------------
# Built frontend, served from this same process in production.
#
# The frontend calls fetch(`/api${path}`) with a RELATIVE path (see
# frontend/src/App.jsx) -- it has no concept of a separate backend origin.
# `npm run dev` works around that with Vite's dev-server proxy, but that
# proxy doesn't exist once `vite build` produces static files. Serving those
# static files from this same FastAPI process means every deployed request
# is same-origin by construction: no CORS config, no "what's my API base
# URL" env var to get wrong in a rush, and exactly one URL to share.
#
# Mounted LAST and only if the build output exists, so `uvicorn` still runs
# fine for API-only local dev (`cd frontend && npm run dev` for the UI) when
# nobody has run `npm run build` yet.
# ---------------------------------------------------------------------------
_FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


def _is_unknown_api_path(full_path: str) -> bool:
    """Catch-all must not turn missing /api/* routes into HTML 200 SPA pages."""
    return full_path == "api" or full_path.startswith("api/")


def _safe_frontend_file(dist_root: Path, full_path: str) -> Path | None:
    """Return an in-dist file to serve, or None if missing / empty path.

    Resolves the joined path and requires containment under dist_root so a
    client-controlled full_path like ``../backend/.env`` cannot be served.
    """
    if not full_path:
        return None
    root = dist_root.resolve()
    try:
        candidate = (root / full_path).resolve()
    except (OSError, ValueError):
        return None
    if not candidate.is_relative_to(root):
        return None
    if candidate.is_file():
        return candidate
    return None


def _frontend_response(full_path: str, dist: Path):
    """SPA/static serve with path containment + unknown-/api JSON 404.

    Traversal that resolves outside ``dist`` returns 404 (never FileResponse
    outside dist, and not SPA index fallthrough for escaped paths). Normal
    missing client routes still get index.html when it stays under dist.
    """
    if _is_unknown_api_path(full_path):
        raise HTTPException(status_code=404, detail="Not Found")

    if not dist.is_dir():
        raise HTTPException(status_code=404, detail="Not Found")

    dist_root = dist.resolve()
    if full_path:
        try:
            candidate = (dist / full_path).resolve()
        except (OSError, ValueError):
            raise HTTPException(status_code=404, detail="Not Found") from None
        if not candidate.is_relative_to(dist_root):
            raise HTTPException(status_code=404, detail="Not Found")
        if candidate.is_file():
            return FileResponse(candidate)

    index = (dist / "index.html").resolve()
    if index.is_file() and index.is_relative_to(dist_root):
        return FileResponse(index)
    raise HTTPException(status_code=404, detail="Not Found")


def mount_frontend(application: FastAPI, dist: Path) -> bool:
    """Register /assets + SPA catch-all for ``dist`` when it exists.

    Extracted so TestClient can mount a temp dist/ without a real vite build
    at import time. Returns True if routes were registered.
    """
    if not dist.is_dir():
        return False

    assets = dist / "assets"
    if assets.is_dir():
        application.mount("/assets", StaticFiles(directory=assets), name="frontend-assets")

    @application.get("/{full_path:path}")
    def serve_frontend(full_path: str):
        return _frontend_response(full_path, dist)

    return True


mount_frontend(app, _FRONTEND_DIST)
