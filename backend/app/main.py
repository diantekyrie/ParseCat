from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()  # picks up backend/.env (gitignored) for OPENAI_API_KEY / ANTHROPIC_API_KEY

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.db import init_db
from app.parsers import WANTED_SECTIONS

_STARTED_AT = datetime.now(timezone.utc).isoformat()

app = FastAPI(title="ParseCat", description="Device log diagnosis API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
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
