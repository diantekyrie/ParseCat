"""Per-user account auth for the whole app (API + static frontend).

Replaces the earlier shared-single-password design on this branch: with one
password known to everyone, any of the small group could see every other
coworker's uploaded captures (there was never a real ownership boundary,
just a lock on the front door). Real accounts fix that at the data layer --
see Device.owner_user_id / Investigation.owner_user_id in db_models.py and
every owner-scoped query in app/api/routes.py -- not just at login.

No self-service signup. Accounts are provisioned by the operator via
PARSECAT_BOOTSTRAP_USERS at startup (see provision_bootstrap_users()), not
created through the API -- for a handful of known coworkers, one env var
beats building and securing a registration flow, and it keeps the same
"configure via Render env vars" workflow already used for every other knob
in this app (PARSECAT_ALLOW_LLM_EGRESS, PARSECAT_ALLOW_BYOK, ...).

Session tokens are unchanged in shape from the shared-credential version:
POST /api/auth/login exchanges credentials for a short-lived, signed Bearer
token (now carrying a user id, not just "logged in or not"); the frontend
holds it only in a JS module variable (frontend/src/authSession.js), never
localStorage/cookies, so a refresh always starts from "no token" and
re-shows the login screen; the token also carries its own server-checked
expiry (PARSECAT_SESSION_TIMEOUT_SECONDS, default 900s / 15 min). See
LoginGate.jsx -- the frontend needed zero changes for this: same request/
response shape as before, just a real account behind it now.
"""
from __future__ import annotations

import hmac
import os
import secrets
import time

import bcrypt
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session, select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.models.db_models import User

BOOTSTRAP_USERS_ENV = "PARSECAT_BOOTSTRAP_USERS"
SESSION_TIMEOUT_ENV = "PARSECAT_SESSION_TIMEOUT_SECONDS"
_DEFAULT_SESSION_TIMEOUT_SECONDS = 15 * 60

# Exempt so a host's liveness probe (Render's optional Health Check Path, or
# any uptime monitor) can work without a session, and so /api/auth/login
# itself is reachable before anyone has a token to send -- a login endpoint
# that required being already logged in would be unusable.
_EXEMPT_PATHS = frozenset({"/api/health", "/api/auth/login"})

# Signs session tokens. Generated fresh every process start, never persisted
# -- a restart invalidates every outstanding session, which fits the intent
# here (periodic forced re-auth) rather than something to work around.
_SESSION_SECRET = secrets.token_bytes(32)

# Paid at login time whenever the username doesn't match a real account, so
# a request for a nonexistent user costs roughly the same wall-clock time as
# one for a real user with a wrong password (bcrypt.checkpw is the
# expensive step; skipping it for "no such user" would otherwise make that
# case measurably faster, leaking which usernames exist).
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"not-a-real-account", bcrypt.gensalt()).decode("utf-8")


def _is_api_path(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False  # malformed stored hash -- treat as "doesn't match", never crash the login route


def provision_bootstrap_users(session: Session) -> None:
    """Creates any account named in PARSECAT_BOOTSTRAP_USERS that doesn't
    already exist. Format: "user1:password1,user2:password2". Only CREATES
    missing accounts -- never touches an existing user's password, so an
    operator can't accidentally reset everyone's login by redeploying with
    the var still set (which is the normal case: nothing here removes it
    after first use). Add a new entry and redeploy to add a new coworker;
    existing ones are untouched.
    """
    raw = os.environ.get(BOOTSTRAP_USERS_ENV, "")
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        username, _, password = entry.partition(":")
        username, password = username.strip(), password.strip()
        if not username or not password:
            continue
        exists = session.exec(select(User.id).where(User.username == username)).first()
        if exists is not None:
            continue
        session.add(User(username=username, password_hash=_hash_password(password)))
    session.commit()


def _session_timeout_seconds() -> int:
    raw = os.environ.get(SESSION_TIMEOUT_ENV)
    if not raw:
        return _DEFAULT_SESSION_TIMEOUT_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_SESSION_TIMEOUT_SECONDS
    return value if value > 0 else _DEFAULT_SESSION_TIMEOUT_SECONDS


def issue_session_token(user_id: int, now: float | None = None) -> tuple[str, int]:
    """Mint a signed, self-expiring token for this user. Returns
    (token, expires_in_seconds).

    Format is "<user_id>:<expires_at_epoch>.<hmac_hex>" -- not a JWT,
    because the only claims this needs are "which user" and "not expired
    yet," and a bespoke library dependency buys nothing a single HMAC
    comparison doesn't already give.
    """
    timeout = _session_timeout_seconds()
    expires_at = int((now if now is not None else time.time())) + timeout
    payload = f"{user_id}:{expires_at}"
    sig = hmac.new(_SESSION_SECRET, payload.encode(), "sha256").hexdigest()
    return f"{payload}.{sig}", timeout


def _verify_session_token(token: str) -> int | None:
    """Returns the token's user_id if it's validly signed and not expired, else None."""
    payload, sep, sig = token.partition(".")
    if not sep:
        return None
    expected_sig = hmac.new(_SESSION_SECRET, payload.encode(), "sha256").hexdigest()
    if not secrets.compare_digest(sig, expected_sig):
        return None
    user_part, colon, exp_part = payload.partition(":")
    if not colon or not user_part.isdigit() or not exp_part.isdigit():
        return None
    if int(exp_part) <= time.time():
        return None
    return int(user_part)


def get_current_user_id(request: Request) -> int:
    """FastAPI dependency for routes that need to know who's asking.
    SessionAuthMiddleware already rejected anything without a valid token
    before a route handler ever runs, and stashes the user id on
    request.state -- this just surfaces it with a typed, explicit
    dependency instead of routes reaching into request.state directly.
    The 401 here is unreachable in production (the middleware already
    would have returned one) but keeps this safe rather than returning
    None if that invariant is ever broken.
    """
    user_id = getattr(request.state, "user_id", None)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return user_id


class LoginRequest(BaseModel):
    username: str
    password: str


def register_auth_routes(application: FastAPI) -> None:
    """POST /api/auth/login -- exempt from SessionAuthMiddleware (see
    _EXEMPT_PATHS) since nobody has a token yet when they call it.
    """
    from app.db import get_session
    from fastapi import Depends

    @application.post("/api/auth/login")
    def login(body: LoginRequest, session: Session = Depends(get_session)):
        user = session.exec(select(User).where(User.username == body.username)).first()
        if user is not None:
            password_ok = _verify_password(body.password, user.password_hash)
        else:
            _verify_password(body.password, _DUMMY_PASSWORD_HASH)  # pay the same bcrypt cost either way
            password_ok = False

        if not password_ok:
            any_user = session.exec(select(User.id).limit(1)).first()
            if any_user is None:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        f"No accounts have been provisioned yet. Set {BOOTSTRAP_USERS_ENV} "
                        "(e.g. \"alice:somepassword\") and redeploy."
                    ),
                )
            raise HTTPException(status_code=401, detail="Incorrect username or password.")

        token, expires_in = issue_session_token(user.id)
        return {"token": token, "expires_in": expires_in}


class SessionAuthMiddleware(BaseHTTPMiddleware):
    """Wraps the ENTIRE app -- API routes, the static frontend mount, and
    the SPA catch-all alike -- added last in main.py so it sits outermost
    and runs before any of them. A request with no valid session token
    never reaches a single /api/* route.
    """

    async def dispatch(self, request: Request, call_next):
        # CORS preflight carries no credentials by spec (browsers never
        # attach Authorization to an OPTIONS preflight) -- if this backend
        # is ever split onto a different origin from its frontend (see the
        # Vercel-split conversation), blocking OPTIONS here would break
        # every cross-origin request even with a valid token on the real
        # one. Preflight itself exposes nothing but CORS negotiation.
        #
        # Non-/api paths are the static frontend (index.html, /assets/*, and
        # the SPA catch-all -- see main.py's mount_frontend) and are exempt
        # too: LoginGate.jsx IS that bundle, so gating it here created a
        # deadlock where the login screen's own JS/CSS couldn't load without
        # a token you can only get from... the login screen. The bundle is
        # just the client-side app shell with no capture data or secrets
        # baked in -- every actual read of device/capture data still goes
        # through a gated, owner-scoped /api/* call, so this doesn't hand
        # out anything an unauthenticated visitor couldn't already infer
        # from the public GitHub repo this is built from.
        if (
            request.method == "OPTIONS"
            or request.url.path in _EXEMPT_PATHS
            or not _is_api_path(request.url.path)
        ):
            return await call_next(request)

        header = request.headers.get("authorization", "")
        token = header[len("Bearer "):] if header.startswith("Bearer ") else None
        user_id = _verify_session_token(token) if token else None
        if user_id is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "Session expired or invalid; please sign in again."},
            )

        request.state.user_id = user_id
        return await call_next(request)
