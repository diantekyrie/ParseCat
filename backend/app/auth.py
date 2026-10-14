"""Shared-credential session auth for the whole app (API + static frontend).

Deliberately NOT per-user accounts. ParseCat still has no ownership model --
see the data-segmentation question this branch was spun off to answer: this
does not segment captures between the people who know the one shared
credential, any more than main does. It answers a narrower, real threat
instead -- an open public URL with no login at all is exactly what gets
found by automated scanners and randoms, not just people who were handed
the link on purpose. One shared username/password keeps out everyone who
doesn't have BOTH the link and the credential; it does not give the small
group who do have it separate, private views of each other's uploads,
which stays unchanged from main.

PARSECAT_AUTH_USERNAME / PARSECAT_AUTH_PASSWORD, required together. Unlike
this app's other env-gated features (PARSECAT_ALLOW_LLM_EGRESS,
PARSECAT_ALLOW_BYOK), which default OFF/safe when unset, this one fails
CLOSED when unset: this branch's whole purpose is "the authed deploy", so a
misconfigured deploy that forgot to set credentials must not silently serve
the app wide open -- every request gets refused with a clear 503 telling
the operator what's missing, the same way AnthropicClient refuses to run
with no ANTHROPIC_API_KEY rather than silently no-op.

This is session-token auth, not raw HTTP Basic: a browser that's been given
Basic credentials once caches and silently replays them on every later
request, including after a page refresh -- the opposite of what was asked
for here ("make them log in again on refresh, or after 10-15 minutes").
Instead, POST /api/auth/login exchanges username+password for a short-lived,
signed Bearer token; the frontend holds that token ONLY in a JS module
variable (frontend/src/authSession.js), never localStorage/sessionStorage/a
cookie, so a refresh always starts from "no token" and re-shows the login
screen. The token also carries its own server-checked expiry
(PARSECAT_SESSION_TIMEOUT_SECONDS, default 900s / 15 min), so a tab left
open and idle loses access even without a refresh. Bearer-in-header rather
than a cookie also sidesteps CSRF by construction -- nothing is attached to
a request automatically, the frontend has to put it there deliberately.
"""
from __future__ import annotations

import hmac
import os
import secrets
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

AUTH_USERNAME_ENV = "PARSECAT_AUTH_USERNAME"
AUTH_PASSWORD_ENV = "PARSECAT_AUTH_PASSWORD"
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


def _configured_credentials() -> tuple[str, str] | None:
    """Read at request time (not cached at import/startup), matching this
    codebase's existing pattern for env-gated behavior (llm_egress_allowed(),
    byok_allowed(), _max_upload_bytes()) -- so tests can monkeypatch the env
    per-case without reimporting the module, and a config change only needs
    a process restart, not a code change.
    """
    username = os.environ.get(AUTH_USERNAME_ENV)
    password = os.environ.get(AUTH_PASSWORD_ENV)
    if not username or not password:
        return None
    return username, password


def _session_timeout_seconds() -> int:
    raw = os.environ.get(SESSION_TIMEOUT_ENV)
    if not raw:
        return _DEFAULT_SESSION_TIMEOUT_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_SESSION_TIMEOUT_SECONDS
    return value if value > 0 else _DEFAULT_SESSION_TIMEOUT_SECONDS


def issue_session_token(now: float | None = None) -> tuple[str, int]:
    """Mint a signed, self-expiring token. Returns (token, expires_in_seconds).

    Format is "<expires_at_epoch>.<hmac_hex>" -- not a JWT, because the only
    claim this needs is "not expired yet" and a bespoke library dependency
    buys nothing a single HMAC comparison doesn't already give.
    """
    timeout = _session_timeout_seconds()
    expires_at = int((now if now is not None else time.time())) + timeout
    payload = str(expires_at)
    sig = hmac.new(_SESSION_SECRET, payload.encode(), "sha256").hexdigest()
    return f"{payload}.{sig}", timeout


def _verify_session_token(token: str) -> bool:
    payload, sep, sig = token.partition(".")
    if not sep or not payload.isdigit():
        return False
    expected_sig = hmac.new(_SESSION_SECRET, payload.encode(), "sha256").hexdigest()
    if not secrets.compare_digest(sig, expected_sig):
        return False
    return int(payload) > time.time()


def _credentials_match(given_user: str, given_pass: str, expected_user: str, expected_pass: str) -> bool:
    # Both comparisons always run (never short-circuited on the username
    # alone) so a wrong username doesn't return measurably faster than a
    # right one -- secrets.compare_digest is constant-time per call, and
    # `and` here still evaluates the right side even when the left is
    # False, so timing stays equivalent either way.
    user_ok = secrets.compare_digest(given_user, expected_user)
    pass_ok = secrets.compare_digest(given_pass, expected_pass)
    return user_ok and pass_ok


class LoginRequest(BaseModel):
    username: str
    password: str


def register_auth_routes(application: FastAPI) -> None:
    """POST /api/auth/login -- exempt from SessionAuthMiddleware (see
    _EXEMPT_PATHS) since nobody has a token yet when they call it.
    """

    @application.post("/api/auth/login")
    def login(body: LoginRequest):
        configured = _configured_credentials()
        if configured is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    f"This deployment requires {AUTH_USERNAME_ENV} and "
                    f"{AUTH_PASSWORD_ENV} to both be set, and is refusing "
                    "all requests until they are."
                ),
            )
        expected_user, expected_pass = configured
        if not _credentials_match(body.username, body.password, expected_user, expected_pass):
            raise HTTPException(status_code=401, detail="Incorrect username or password.")
        token, expires_in = issue_session_token()
        return {"token": token, "expires_in": expires_in}


class SessionAuthMiddleware(BaseHTTPMiddleware):
    """Wraps the ENTIRE app -- API routes, the static frontend mount, and
    the SPA catch-all alike -- added last in main.py so it sits outermost
    and runs before any of them. A request with no valid session token never
    reaches the static bundle, the health check's internals (moot, it's
    exempt), or a single API route.
    """

    async def dispatch(self, request: Request, call_next):
        # CORS preflight carries no credentials by spec (browsers never
        # attach Authorization to an OPTIONS preflight) -- if this backend
        # is ever split onto a different origin from its frontend (see the
        # Vercel-split conversation), blocking OPTIONS here would break
        # every cross-origin request even with a valid token on the real
        # one. Preflight itself exposes nothing but CORS negotiation.
        if request.method == "OPTIONS" or request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        if _configured_credentials() is None:
            return JSONResponse(
                status_code=503,
                content={
                    "detail": (
                        f"This deployment requires {AUTH_USERNAME_ENV} and "
                        f"{AUTH_PASSWORD_ENV} to both be set, and is refusing "
                        "all requests until they are."
                    ),
                },
            )

        header = request.headers.get("authorization", "")
        token = header[len("Bearer "):] if header.startswith("Bearer ") else None
        if not token or not _verify_session_token(token):
            return JSONResponse(
                status_code=401,
                content={"detail": "Session expired or invalid; please sign in again."},
            )

        return await call_next(request)
