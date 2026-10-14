"""Shared-credential HTTP Basic Auth for the whole app (API + static frontend).

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
"""
from __future__ import annotations

import base64
import os
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

AUTH_USERNAME_ENV = "PARSECAT_AUTH_USERNAME"
AUTH_PASSWORD_ENV = "PARSECAT_AUTH_PASSWORD"

# Exempt so a host's liveness probe (Render's optional Health Check Path,
# or any uptime monitor) can work without the shared credential baked into
# its config. Low-risk to expose unauthenticated: no capture/device data,
# just a status string, a build hash, and the list of dumpsys sections this
# build can parse -- see main.py's health() docstring.
_EXEMPT_PATHS = frozenset({"/api/health"})


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


def _basic_auth_ok(header: str, expected_user: str, expected_pass: str) -> bool:
    if not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[len("Basic "):]).decode("utf-8")
    except Exception:  # noqa: BLE001 -- malformed header is just "not authorized"
        return False
    given_user, sep, given_pass = decoded.partition(":")
    if not sep:
        return False
    # Both comparisons always run (never short-circuited on the username
    # alone) so a wrong username doesn't return measurably faster than a
    # right one -- secrets.compare_digest is constant-time per call, and
    # `and` here still evaluates the right side even when the left is
    # False, so timing stays equivalent either way.
    user_ok = secrets.compare_digest(given_user, expected_user)
    pass_ok = secrets.compare_digest(given_pass, expected_pass)
    return user_ok and pass_ok


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Wraps the ENTIRE app -- API routes, the static frontend mount, and
    the SPA catch-all alike -- added last in main.py so it sits outermost
    and runs before any of them. A browser that fails the native Basic Auth
    prompt never reaches the static bundle, the health check's internals,
    or a single API route.
    """

    async def dispatch(self, request: Request, call_next):
        # CORS preflight carries no credentials by spec (browsers never
        # attach Authorization to an OPTIONS preflight) -- if this backend
        # is ever split onto a different origin from its frontend (see the
        # Vercel-split conversation), blocking OPTIONS here would break
        # every cross-origin request even with a correct password on the
        # real one. Preflight itself exposes nothing but CORS negotiation.
        if request.method == "OPTIONS" or request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        configured = _configured_credentials()
        if configured is None:
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

        expected_user, expected_pass = configured
        header = request.headers.get("authorization", "")
        if not _basic_auth_ok(header, expected_user, expected_pass):
            # WWW-Authenticate is what makes a browser pop its OWN native
            # login dialog -- no frontend code needed for this to work.
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="ParseCat"'})

        return await call_next(request)
