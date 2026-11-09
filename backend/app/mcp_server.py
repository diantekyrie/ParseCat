"""ParseCat read-only MCP server (stdio only).

Exposes deterministic verified_facts to local MCP clients (Claude Desktop /
Claude Code, Cursor, OpenAI Agents SDK). No write tools, no LLM narration,
no HTTP/SSE listener — main still lacks capture ownership (#87), so a remote
transport would expose every user's captures.

Run (from backend/, with deps installed)::

    python -m app.mcp_server

Or point a host at this module; ``mcp.run()`` defaults to stdio.
"""
from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from sqlmodel import Session

from app.services.mcp_readonly import (
    DEFAULT_FACT_LIMIT,
    MAX_FACT_LIMIT,
    CaptureNotFoundError,
    FactNotFoundError,
    assert_engine_is_readonly,
    get_fact as ro_get_fact,
    get_verified_facts as ro_get_verified_facts,
    list_captures as ro_list_captures,
    open_readonly_engine,
)

logger = logging.getLogger("parsecat.mcp")

mcp = MCPServer(
    name="parsecat-readonly",
    instructions=(
        "Read-only ParseCat tools. Return deterministic parser verified_facts "
        "only — never invent narration, confidence, or causal claims. "
        "Identifiers (SSID/BSSID/MAC/serial) are stripped. No write/upload/"
        "diagnose/LLM tools exist on this server."
    ),
)


def _engine():
    return open_readonly_engine()


@contextmanager
def _session():
    engine = _engine()
    with Session(engine) as session:
        yield session


def _json(payload: Any) -> str:
    return json.dumps(payload, default=str, ensure_ascii=True)


@mcp.tool(
    name="list_captures",
    description=(
        "List ParseCat captures on non-archived devices. Returns id, device "
        "label, kind (bugreport|pcap), timestamps, and cheap severity counts. "
        "Does not return raw capture bytes, serials, or network identifiers."
    ),
)
def list_captures() -> str:
    try:
        with _session() as session:
            return _json(ro_list_captures(session))
    except FileNotFoundError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool(
    name="get_verified_facts",
    description=(
        "Return deterministic verified_facts for one capture (parser ground "
        "truth with fact_id + SourceRef). Optional category filter "
        "(e.g. wifi, crash, anr, pairing, battery, memory). "
        f"Default limit {DEFAULT_FACT_LIMIT}, hard cap {MAX_FACT_LIMIT}. "
        "SSID/BSSID/MAC/serial are stripped. Never returns LLM narration."
    ),
)
def get_verified_facts(
    capture_id: int,
    category: str | None = None,
    limit: int | None = None,
) -> str:
    try:
        with _session() as session:
            return _json(ro_get_verified_facts(
                session, capture_id, category=category, limit=limit,
            ))
    except CaptureNotFoundError as exc:
        raise ToolError(str(exc)) from exc
    except FileNotFoundError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool(
    name="get_fact",
    description=(
        "Look up one verified fact by fact_id (vf_…). Optional capture_id "
        "scopes the search. Returns a single redacted fact object or not-found."
    ),
)
def get_fact(fact_id: str, capture_id: int | None = None) -> str:
    try:
        with _session() as session:
            return _json(ro_get_fact(session, fact_id, capture_id=capture_id))
    except (CaptureNotFoundError, FactNotFoundError) as exc:
        raise ToolError(str(exc)) from exc
    except FileNotFoundError as exc:
        raise ToolError(str(exc)) from exc


# Tool names registered on this server — kept for tests / docs.
READONLY_TOOL_NAMES = frozenset({
    "list_captures",
    "get_verified_facts",
    "get_fact",
})
WRITEISH_TOOL_NAME_FRAGMENTS = (
    "write", "delete", "upload", "diagnose", "scan", "ask", "ingest", "put", "post",
)


def main() -> None:
    # Fail fast if someone points us at a writable misconfig; mode=ro is the
    # real guard, this just surfaces a clear error at startup when possible.
    if os.environ.get("PARSECAT_MCP_SKIP_RO_PROBE") != "1":
        try:
            assert_engine_is_readonly(_engine())
        except FileNotFoundError:
            logger.warning(
                "ParseCat DB missing at startup; tools will error until a DB exists"
            )
    mcp.run()  # stdio by default — no network listener


if __name__ == "__main__":
    main()
