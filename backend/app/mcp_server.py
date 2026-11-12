"""ParseCat read-only MCP server (stdio only).

Exposes deterministic verified_facts to local MCP clients (Claude Desktop /
Claude Code, Cursor, OpenAI Agents SDK). No write tools, no LLM narration,
no HTTP/SSE listener — main still lacks capture ownership (#87), so a remote
transport would expose every user's captures.

Run (from backend/, with deps installed)::

    python -m app.mcp_server

Or point a host at this module; transport is explicitly stdio.
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
    DEFAULT_LIST_LIMIT,
    MAX_FACT_LIMIT,
    MAX_LIST_LIMIT,
    UNTRUSTED_DATA_NOTICE,
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
        "Read-only ParseCat tools. Return allowlisted structured parser "
        "fields only (shape-validated). Capture IDs instead of filenames. "
        "Labels, filenames, CDM display names, SSID/BSSID/MAC/serial, and "
        "coordinates are never returned as fields. Crash/ANR/kernel free text "
        "is omitted unless PARSECAT_MCP_INCLUDE_FREE_TEXT=1; when enabled it "
        "is scrubbed for PII/keys/MAC/IP and this capture's own label/"
        "filename/serial/SSID/BSSID. Residual risk when enabled: other names "
        "and free-form log text may still reach the model. "
        "No write/upload/diagnose/LLM tools. "
        f"{UNTRUSTED_DATA_NOTICE}"
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


def _db_unavailable(exc: Exception) -> ToolError:
    logger.warning("MCP DB unavailable: %s", exc)
    return ToolError("ParseCat DB not available")


@mcp.tool(
    name="list_captures",
    description=(
        "List ParseCat captures on non-archived devices. Returns id, kind "
        f"(bugreport|pcap), timestamps, and cheap severity counts. "
        f"Paginated via offset/limit (default {DEFAULT_LIST_LIMIT}, max "
        f"{MAX_LIST_LIMIT}). Does not return device labels, filenames, "
        "serials, or network identifiers. Log-derived content is absent here; "
        "see untrusted_data_notice."
    ),
)
def list_captures(offset: int | None = None, limit: int | None = None) -> str:
    try:
        with _session() as session:
            return _json(ro_list_captures(session, offset=offset, limit=limit))
    except FileNotFoundError as exc:
        raise _db_unavailable(exc) from exc


@mcp.tool(
    name="get_verified_facts",
    description=(
        "Return deterministic verified_facts for ONE capture only (parser "
        "ground truth with fact_id + SourceRef). Sibling captures on the same "
        "device are never included. Optional category filter "
        "(e.g. wifi, crash, anr, pairing, battery, memory). "
        f"Paginated via offset/limit (default {DEFAULT_FACT_LIMIT}, max "
        f"{MAX_FACT_LIMIT}). Allowlisted structured fields only. "
        "Crash/ANR/kernel free text omitted unless "
        "PARSECAT_MCP_INCLUDE_FREE_TEXT=1 (when on: scrubbed for PII/keys/"
        "MAC/IP and this capture's own label/filename/serial/SSID/BSSID; "
        "residual risk: other names/free-form log text may remain). Never "
        "returns labels/filenames/CDM names/SSID/BSSID/MAC/serial/"
        "coordinates as fields, or LLM narration."
    ),
)
def get_verified_facts(
    capture_id: int,
    category: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> str:
    try:
        with _session() as session:
            return _json(ro_get_verified_facts(
                session, capture_id,
                category=category, limit=limit, offset=offset,
            ))
    except CaptureNotFoundError as exc:
        raise ToolError("capture not found") from exc
    except FileNotFoundError as exc:
        raise _db_unavailable(exc) from exc


@mcp.tool(
    name="get_fact",
    description=(
        "Look up one verified fact by fact_id (vf_…). Pass capture_id to "
        "scope the search to that capture (required for precise lookups). "
        "Without capture_id, at most a small number of captures are scanned. "
        "A fact from sibling capture B is never returned when capture_id=A. "
        "Structured fields only; free text omitted unless "
        "PARSECAT_MCP_INCLUDE_FREE_TEXT=1 (scrubbed for PII/keys/MAC/IP and "
        "capture identity tokens; residual risk: other names/free-form log "
        "text may remain)."
    ),
)
def get_fact(fact_id: str, capture_id: int | None = None) -> str:
    try:
        with _session() as session:
            return _json(ro_get_fact(session, fact_id, capture_id=capture_id))
    except CaptureNotFoundError as exc:
        raise ToolError("capture not found") from exc
    except FactNotFoundError as exc:
        raise ToolError("fact not found") from exc
    except FileNotFoundError as exc:
        raise _db_unavailable(exc) from exc



def _sanitize_tool_validation_error(exc: BaseException) -> ToolError | None:
    """Map pydantic ValidationError → generic error (param names only, no values)."""
    from pydantic import ValidationError

    cause = exc.__cause__ if isinstance(exc, ToolError) else None
    verr = cause if isinstance(cause, ValidationError) else (
        exc if isinstance(exc, ValidationError) else None
    )
    if verr is None:
        return None
    fields = sorted({
        ".".join(str(part) for part in err.get("loc", ()) if part != "args")
        for err in verr.errors()
    })
    fields = [f for f in fields if f]
    names = ", ".join(fields) if fields else "arguments"
    return ToolError(f"invalid arguments: {names}")


_orig_call_tool = mcp.call_tool


async def _call_tool_no_echo(name: str, arguments: dict | None = None, context=None):
    try:
        return await _orig_call_tool(name, arguments or {}, context)
    except ToolError as exc:
        sanitized = _sanitize_tool_validation_error(exc)
        if sanitized is not None:
            raise sanitized from None
        # Arch nit: never echo the submitted tool name on unknown-tool.
        msg = str(exc)
        if msg.startswith("Unknown tool:") or msg.startswith("unknown tool"):
            raise ToolError("unknown tool") from None
        raise


mcp.call_tool = _call_tool_no_echo  # type: ignore[method-assign]

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
    # Explicit transport — never rely on SDK default alone (FE nice-to-have).
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
