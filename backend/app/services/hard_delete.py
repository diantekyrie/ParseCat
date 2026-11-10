"""Hard-delete a capture and every row that references it (#95).

Today device/investigation "delete" is soft-archive only (see Device.archived).
Captures had no delete path at all — parsed facts stayed in SQLite forever,
including free-text that may still hold PII from before #96 scrubbing.
This module is the capture-scoped hard delete Knucklez approved for the
Nov 25 invite beta: remove the Capture row and every dependent fact/event/
link row keyed by capture_id.

Existing soft-deleted rows: there are no soft-deleted Capture rows (Capture
has no archived/deleted_at flag). Device/Investigation archive is unchanged
and is not purged here. No startup migration wipe; no Render DB touch.
"""
from __future__ import annotations

from sqlalchemy import Table
from sqlmodel import Session, SQLModel, select

from app.models.db_models import Capture


def capture_id_tables() -> list[Table]:
    """Every SQLAlchemy table with a capture_id column (not Capture itself).

    Discovered from SQLModel.metadata so a newly added fact table is
    included automatically — the exact miss the Device.archived comment
    warned about for hand-rolled cascade lists.
    """
    # Ensure models are registered (idempotent).
    from app.models import db_models  # noqa: F401

    tables: list[Table] = []
    for table in SQLModel.metadata.sorted_tables:
        if table.name == "capture":
            continue
        if "capture_id" in table.c:
            tables.append(table)
    return tables


def tables_referencing_capture(session: Session, capture_id: int) -> list[str]:
    """Return table names that still have at least one row for capture_id."""
    remaining: list[str] = []
    for table in capture_id_tables():
        row = session.execute(
            table.select().where(table.c.capture_id == capture_id).limit(1)
        ).first()
        if row is not None:
            remaining.append(table.name)
    if session.get(Capture, capture_id) is not None:
        remaining.append("capture")
    return remaining


def hard_delete_capture(session: Session, capture_id: int) -> bool:
    """Remove a capture and all capture_id-keyed dependents from ParseCat's
    database.

    This is logical removal from the live database; combined with
    PRAGMA secure_delete=ON (see app.db) the freed pages are zeroed on disk.
    It is NOT a guarantee about data outside the live DB: SQLite WAL/journal
    files and any external backups or snapshots may still retain old pages
    until they roll over or are themselves purged.

    Returns False if the capture id is unknown (caller maps to 404).
    Commits on success.
    """
    capture = session.get(Capture, capture_id)
    if capture is None:
        return False

    for table in capture_id_tables():
        session.execute(table.delete().where(table.c.capture_id == capture_id))
    session.delete(capture)
    session.commit()
    return True
