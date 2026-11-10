from __future__ import annotations

from sqlalchemy import event, text
from sqlmodel import SQLModel, Session, create_engine

DATABASE_URL = "sqlite:///./parsecat.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


# Capture hard-delete (#95) is meant to actually get PII-bearing free-text off
# disk, not just unlink it from the live tables. By default SQLite leaves the
# old bytes sitting in freed pages until they're reused, so a deleted capture's
# content can linger in the database file. PRAGMA secure_delete=ON makes SQLite
# zero out freed pages as part of the DELETE, so hard_delete_capture's freed
# pages hold zeros rather than stale rows. It applies per-connection, so set it
# on every connect. (This is about the live DB file only -- WAL/journal files
# and external backups are out of scope; see hard_delete_capture's docstring.)
@event.listens_for(engine, "connect")
def _enable_secure_delete(dbapi_connection, connection_record):  # noqa: ANN001
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA secure_delete=ON")
    finally:
        cursor.close()

# No migration framework in this project (no Alembic) -- create_all() only
# creates tables that don't exist yet, it never alters an existing table to
# add a new column. Any real parsecat.db already on disk (with real devices/
# captures in it) would otherwise raise "no such column: device.archived" on
# the very first query. (table, column, sqlite type) added here get an
# idempotent `ALTER TABLE ... ADD COLUMN` if the column is missing.
_COLUMN_MIGRATIONS = [
    ("device", "archived", "BOOLEAN NOT NULL DEFAULT 0"),
    ("investigation", "archived", "BOOLEAN NOT NULL DEFAULT 0"),
    ("device", "owner_user_id", "INTEGER"),
    ("investigation", "owner_user_id", "INTEGER"),
    # Msg5: BT HCI auth/encrypt/link-key events + SourceRef + severity/confidence
    ("bthcieventrow", "encryption_enabled", "INTEGER"),
    ("bthcieventrow", "key_type", "INTEGER"),
    ("bthcieventrow", "source_section", "VARCHAR"),
    ("bthcieventrow", "source_line_start", "INTEGER"),
    ("bthcieventrow", "source_line_end", "INTEGER"),
    ("bthcieventrow", "severity", "VARCHAR"),
    ("bthcieventrow", "confidence", "VARCHAR"),
]


def _run_column_migrations() -> None:
    with engine.begin() as conn:
        for table, column, coltype in _COLUMN_MIGRATIONS:
            existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            if column not in existing:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"))


def _backfill_orphaned_ownership() -> None:
    """Any device/investigation that predates the owner_user_id column (or
    was created before any account existed) has owner_user_id = NULL.
    Assigns those to whichever account has the lowest id -- there is no
    "correct" owner to infer for pre-existing data, but silently leaving it
    unownable (invisible to every per-user query forever) would be worse
    than picking one. A no-op once every row has an owner, and a no-op
    entirely until at least one account has been provisioned.
    """
    with engine.begin() as conn:
        first_user_id = conn.execute(text("SELECT id FROM user ORDER BY id LIMIT 1")).scalar()
        if first_user_id is None:
            return
        conn.execute(
            text("UPDATE device SET owner_user_id = :uid WHERE owner_user_id IS NULL"),
            {"uid": first_user_id},
        )
        conn.execute(
            text("UPDATE investigation SET owner_user_id = :uid WHERE owner_user_id IS NULL"),
            {"uid": first_user_id},
        )


def init_db() -> None:
    # Import models so their tables register with SQLModel.metadata before create_all.
    from app.models import db_models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    _run_column_migrations()

    from app.auth import provision_bootstrap_users

    with Session(engine) as session:
        provision_bootstrap_users(session)
    _backfill_orphaned_ownership()


def get_session():
    with Session(engine) as session:
        yield session
