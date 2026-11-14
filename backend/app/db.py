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


def _unique_indexes_covering(conn, table: str) -> dict[tuple[str, ...], str]:
    """Maps each UNIQUE index on `table` to the exact tuple of columns it
    covers, e.g. {("label",): "ix_device_label"} or
    {("owner_user_id", "label"): "sqlite_autoindex_device_1"}. Column order
    matches PRAGMA index_info's own ordering (declaration order), so this
    correctly recognizes an inline `UniqueConstraint`'s auto-named SQLite
    index as covering the same columns a hand-written CREATE UNIQUE INDEX
    would, regardless of what either happens to be named.
    """
    out: dict[tuple[str, ...], str] = {}
    for row in conn.execute(text(f"PRAGMA index_list({table})")):
        _seq, name, unique, _origin, _partial = row
        if not unique:
            continue
        info = sorted(conn.execute(text(f"PRAGMA index_info({name})")), key=lambda r: r[0])
        out[tuple(r[2] for r in info)] = name
    return out


# Device.label / Investigation.label used to be globally unique (before
# per-owner ownership existed -- see Device.owner_user_id). create_all()
# never alters an EXISTING table, so on any DB that predates this PR, the
# old global UNIQUE index on label alone is still enforced even though the
# model now declares uniqueness per (owner_user_id, label) instead: two
# different users picking the same device label (e.g. "work phone") hits
# the stale global constraint and 500s on upload (Arch review on #123,
# reproduced against a legacy-shaped DB). Each tuple is
# (table, the old globally-unique column, the new per-owner column tuple,
# a name for the new unique index if one needs creating).
_LABEL_OWNERSHIP_INDEX_MIGRATIONS = [
    ("device", "label", ("owner_user_id", "label"), "uq_device_owner_label"),
    ("investigation", "label", ("owner_user_id", "label"), "uq_investigation_owner_label"),
]


def _run_label_ownership_index_migrations() -> None:
    """Drops the legacy single-column unique index on `label` (recreating
    it non-unique, matching exactly what create_all() produces for a fresh
    table) and ensures a unique index on (owner_user_id, label) exists.
    Detects both shapes by the COLUMNS a unique index covers, not by name,
    so this is idempotent and a true no-op on a DB that's already correct
    (fresh, or previously migrated) -- safe to run on every startup.

    The drop path (DROP INDEX) assumes the legacy unique index is a
    standalone one, e.g. from Field(index=True, unique=True) -- which is
    the only shape `main` has ever produced for `label`. SQLite refuses to
    drop a `sqlite_autoindex_*` backing an inline UNIQUE constraint, so if
    a legacy DB ever had `label` unique that way instead, this would raise
    inside init_db() (Arch review on #123's re-review of 30a373f).
    """
    with engine.begin() as conn:
        for table, legacy_col, owner_cols, new_index_name in _LABEL_OWNERSHIP_INDEX_MIGRATIONS:
            unique_indexes = _unique_indexes_covering(conn, table)
            legacy_name = unique_indexes.get((legacy_col,))
            if legacy_name is not None:
                conn.execute(text(f"DROP INDEX {legacy_name}"))
                conn.execute(text(f"CREATE INDEX {legacy_name} ON {table} ({legacy_col})"))
                unique_indexes = _unique_indexes_covering(conn, table)
            if owner_cols not in unique_indexes:
                cols_sql = ", ".join(owner_cols)
                conn.execute(text(f"CREATE UNIQUE INDEX {new_index_name} ON {table} ({cols_sql})"))


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
    _run_label_ownership_index_migrations()

    from app.auth import provision_bootstrap_users

    with Session(engine) as session:
        provision_bootstrap_users(session)
    _backfill_orphaned_ownership()


def get_session():
    with Session(engine) as session:
        yield session
