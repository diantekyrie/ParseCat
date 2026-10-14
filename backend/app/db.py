from __future__ import annotations

from sqlalchemy import text
from sqlmodel import SQLModel, Session, create_engine

DATABASE_URL = "sqlite:///./parsecat.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

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
