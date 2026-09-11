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
]


def _run_column_migrations() -> None:
    with engine.begin() as conn:
        for table, column, coltype in _COLUMN_MIGRATIONS:
            existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            if column not in existing:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"))


def init_db() -> None:
    # Import models so their tables register with SQLModel.metadata before create_all.
    from app.models import db_models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    _run_column_migrations()


def get_session():
    with Session(engine) as session:
        yield session
