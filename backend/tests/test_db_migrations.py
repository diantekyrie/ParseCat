"""Arch review on #123: Device.label / Investigation.label used to be
globally unique (pre-per-owner ownership, see Device.owner_user_id).
create_all() never alters an EXISTING table, so on any DB that predates
this PR, the old global UNIQUE index on label alone stayed enforced even
after the model moved to per-(owner_user_id, label) uniqueness -- two
different users picking the same device label would hit the stale global
constraint and 500 on upload. Reproduces that against a hand-built
legacy-shaped SQLite DB (not create_all()'s own output, which is already
correct), then confirms init_db()'s migration fixes it.
"""
from __future__ import annotations

import sqlalchemy
from sqlalchemy import text
from sqlmodel import Session, create_engine

from app import db as db_module


def _build_legacy_schema(engine):
    """Device/investigation exactly as shaped on `main` before per-owner
    ownership: a global UNIQUE index on label, no owner_user_id column.
    `archived` is included since that migration shipped before this one;
    `user`/`refreshtoken`/`userbyokkey` are created via the real metadata
    further down since they're unaffected by this migration.
    """
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE device ("
            "id INTEGER PRIMARY KEY, label VARCHAR NOT NULL, "
            "created_at VARCHAR NOT NULL, archived BOOLEAN NOT NULL DEFAULT 0"
            ")"
        ))
        conn.execute(text("CREATE UNIQUE INDEX ix_device_label ON device (label)"))
        conn.execute(text(
            "CREATE TABLE investigation ("
            "id INTEGER PRIMARY KEY, label VARCHAR NOT NULL, "
            "created_at VARCHAR NOT NULL, archived BOOLEAN NOT NULL DEFAULT 0"
            ")"
        ))
        conn.execute(text("CREATE UNIQUE INDEX ix_investigation_label ON investigation (label)"))


def _legacy_engine():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    _build_legacy_schema(engine)
    return engine


def test_legacy_global_unique_label_blocks_two_owners_before_migration():
    """Confirms the bug is real on the hand-built legacy schema, before
    init_db() ever touches it -- if this didn't raise, the rest of this
    file would be testing a problem that doesn't exist."""
    engine = _legacy_engine()
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO device (label, created_at, archived) VALUES ('work phone', 'x', 0)"
        ))
        try:
            conn.execute(text(
                "INSERT INTO device (label, created_at, archived) VALUES ('work phone', 'x', 0)"
            ))
            raised = False
        except sqlalchemy.exc.IntegrityError:
            raised = True
    assert raised, "legacy schema should reject a second global 'work phone' label"


def test_init_db_migration_lets_two_owners_share_a_label(monkeypatch):
    engine = _legacy_engine()
    monkeypatch.setattr(db_module, "engine", engine)

    db_module.init_db()  # must not raise on a legacy-shaped DB

    with Session(engine) as session:
        session.exec(text(
            "INSERT INTO device (label, created_at, archived, owner_user_id) "
            "VALUES ('work phone', 'x', 0, 1)"
        ))
        # Same label, DIFFERENT owner -- must now succeed. This is the
        # exact scenario Arch reproduced failing before the migration.
        session.exec(text(
            "INSERT INTO device (label, created_at, archived, owner_user_id) "
            "VALUES ('work phone', 'x', 0, 2)"
        ))
        session.commit()

        rows = session.exec(text("SELECT owner_user_id FROM device WHERE label = 'work phone'")).all()
    assert {r[0] for r in rows} == {1, 2}


def test_init_db_migration_still_rejects_same_owner_duplicate_label(monkeypatch):
    engine = _legacy_engine()
    monkeypatch.setattr(db_module, "engine", engine)
    db_module.init_db()

    with Session(engine) as session:
        session.exec(text(
            "INSERT INTO device (label, created_at, archived, owner_user_id) "
            "VALUES ('work phone', 'x', 0, 1)"
        ))
        session.commit()

    raised = False
    with engine.begin() as conn:
        try:
            conn.execute(text(
                "INSERT INTO device (label, created_at, archived, owner_user_id) "
                "VALUES ('work phone', 'x', 0, 1)"
            ))
        except sqlalchemy.exc.IntegrityError:
            raised = True
    assert raised, "the SAME owner reusing a label must still be rejected"


def test_init_db_migration_is_idempotent_on_an_already_migrated_db(monkeypatch):
    engine = _legacy_engine()
    monkeypatch.setattr(db_module, "engine", engine)

    db_module.init_db()
    db_module.init_db()  # must not raise the second time (e.g. "index already exists")

    with Session(engine) as session:
        session.exec(text(
            "INSERT INTO device (label, created_at, archived, owner_user_id) "
            "VALUES ('idempotent-check', 'x', 0, 7)"
        ))
        session.commit()
        rows = session.exec(text("SELECT owner_user_id FROM device WHERE label = 'idempotent-check'")).all()
    assert [r[0] for r in rows] == [7]


def test_fresh_db_migration_is_a_true_no_op(monkeypatch):
    """A brand-new DB (created entirely by create_all(), never through the
    legacy path) must not be touched or broken by the migration -- it's
    already correct (owner-scoped uniqueness enforced via the model's own
    UniqueConstraint)."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    monkeypatch.setattr(db_module, "engine", engine)

    db_module.init_db()  # create_all() builds the fresh, already-correct schema

    with Session(engine) as session:
        session.exec(text(
            "INSERT INTO device (label, created_at, archived, owner_user_id) "
            "VALUES ('fresh-device', '2026-01-01T00:00:00+00:00', 0, 1)"
        ))
        session.exec(text(
            "INSERT INTO device (label, created_at, archived, owner_user_id) "
            "VALUES ('fresh-device', '2026-01-01T00:00:00+00:00', 0, 2)"
        ))
        session.commit()
        rows = session.exec(text("SELECT owner_user_id FROM device WHERE label = 'fresh-device'")).all()
    assert {r[0] for r in rows} == {1, 2}
