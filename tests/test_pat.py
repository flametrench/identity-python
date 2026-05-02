# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Tests for the v0.3 personal access token primitive (ADR 0016).

Covers both InMemoryIdentityStore (always run) and PostgresIdentityStore
(gated on IDENTITY_POSTGRES_URL — same pattern as test_postgres.py).
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import pytest
from flametrench_ids import generate

from flametrench_identity import (
    InMemoryIdentityStore,
    InvalidPatTokenError,
    NotFoundError,
    PatExpiredError,
    PatRevokedError,
    PatStatus,
    PreconditionError,
)
from flametrench_identity.errors import AlreadyTerminalError

POSTGRES_URL = os.environ.get("IDENTITY_POSTGRES_URL")

if POSTGRES_URL is not None:
    import psycopg

    from flametrench_identity.postgres import PostgresIdentityStore

SCHEMA_SQL = Path(__file__).parent.joinpath("postgres-schema.sql").read_text()


# ─── In-memory tests ──────────────────────────────────────────────


class _Clock:
    """Mutable wall-clock test fixture (so tests can advance time)."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def advance(self, **kwargs: int) -> None:
        self.now = self.now + timedelta(**kwargs)


@pytest.fixture
def clock() -> _Clock:
    return _Clock(datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc))


@pytest.fixture
def in_memory(clock: _Clock) -> InMemoryIdentityStore:
    # coalesce=0 in default test store so most assertions don't fight
    # the 60s window. Coalescing-specific tests instantiate their own.
    return InMemoryIdentityStore(
        clock=lambda: clock.now,
        pat_last_used_coalesce_seconds=0,
    )


def test_in_memory_create_pat_returns_record_and_token(
    in_memory: InMemoryIdentityStore,
) -> None:
    u = in_memory.create_user()
    pat, token = in_memory.create_pat(u.id, "laptop-cli", ["repo:read"])
    assert re.fullmatch(r"pat_[0-9a-f]{32}", pat.id)
    assert pat.name == "laptop-cli"
    assert pat.scope == ["repo:read"]
    assert pat.status is PatStatus.ACTIVE
    assert pat.last_used_at is None
    assert pat.expires_at is None
    assert re.fullmatch(r"pat_[0-9a-f]{32}_[A-Za-z0-9_-]+", token)
    # The id segment in the token must match the row's id.
    assert token[4:36] == pat.id[4:]


def test_in_memory_create_pat_rejects_empty_name(
    in_memory: InMemoryIdentityStore,
) -> None:
    u = in_memory.create_user()
    with pytest.raises(PreconditionError):
        in_memory.create_pat(u.id, "", [])


def test_in_memory_create_pat_rejects_long_name(
    in_memory: InMemoryIdentityStore,
) -> None:
    u = in_memory.create_user()
    with pytest.raises(PreconditionError):
        in_memory.create_pat(u.id, "x" * 121, [])


def test_in_memory_create_pat_rejects_past_expiry(
    in_memory: InMemoryIdentityStore,
) -> None:
    u = in_memory.create_user()
    with pytest.raises(PreconditionError):
        in_memory.create_pat(
            u.id,
            "cli",
            [],
            expires_at=datetime(2026, 4, 1, tzinfo=timezone.utc),
        )


def test_in_memory_create_pat_refuses_revoked_user(
    in_memory: InMemoryIdentityStore,
) -> None:
    u = in_memory.create_user()
    in_memory.revoke_user(u.id)
    with pytest.raises(AlreadyTerminalError):
        in_memory.create_pat(u.id, "cli", [])


def test_in_memory_verify_pat_token_happy_path(
    in_memory: InMemoryIdentityStore,
) -> None:
    u = in_memory.create_user()
    pat, token = in_memory.create_pat(u.id, "cli", ["admin"])
    verified = in_memory.verify_pat_token(token)
    assert verified.pat_id == pat.id
    assert verified.usr_id == u.id
    assert verified.scope == ["admin"]


def test_in_memory_verify_updates_last_used_at_when_coalesce_zero(
    in_memory: InMemoryIdentityStore, clock: _Clock,
) -> None:
    u = in_memory.create_user()
    pat, token = in_memory.create_pat(u.id, "cli", [])
    assert pat.last_used_at is None

    clock.advance(seconds=5)
    in_memory.verify_pat_token(token)
    reread = in_memory.get_pat(pat.id)
    assert reread.last_used_at == clock.now


def test_in_memory_verify_throws_invalid_for_malformed_bearer(
    in_memory: InMemoryIdentityStore,
) -> None:
    with pytest.raises(InvalidPatTokenError):
        in_memory.verify_pat_token("not-a-pat")


def test_in_memory_verify_throws_invalid_for_non_pat_prefix(
    in_memory: InMemoryIdentityStore,
) -> None:
    with pytest.raises(InvalidPatTokenError):
        in_memory.verify_pat_token("shr_" + "a" * 32 + "_secretvalue")


def test_in_memory_verify_throws_invalid_for_missing_row(
    in_memory: InMemoryIdentityStore,
) -> None:
    """Token-presence timing-oracle defense: missing-row and wrong-secret
    cases conflate to InvalidPatTokenError."""
    with pytest.raises(InvalidPatTokenError):
        in_memory.verify_pat_token("pat_" + "a" * 32 + "_anysecret")


def test_in_memory_verify_throws_invalid_for_wrong_secret(
    in_memory: InMemoryIdentityStore,
) -> None:
    u = in_memory.create_user()
    pat, _ = in_memory.create_pat(u.id, "cli", [])
    id_hex = pat.id[4:]
    with pytest.raises(InvalidPatTokenError):
        in_memory.verify_pat_token(f"pat_{id_hex}_wrongSecret")


def test_in_memory_verify_throws_revoked_before_expiry_check(
    in_memory: InMemoryIdentityStore,
) -> None:
    u = in_memory.create_user()
    pat, token = in_memory.create_pat(
        u.id, "cli", [], expires_at=datetime(2026, 6, 1, tzinfo=timezone.utc)
    )
    in_memory.revoke_pat(pat.id)
    with pytest.raises(PatRevokedError):
        in_memory.verify_pat_token(token)


def test_in_memory_verify_throws_expired_after_expires_at(
    in_memory: InMemoryIdentityStore, clock: _Clock,
) -> None:
    u = in_memory.create_user()
    _, token = in_memory.create_pat(
        u.id, "cli", [], expires_at=datetime(2026, 5, 1, 13, 0, tzinfo=timezone.utc)
    )
    clock.now = datetime(2026, 5, 2, tzinfo=timezone.utc)
    with pytest.raises(PatExpiredError):
        in_memory.verify_pat_token(token)


def test_in_memory_revoke_marks_status_revoked(
    in_memory: InMemoryIdentityStore, clock: _Clock,
) -> None:
    u = in_memory.create_user()
    pat, _ = in_memory.create_pat(u.id, "cli", [])
    revoked = in_memory.revoke_pat(pat.id)
    assert revoked.status is PatStatus.REVOKED
    assert revoked.revoked_at == clock.now


def test_in_memory_revoke_is_idempotent(
    in_memory: InMemoryIdentityStore, clock: _Clock,
) -> None:
    u = in_memory.create_user()
    pat, _ = in_memory.create_pat(u.id, "cli", [])
    first = in_memory.revoke_pat(pat.id)
    clock.advance(hours=1)
    second = in_memory.revoke_pat(pat.id)
    assert second.revoked_at == first.revoked_at


def test_in_memory_revoke_unknown_raises_not_found(
    in_memory: InMemoryIdentityStore,
) -> None:
    with pytest.raises(NotFoundError):
        in_memory.revoke_pat(generate("pat"))


def test_in_memory_list_pats_id_ordered(in_memory: InMemoryIdentityStore) -> None:
    alice = in_memory.create_user()
    bob = in_memory.create_user()
    a1, _ = in_memory.create_pat(alice.id, "a-1", [])
    time.sleep(0.002)
    a2, _ = in_memory.create_pat(alice.id, "a-2", [])
    in_memory.create_pat(bob.id, "bob-1", [])

    page = in_memory.list_pats_for_user(alice.id)
    assert len(page.data) == 2
    assert page.data[0].id == a1.id
    assert page.data[1].id == a2.id
    assert page.next_cursor is None


def test_in_memory_list_pats_filters_by_status(
    in_memory: InMemoryIdentityStore,
) -> None:
    u = in_memory.create_user()
    live, _ = in_memory.create_pat(u.id, "live", [])
    rev, _ = in_memory.create_pat(u.id, "rev", [])
    in_memory.revoke_pat(rev.id)

    active_only = in_memory.list_pats_for_user(u.id, status=PatStatus.ACTIVE)
    assert len(active_only.data) == 1
    assert active_only.data[0].id == live.id

    revoked_only = in_memory.list_pats_for_user(u.id, status=PatStatus.REVOKED)
    assert len(revoked_only.data) == 1
    assert revoked_only.data[0].id == rev.id


def test_in_memory_list_pats_paginates(in_memory: InMemoryIdentityStore) -> None:
    u = in_memory.create_user()
    ids = []
    for i in range(5):
        time.sleep(0.002)
        pat, _ = in_memory.create_pat(u.id, f"p{i}", [])
        ids.append(pat.id)
    ids.sort()

    first = in_memory.list_pats_for_user(u.id, limit=2)
    assert len(first.data) == 2
    assert first.next_cursor is not None
    second = in_memory.list_pats_for_user(u.id, cursor=first.next_cursor, limit=2)
    assert len(second.data) == 2
    assert second.data[0].id == ids[2]


def test_in_memory_last_used_at_coalesces_within_window(clock: _Clock) -> None:
    store = InMemoryIdentityStore(
        clock=lambda: clock.now,
        pat_last_used_coalesce_seconds=60,
    )
    u = store.create_user()
    pat, token = store.create_pat(u.id, "cli", [])

    clock.advance(seconds=5)
    store.verify_pat_token(token)
    after_first = store.get_pat(pat.id).last_used_at

    clock.advance(seconds=10)  # 15s in — within 60s window
    store.verify_pat_token(token)
    after_second = store.get_pat(pat.id).last_used_at

    assert after_second == after_first


def test_in_memory_last_used_at_updates_after_window(clock: _Clock) -> None:
    store = InMemoryIdentityStore(
        clock=lambda: clock.now,
        pat_last_used_coalesce_seconds=60,
    )
    u = store.create_user()
    pat, token = store.create_pat(u.id, "cli", [])

    clock.advance(seconds=5)
    store.verify_pat_token(token)
    after_first = store.get_pat(pat.id).last_used_at

    clock.advance(seconds=90)  # 95s in — past 60s window
    store.verify_pat_token(token)
    after_second = store.get_pat(pat.id).last_used_at

    assert after_second != after_first
    assert after_second == clock.now


# ─── Postgres tests (skipped without IDENTITY_POSTGRES_URL) ──────


pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="IDENTITY_POSTGRES_URL not set; PostgresIdentityStore tests skipped.",
)


@pytest.fixture
def conn() -> Iterator[Any]:
    assert POSTGRES_URL is not None
    c = psycopg.connect(POSTGRES_URL, autocommit=False)
    try:
        with c.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            cur.execute(SCHEMA_SQL)
        c.commit()
        yield c
    finally:
        c.close()


@pytest.fixture
def pg_store(conn: Any, clock: _Clock) -> "PostgresIdentityStore":
    return PostgresIdentityStore(
        conn,
        clock=lambda: clock.now,
        pat_last_used_coalesce_seconds=0,
    )


def test_pg_create_pat_persists_row(pg_store: "PostgresIdentityStore") -> None:
    u = pg_store.create_user()
    pat, token = pg_store.create_pat(u.id, "laptop-cli", ["repo:read"])
    assert re.fullmatch(r"pat_[0-9a-f]{32}", pat.id)
    assert pat.name == "laptop-cli"
    assert pat.scope == ["repo:read"]
    assert pat.status is PatStatus.ACTIVE
    assert re.fullmatch(r"pat_[0-9a-f]{32}_[A-Za-z0-9_-]+", token)


def test_pg_create_pat_rejects_revoked_user(
    pg_store: "PostgresIdentityStore",
) -> None:
    u = pg_store.create_user()
    pg_store.revoke_user(u.id)
    with pytest.raises(AlreadyTerminalError):
        pg_store.create_pat(u.id, "cli", [])


def test_pg_verify_returns_verified(pg_store: "PostgresIdentityStore") -> None:
    u = pg_store.create_user()
    pat, token = pg_store.create_pat(u.id, "cli", ["admin"])
    verified = pg_store.verify_pat_token(token)
    assert verified.pat_id == pat.id
    assert verified.usr_id == u.id
    assert verified.scope == ["admin"]


def test_pg_verify_throws_invalid_for_missing_row(
    pg_store: "PostgresIdentityStore",
) -> None:
    with pytest.raises(InvalidPatTokenError):
        pg_store.verify_pat_token("pat_" + "a" * 32 + "_anysecret")


def test_pg_verify_throws_invalid_for_wrong_secret(
    pg_store: "PostgresIdentityStore",
) -> None:
    u = pg_store.create_user()
    pat, _ = pg_store.create_pat(u.id, "cli", [])
    id_hex = pat.id[4:]
    with pytest.raises(InvalidPatTokenError):
        pg_store.verify_pat_token(f"pat_{id_hex}_wrongSecret")


def test_pg_verify_throws_revoked_first(pg_store: "PostgresIdentityStore") -> None:
    u = pg_store.create_user()
    pat, token = pg_store.create_pat(
        u.id, "cli", [], expires_at=datetime(2026, 6, 1, tzinfo=timezone.utc)
    )
    pg_store.revoke_pat(pat.id)
    with pytest.raises(PatRevokedError):
        pg_store.verify_pat_token(token)


def test_pg_verify_throws_expired(
    pg_store: "PostgresIdentityStore", clock: _Clock,
) -> None:
    u = pg_store.create_user()
    _, token = pg_store.create_pat(
        u.id, "cli", [], expires_at=datetime(2026, 5, 1, 13, 0, tzinfo=timezone.utc)
    )
    clock.now = datetime(2026, 5, 2, tzinfo=timezone.utc)
    with pytest.raises(PatExpiredError):
        pg_store.verify_pat_token(token)


def test_pg_revoke_idempotent(
    pg_store: "PostgresIdentityStore", clock: _Clock,
) -> None:
    u = pg_store.create_user()
    pat, _ = pg_store.create_pat(u.id, "cli", [])
    first = pg_store.revoke_pat(pat.id)
    clock.advance(hours=1)
    second = pg_store.revoke_pat(pat.id)
    assert second.revoked_at == first.revoked_at


def test_pg_revoke_unknown_not_found(
    pg_store: "PostgresIdentityStore",
) -> None:
    with pytest.raises(NotFoundError):
        pg_store.revoke_pat(generate("pat"))


def test_pg_list_pats_filters_by_status(
    pg_store: "PostgresIdentityStore",
) -> None:
    u = pg_store.create_user()
    live, _ = pg_store.create_pat(u.id, "live", [])
    rev, _ = pg_store.create_pat(u.id, "rev", [])
    pg_store.revoke_pat(rev.id)

    active_only = pg_store.list_pats_for_user(u.id, status=PatStatus.ACTIVE)
    assert len(active_only.data) == 1
    assert active_only.data[0].id == live.id


def test_pg_coalesces_last_used_at_within_window(
    conn: Any, clock: _Clock,
) -> None:
    store = PostgresIdentityStore(
        conn,
        clock=lambda: clock.now,
        pat_last_used_coalesce_seconds=60,
    )
    u = store.create_user()
    pat, token = store.create_pat(u.id, "cli", [])

    clock.advance(seconds=5)
    store.verify_pat_token(token)
    after_first = store.get_pat(pat.id).last_used_at

    clock.advance(seconds=10)
    store.verify_pat_token(token)
    after_second = store.get_pat(pat.id).last_used_at
    assert after_second == after_first

    clock.advance(seconds=90)
    store.verify_pat_token(token)
    after_third = store.get_pat(pat.id).last_used_at
    assert after_third != after_first


def test_pg_cooperates_with_outer_transaction_via_savepoint(
    conn: Any, clock: _Clock,
) -> None:
    """ADR 0013 — psycopg3's transaction() context auto-uses savepoints
    when nested. This test wraps multiple PAT operations in one outer
    transaction and confirms they atomic-commit together."""
    store = PostgresIdentityStore(
        conn,
        clock=lambda: clock.now,
        pat_last_used_coalesce_seconds=0,
    )
    u = store.create_user()
    with conn.transaction():
        pat, _ = store.create_pat(u.id, "cli", [])
        store.revoke_pat(pat.id)
    reread = store.get_pat(pat.id)
    assert reread.status is PatStatus.REVOKED
