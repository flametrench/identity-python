# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""TOTP replay protection, user-status gates and recovery re-enrollment.

Each behaviour runs against InMemoryIdentityStore and, when
IDENTITY_POSTGRES_URL is set, PostgresIdentityStore. PAT tests are
in-memory only: PostgresIdentityStore has no PAT methods.

Every refusal is paired with a check that the refused call changed
nothing.
"""

from __future__ import annotations

import base64
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import pytest

import flametrench_identity.in_memory as in_memory_mod
import flametrench_identity.postgres as postgres_mod
from flametrench_identity import InMemoryIdentityStore
from flametrench_identity.errors import (
    InvalidCredentialError,
    InvalidPatTokenError,
    PatRevokedError,
    PreconditionError,
    ReplayedTotpError,
)
from flametrench_identity.mfa import (
    FactorStatus,
    FactorType,
    RecoveryProof,
    TotpProof,
    totp_compute,
    totp_match_step,
)
from flametrench_identity.types import Status

POSTGRES_URL = os.environ.get("IDENTITY_POSTGRES_URL")
SCHEMA_SQL = Path(__file__).parent.joinpath("postgres-schema.sql").read_text()

PASSWORD = "long-enough-password-for-floor"
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)

    @property
    def ts(self) -> int:
        return int(self.now.timestamp())


def _connect() -> Any:
    import psycopg

    assert POSTGRES_URL is not None
    return psycopg.connect(POSTGRES_URL, autocommit=False)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def pg_conn() -> Iterator[Any]:
    if POSTGRES_URL is None:
        pytest.skip("IDENTITY_POSTGRES_URL not set; PostgresIdentityStore tests skipped.")
    c = _connect()
    try:
        with c.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            cur.execute(SCHEMA_SQL)
        c.commit()
        yield c
    finally:
        c.close()


@pytest.fixture(params=["memory", "postgres"])
def store(request: Any, clock: Clock) -> Any:
    if request.param == "memory":
        return InMemoryIdentityStore(clock=clock)
    conn = request.getfixturevalue("pg_conn")
    return postgres_mod.PostgresIdentityStore(conn, clock=clock)


def _secret(b32: str) -> bytes:
    return base64.b32decode(b32 + "=" * (-len(b32) % 8))


def _active_totp(store: Any, clock: Clock) -> tuple[str, str, bytes]:
    """Enroll + confirm a TOTP factor at T0; return (usr_id, mfa_id, secret)."""
    user = store.create_user()
    enroll = store.enroll_totp_factor(user.id, "iPhone")
    secret = _secret(enroll.secret_b32)
    store.confirm_totp_factor(enroll.factor.id, totp_compute(secret, clock.ts))
    return user.id, enroll.factor.id, secret


def _code(secret: bytes, clock: Clock, offset_steps: int = 0) -> str:
    return totp_compute(secret, clock.ts + 30 * offset_steps)


def _last_step(store: Any, mfa_id: str) -> int | None:
    if isinstance(store, InMemoryIdentityStore):
        return store._mfa_totp_last_step.get(mfa_id)
    with store._conn.cursor() as cur:
        cur.execute(
            "SELECT totp_last_accepted_step FROM mfa WHERE id = %s",
            (postgres_mod._wire_to_uuid(mfa_id),),
        )
        row = cur.fetchone()
    store._conn.commit()
    return None if row is None else row[0]


# ─── totp_match_step ───


def test_totp_match_step_returns_matched_window() -> None:
    secret = b"12345678901234567890"
    ts = 1_700_000_000
    assert totp_match_step(secret, totp_compute(secret, ts), timestamp=ts) == ts // 30
    assert totp_match_step(secret, totp_compute(secret, ts - 30), timestamp=ts) == ts // 30 - 1
    assert totp_match_step(secret, totp_compute(secret, ts + 30), timestamp=ts) == ts // 30 + 1
    assert totp_match_step(secret, totp_compute(secret, ts + 60), timestamp=ts) is None
    assert totp_match_step(secret, "abcdef", timestamp=ts) is None


# ─── TOTP replay (ADR 0008 §verifyMfa) ───


def test_replayed_totp_error_is_an_invalid_credential() -> None:
    assert issubclass(ReplayedTotpError, InvalidCredentialError)
    assert ReplayedTotpError().code == "unauthorized.totp_replayed"


def test_confirm_records_step_and_its_code_cannot_verify(store: Any, clock: Clock) -> None:
    usr_id, mfa_id, secret = _active_totp(store, clock)
    assert _last_step(store, mfa_id) == clock.ts // 30
    with pytest.raises(ReplayedTotpError):
        store.verify_mfa(usr_id, TotpProof(code=_code(secret, clock)))


def test_same_code_same_step_second_use_rejected(store: Any, clock: Clock) -> None:
    usr_id, mfa_id, secret = _active_totp(store, clock)
    clock.advance(60)
    code = _code(secret, clock)
    assert store.verify_mfa(usr_id, TotpProof(code=code)).mfa_id == mfa_id
    step = _last_step(store, mfa_id)
    with pytest.raises(ReplayedTotpError):
        store.verify_mfa(usr_id, TotpProof(code=code))
    # The refused verify changed nothing.
    assert _last_step(store, mfa_id) == step


def test_consumed_code_replayed_in_next_step_rejected(store: Any, clock: Clock) -> None:
    usr_id, _, secret = _active_totp(store, clock)
    clock.advance(60)
    code_n = _code(secret, clock)
    store.verify_mfa(usr_id, TotpProof(code=code_n))
    clock.advance(30)
    store.verify_mfa(usr_id, TotpProof(code=_code(secret, clock)))
    # code_n is still inside the ±1 drift window at step N+1.
    with pytest.raises(ReplayedTotpError):
        store.verify_mfa(usr_id, TotpProof(code=code_n))


def test_older_unused_step_rejected_after_newer_accepted(store: Any, clock: Clock) -> None:
    usr_id, _, secret = _active_totp(store, clock)
    clock.advance(60)
    store.verify_mfa(usr_id, TotpProof(code=_code(secret, clock, +1)))
    with pytest.raises(ReplayedTotpError):
        store.verify_mfa(usr_id, TotpProof(code=_code(secret, clock)))


def test_next_step_code_accepted(store: Any, clock: Clock) -> None:
    usr_id, mfa_id, secret = _active_totp(store, clock)
    clock.advance(60)
    store.verify_mfa(usr_id, TotpProof(code=_code(secret, clock)))
    clock.advance(30)
    store.verify_mfa(usr_id, TotpProof(code=_code(secret, clock)))
    assert _last_step(store, mfa_id) == clock.ts // 30


def test_replay_refusal_does_not_lock_the_factor(store: Any, clock: Clock) -> None:
    usr_id, _, secret = _active_totp(store, clock)
    clock.advance(60)
    code = _code(secret, clock)
    store.verify_mfa(usr_id, TotpProof(code=code))
    with pytest.raises(ReplayedTotpError):
        store.verify_mfa(usr_id, TotpProof(code=code))
    clock.advance(30)
    store.verify_mfa(usr_id, TotpProof(code=_code(secret, clock)))


def test_wrong_code_is_invalid_not_replayed_and_changes_nothing(
    store: Any, clock: Clock
) -> None:
    usr_id, mfa_id, secret = _active_totp(store, clock)
    clock.advance(60)
    good = _code(secret, clock)
    bad = f"{(int(good) + 1) % 1_000_000:06d}"
    with pytest.raises(InvalidCredentialError) as exc:
        store.verify_mfa(usr_id, TotpProof(code=bad))
    assert type(exc.value) is InvalidCredentialError
    assert _last_step(store, mfa_id) == T0.timestamp() // 30
    store.verify_mfa(usr_id, TotpProof(code=good))


def test_replay_state_is_per_factor(store: Any, clock: Clock) -> None:
    a_usr, _, a_secret = _active_totp(store, clock)
    b_usr, _, b_secret = _active_totp(store, clock)
    clock.advance(60)
    store.verify_mfa(a_usr, TotpProof(code=_code(a_secret, clock)))
    store.verify_mfa(b_usr, TotpProof(code=_code(b_secret, clock)))


def test_revoked_totp_factor_is_invalid_not_replayed(store: Any, clock: Clock) -> None:
    usr_id, mfa_id, secret = _active_totp(store, clock)
    store.revoke_mfa_factor(mfa_id)
    clock.advance(60)
    with pytest.raises(InvalidCredentialError) as exc:
        store.verify_mfa(usr_id, TotpProof(code=_code(secret, clock)))
    assert type(exc.value) is InvalidCredentialError


def test_postgres_concurrent_verifies_of_one_code_exactly_one_wins(
    pg_conn: Any, clock: Clock
) -> None:
    """Two connections verify the same code at once: the conditional
    UPDATE lets exactly one succeed."""
    setup = postgres_mod.PostgresIdentityStore(pg_conn, clock=clock)
    usr_id, _, secret = _active_totp(setup, clock)
    pg_conn.commit()  # make the factor visible to the racing connections

    rounds = 10
    for _ in range(rounds):
        clock.advance(30)
        code = _code(secret, clock)
        conns = [_connect(), _connect()]
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def attempt(conn: Any) -> None:
            s = postgres_mod.PostgresIdentityStore(conn, clock=clock)
            barrier.wait()
            try:
                s.verify_mfa(usr_id, TotpProof(code=code))
                result = "ok"
            except ReplayedTotpError:
                result = "replayed"
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=attempt, args=(c,)) for c in conns]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for c in conns:
            c.close()
        assert sorted(outcomes) == ["ok", "replayed"], outcomes


# ─── verifyPassword refuses a suspended user ───


def test_verify_password_suspended_refused_then_reinstated_ok(store: Any) -> None:
    user = store.create_user()
    cred = store.create_password_credential(user.id, "sus@example.com", PASSWORD)
    store.suspend_user(user.id)
    with pytest.raises(InvalidCredentialError) as exc:
        store.verify_password("sus@example.com", PASSWORD)
    assert type(exc.value) is InvalidCredentialError
    # Refusal changed nothing: user still suspended, credential still active.
    assert store.get_user(user.id).status == Status.SUSPENDED
    assert store.get_credential(cred.id).status == Status.ACTIVE
    store.reinstate_user(user.id)
    assert store.verify_password("sus@example.com", PASSWORD).usr_id == user.id


def test_verify_password_suspended_is_indistinguishable_from_bad_password(
    store: Any,
) -> None:
    user = store.create_user()
    store.create_password_credential(user.id, "sus2@example.com", PASSWORD)
    store.suspend_user(user.id)
    with pytest.raises(InvalidCredentialError) as suspended:
        store.verify_password("sus2@example.com", PASSWORD)
    with pytest.raises(InvalidCredentialError) as bad:
        store.verify_password("sus2@example.com", PASSWORD + "x")
    assert type(suspended.value) is type(bad.value)
    assert str(suspended.value) == str(bad.value)
    assert suspended.value.code == bad.value.code


def test_verify_password_checks_status_after_the_hash(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Security ruling: status is checked after the Argon2id verify, so a
    suspended user's correct password costs the same full hash."""
    user = store.create_user()
    store.create_password_credential(user.id, "sus3@example.com", PASSWORD)
    store.suspend_user(user.id)
    module = in_memory_mod if isinstance(store, InMemoryIdentityStore) else postgres_mod
    real = module.verify_password_hash
    calls: list[str] = []

    def spy(phc: str, pw: str) -> bool:
        ok = real(phc, pw)
        calls.append("match" if ok else "no-match")
        return ok

    monkeypatch.setattr(module, "verify_password_hash", spy)
    with pytest.raises(InvalidCredentialError):
        store.verify_password("sus3@example.com", PASSWORD)
    assert calls == ["match"]


# ─── Recovery re-enrollment (ADR 0008 §Verification flow) ───


def _active_recovery(store: Any, usr_id: str) -> list[Any]:
    return [
        f for f in store.list_mfa_factors(usr_id)
        if f.type == FactorType.RECOVERY and f.status == FactorStatus.ACTIVE
    ]


def test_recovery_re_enroll_after_exhaustion_replaces_set(store: Any) -> None:
    user = store.create_user()
    first = store.enroll_recovery_factor(user.id)
    for code in first.codes:
        store.verify_mfa(user.id, RecoveryProof(code=code))
    second = store.enroll_recovery_factor(user.id)
    assert second.factor.replaces == first.factor.id
    assert store.get_mfa_factor(first.factor.id).status == FactorStatus.REVOKED
    active = _active_recovery(store, user.id)
    assert [f.id for f in active] == [second.factor.id]
    assert store.verify_mfa(user.id, RecoveryProof(code=second.codes[0])).mfa_id == second.factor.id


def test_recovery_re_enroll_with_codes_left_refused_and_changes_nothing(
    store: Any,
) -> None:
    user = store.create_user()
    first = store.enroll_recovery_factor(user.id)
    for code in first.codes[:9]:
        store.verify_mfa(user.id, RecoveryProof(code=code))
    before = store.get_mfa_factor(first.factor.id)
    with pytest.raises(PreconditionError) as exc:
        store.enroll_recovery_factor(user.id)
    assert exc.value.reason == "active_singleton_exists"
    after = store.get_mfa_factor(first.factor.id)
    assert after.status == FactorStatus.ACTIVE
    assert [f.id for f in _active_recovery(store, user.id)] == [first.factor.id]
    assert len(store.list_mfa_factors(user.id)) == 1
    assert after.replaces == before.replaces
    # The last unused code of the original set still verifies.
    store.verify_mfa(user.id, RecoveryProof(code=first.codes[9]))


# ─── PATs: owner status (in-memory; PostgresIdentityStore has no PATs) ───


@pytest.fixture
def mem(clock: Clock) -> InMemoryIdentityStore:
    return InMemoryIdentityStore(clock=clock)


def test_verify_pat_suspended_owner_refused_then_reinstated_ok(
    mem: InMemoryIdentityStore, clock: Clock
) -> None:
    user = mem.create_user()
    created = mem.create_pat(user.id, "ci", [])
    mem.suspend_user(user.id)
    clock.advance(3600)  # past the last_used_at coalescing window
    with pytest.raises(InvalidPatTokenError):
        mem.verify_pat_token(created.token)
    # Suspension did not revoke the PAT, and the refused verify did not
    # record a use.
    pat = mem.get_pat(created.pat.id)
    assert pat.revoked_at is None
    assert pat.last_used_at is None
    mem.reinstate_user(user.id)
    assert mem.verify_pat_token(created.token).usr_id == user.id


def test_verify_pat_suspended_owner_error_matches_wrong_secret(
    mem: InMemoryIdentityStore,
) -> None:
    user = mem.create_user()
    created = mem.create_pat(user.id, "ci", [])
    mem.suspend_user(user.id)
    with pytest.raises(InvalidPatTokenError) as suspended:
        mem.verify_pat_token(created.token)
    with pytest.raises(InvalidPatTokenError) as wrong:
        mem.verify_pat_token(created.token[:37] + "A" * (len(created.token) - 37))
    assert str(suspended.value) == str(wrong.value)
    assert suspended.value.code == wrong.value.code


def test_revoke_user_alone_revokes_pats(mem: InMemoryIdentityStore) -> None:
    user = mem.create_user()
    created = mem.create_pat(user.id, "ci", [])
    mem.revoke_user(user.id)
    with pytest.raises(PatRevokedError):
        mem.verify_pat_token(created.token)


def test_create_pat_revoked_user_refused_and_creates_nothing(
    mem: InMemoryIdentityStore,
) -> None:
    user = mem.create_user()
    mem.revoke_user(user.id)
    with pytest.raises(PreconditionError) as exc:
        mem.create_pat(user.id, "ci", [])
    assert exc.value.reason == "user_not_active"
    assert mem.list_pats_for_user(user.id).data == []


def test_create_pat_suspended_user_refused_and_creates_nothing(
    mem: InMemoryIdentityStore,
) -> None:
    user = mem.create_user()
    mem.suspend_user(user.id)
    with pytest.raises(PreconditionError) as exc:
        mem.create_pat(user.id, "ci", [])
    assert exc.value.reason == "user_not_active"
    assert mem.list_pats_for_user(user.id).data == []
