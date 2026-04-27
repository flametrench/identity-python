# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for PostgresIdentityStore.

Gated on IDENTITY_POSTGRES_URL — when the env var is unset the entire
module is skipped, mirroring the Node and PHP suites.
"""

from __future__ import annotations

import base64
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import pytest
from flametrench_ids import generate

from flametrench_identity.errors import (
    AlreadyTerminalError,
    CredentialNotActiveError,
    DuplicateCredentialError,
    InvalidCredentialError,
    InvalidTokenError,
    NotFoundError,
    PreconditionError,
    SessionExpiredError,
)
from flametrench_identity.mfa import (
    FactorStatus,
    FactorType,
    RecoveryFactor,
    RecoveryProof,
    TotpProof,
    totp_compute,
)
from flametrench_identity.types import (
    PasswordCredential,
    Status,
)

POSTGRES_URL = os.environ.get("IDENTITY_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="IDENTITY_POSTGRES_URL not set; PostgresIdentityStore tests skipped.",
)

if POSTGRES_URL is not None:
    import psycopg

    from flametrench_identity.postgres import PostgresIdentityStore

SCHEMA_SQL = Path(__file__).parent.joinpath("postgres-schema.sql").read_text()


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
def store(conn: Any) -> "PostgresIdentityStore":
    return PostgresIdentityStore(conn)


# ─── Users ───

def test_create_user_yields_active(store):
    u = store.create_user()
    assert u.id.startswith("usr_")
    assert u.status == Status.ACTIVE


def test_get_user_unknown_raises(store):
    with pytest.raises(NotFoundError):
        store.get_user(generate("usr"))


def test_suspend_reinstate_round_trip(store):
    u = store.create_user()
    suspended = store.suspend_user(u.id)
    assert suspended.status == Status.SUSPENDED
    reinstated = store.reinstate_user(u.id)
    assert reinstated.status == Status.ACTIVE


def test_revoke_user_cascades(store):
    u = store.create_user()
    cred = store.create_password_credential(u.id, "alice@example.com", "pw")
    sw = store.create_session(u.id, cred.id, 3600)
    store.revoke_user(u.id)
    assert store.get_user(u.id).status == Status.REVOKED
    assert store.get_credential(cred.id).status == Status.REVOKED
    assert store.get_session(sw.session.id).revoked_at is not None


def test_double_revoke_rejected(store):
    u = store.create_user()
    store.revoke_user(u.id)
    with pytest.raises(AlreadyTerminalError):
        store.revoke_user(u.id)


# ─── Credentials ───

def test_password_credential_round_trip(store):
    u = store.create_user()
    cred = store.create_password_credential(u.id, "alice@example.com", "correct horse battery staple")
    assert isinstance(cred, PasswordCredential)
    verified = store.verify_password("alice@example.com", "correct horse battery staple")
    assert verified.usr_id == u.id
    assert verified.cred_id == cred.id


def test_verify_password_wrong_rejected(store):
    u = store.create_user()
    store.create_password_credential(u.id, "alice@example.com", "pw")
    with pytest.raises(InvalidCredentialError):
        store.verify_password("alice@example.com", "wrong")


def test_duplicate_active_credential_rejected(store):
    u = store.create_user()
    store.create_password_credential(u.id, "alice@example.com", "p1")
    with pytest.raises(DuplicateCredentialError):
        store.create_password_credential(u.id, "alice@example.com", "p2")


def test_rotate_password_revokes_old_terminates_sessions(store):
    u = store.create_user()
    old = store.create_password_credential(u.id, "alice@example.com", "old")
    sw = store.create_session(u.id, old.id, 3600)
    new = store.rotate_password(old.id, "new")
    assert new.replaces == old.id
    assert store.get_credential(old.id).status == Status.REVOKED
    assert store.get_session(sw.session.id).revoked_at is not None
    with pytest.raises(InvalidCredentialError):
        store.verify_password("alice@example.com", "old")
    ok = store.verify_password("alice@example.com", "new")
    assert ok.cred_id == new.id


def test_find_credential_by_identifier_active_only(store):
    from flametrench_identity.types import CredentialType
    u = store.create_user()
    cred = store.create_password_credential(u.id, "alice@example.com", "p")
    found = store.find_credential_by_identifier(CredentialType.PASSWORD, "alice@example.com")
    assert found is not None and found.id == cred.id
    store.revoke_credential(cred.id)
    assert store.find_credential_by_identifier(CredentialType.PASSWORD, "alice@example.com") is None


# ─── Sessions ───

def test_session_token_round_trips(store):
    u = store.create_user()
    cred = store.create_password_credential(u.id, "alice@example.com", "p")
    sw = store.create_session(u.id, cred.id, 3600)
    assert sw.token != sw.session.id
    verified = store.verify_session_token(sw.token)
    assert verified.id == sw.session.id


def test_verify_session_unknown_token_rejected(store):
    with pytest.raises(InvalidTokenError):
        store.verify_session_token("nope")


def test_verify_session_revoked_rejected(store):
    u = store.create_user()
    cred = store.create_password_credential(u.id, "alice@example.com", "p")
    sw = store.create_session(u.id, cred.id, 3600)
    store.revoke_session(sw.session.id)
    with pytest.raises(SessionExpiredError):
        store.verify_session_token(sw.token)


def test_refresh_session_returns_new(store):
    u = store.create_user()
    cred = store.create_password_credential(u.id, "alice@example.com", "p")
    sw = store.create_session(u.id, cred.id, 3600)
    refreshed = store.refresh_session(sw.session.id)
    assert refreshed.session.id != sw.session.id
    assert refreshed.token != sw.token
    assert store.get_session(sw.session.id).revoked_at is not None


def test_create_session_short_ttl_rejected(store):
    u = store.create_user()
    cred = store.create_password_credential(u.id, "alice@example.com", "p")
    with pytest.raises(PreconditionError):
        store.create_session(u.id, cred.id, 30)


def test_create_session_suspended_cred_rejected(store):
    u = store.create_user()
    cred = store.create_password_credential(u.id, "alice@example.com", "p")
    store.suspend_credential(cred.id)
    with pytest.raises(CredentialNotActiveError):
        store.create_session(u.id, cred.id, 3600)


# ─── MFA ───

def _b32_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 8)
    return base64.b32decode(s + pad)


def test_totp_enroll_confirm_verify_round_trip(store):
    u = store.create_user()
    enroll = store.enroll_totp_factor(u.id, "iPhone")
    assert enroll.factor.status == FactorStatus.PENDING
    secret = _b32_decode(enroll.secret_b32)
    assert enroll.otpauth_uri.startswith("otpauth://totp/")
    code = totp_compute(secret, int(time.time()))
    active = store.confirm_totp_factor(enroll.factor.id, code)
    assert active.status == FactorStatus.ACTIVE
    result = store.verify_mfa(u.id, TotpProof(code=code))
    assert result.type == FactorType.TOTP
    assert result.mfa_id == active.id


def test_totp_enforces_one_active(store):
    u = store.create_user()
    first = store.enroll_totp_factor(u.id, "iPhone")
    code = totp_compute(_b32_decode(first.secret_b32), int(time.time()))
    store.confirm_totp_factor(first.factor.id, code)
    with pytest.raises(PreconditionError):
        store.enroll_totp_factor(u.id, "Yubico")


def test_recovery_codes_consume_once(store):
    u = store.create_user()
    enroll = store.enroll_recovery_factor(u.id)
    assert len(enroll.codes) == 10
    first = enroll.codes[0]
    result = store.verify_mfa(u.id, RecoveryProof(code=first))
    assert result.type == FactorType.RECOVERY
    with pytest.raises(InvalidCredentialError):
        store.verify_mfa(u.id, RecoveryProof(code=first))
    factors = store.list_mfa_factors(u.id)
    recovery = next(f for f in factors if f.type == FactorType.RECOVERY)
    assert isinstance(recovery, RecoveryFactor)
    assert recovery.remaining == 9


def test_recovery_malformed_input_rejected(store):
    u = store.create_user()
    store.enroll_recovery_factor(u.id)
    with pytest.raises(InvalidCredentialError):
        store.verify_mfa(u.id, RecoveryProof(code="not-a-code"))


def test_revoke_mfa_frees_singleton(store):
    u = store.create_user()
    first = store.enroll_totp_factor(u.id, "iPhone")
    code = totp_compute(_b32_decode(first.secret_b32), int(time.time()))
    store.confirm_totp_factor(first.factor.id, code)
    store.revoke_mfa_factor(first.factor.id)
    second = store.enroll_totp_factor(u.id, "Yubico")
    assert second.factor.status == FactorStatus.PENDING


def test_set_mfa_policy_upserts(store):
    u = store.create_user()
    assert store.get_mfa_policy(u.id) is None
    grace = datetime.now(timezone.utc) + timedelta(days=14)
    set1 = store.set_mfa_policy(u.id, required=True, grace_until=grace)
    assert set1.required is True
    assert set1.grace_until is not None
    fetched = store.get_mfa_policy(u.id)
    assert fetched is not None and fetched.required is True
    set2 = store.set_mfa_policy(u.id, required=True)
    assert set2.grace_until is None


def test_get_mfa_policy_unknown_user_raises(store):
    with pytest.raises(NotFoundError):
        store.get_mfa_policy(generate("usr"))
