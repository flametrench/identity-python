# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for InMemoryIdentityStore.

Mirrors the Node + PHP unit suites; keeps behavior consistent across SDKs.
"""

from __future__ import annotations

import re

import pytest

from flametrench_identity import (
    AlreadyTerminalError,
    CredentialNotActiveError,
    DuplicateCredentialError,
    InMemoryIdentityStore,
    InvalidCredentialError,
    InvalidTokenError,
    NotFoundError,
    PreconditionError,
    SessionExpiredError,
    Status,
    hash_password,
    verify_password_hash,
)


@pytest.fixture
def store() -> InMemoryIdentityStore:
    return InMemoryIdentityStore()


class TestUserLifecycle:
    def test_create_returns_active_user_with_usr_id(
        self, store: InMemoryIdentityStore
    ) -> None:
        u = store.create_user()
        assert re.match(r"^usr_[0-9a-f]{32}$", u.id)
        assert u.status == Status.ACTIVE

    def test_get_unknown_user_raises(self, store: InMemoryIdentityStore) -> None:
        with pytest.raises(NotFoundError):
            store.get_user("usr_00000000000000000000000000000001")

    def test_suspend_then_reinstate_round_trip(
        self, store: InMemoryIdentityStore
    ) -> None:
        u = store.create_user()
        s = store.suspend_user(u.id)
        assert s.status == Status.SUSPENDED
        r = store.reinstate_user(u.id)
        assert r.status == Status.ACTIVE

    def test_cannot_reinstate_active_user(self, store: InMemoryIdentityStore) -> None:
        u = store.create_user()
        with pytest.raises(PreconditionError):
            store.reinstate_user(u.id)

    def test_revoke_is_terminal(self, store: InMemoryIdentityStore) -> None:
        u = store.create_user()
        store.revoke_user(u.id)
        with pytest.raises(AlreadyTerminalError):
            store.revoke_user(u.id)


class TestPasswordCredential:
    def test_create_then_verify_round_trip(
        self, store: InMemoryIdentityStore
    ) -> None:
        u = store.create_user()
        store.create_password_credential(
            u.id, "alice@example.com", "correcthorsebatterystaple"
        )
        verified = store.verify_password(
            "alice@example.com", "correcthorsebatterystaple"
        )
        assert verified.usr_id == u.id

    def test_wrong_password_raises(self, store: InMemoryIdentityStore) -> None:
        u = store.create_user()
        store.create_password_credential(u.id, "alice@example.com", "right")
        with pytest.raises(InvalidCredentialError):
            store.verify_password("alice@example.com", "wrong")

    def test_unknown_identifier_raises(self, store: InMemoryIdentityStore) -> None:
        with pytest.raises(InvalidCredentialError):
            store.verify_password("nobody@example.com", "anything")

    def test_duplicate_identifier_rejected(self, store: InMemoryIdentityStore) -> None:
        u1 = store.create_user()
        u2 = store.create_user()
        store.create_password_credential(u1.id, "shared@example.com", "x")
        with pytest.raises(DuplicateCredentialError):
            store.create_password_credential(u2.id, "shared@example.com", "y")

    def test_rotation_revokes_old_and_returns_new(
        self, store: InMemoryIdentityStore
    ) -> None:
        u = store.create_user()
        old = store.create_password_credential(u.id, "alice@example.com", "v1")
        new = store.rotate_password(old.id, "v2")
        assert new.replaces == old.id
        # old hash no longer verifies (key index points to the new id).
        with pytest.raises(InvalidCredentialError):
            store.verify_password("alice@example.com", "v1")
        verified = store.verify_password("alice@example.com", "v2")
        assert verified.cred_id == new.id

    def test_revoke_user_cascades_credentials(
        self, store: InMemoryIdentityStore
    ) -> None:
        u = store.create_user()
        store.create_password_credential(u.id, "alice@example.com", "v1")
        store.revoke_user(u.id)
        with pytest.raises(InvalidCredentialError):
            store.verify_password("alice@example.com", "v1")


class TestSessionLifecycle:
    def test_create_then_verify_token(self, store: InMemoryIdentityStore) -> None:
        u = store.create_user()
        cred = store.create_password_credential(u.id, "alice@example.com", "pw")
        sw = store.create_session(u.id, cred.id, ttl_seconds=3600)
        session = store.verify_session_token(sw.token)
        assert session.id == sw.session.id
        assert session.usr_id == u.id

    def test_reject_unknown_token(self, store: InMemoryIdentityStore) -> None:
        with pytest.raises(InvalidTokenError):
            store.verify_session_token("definitely-not-a-real-token")

    def test_refresh_revokes_old_issues_new(
        self, store: InMemoryIdentityStore
    ) -> None:
        u = store.create_user()
        cred = store.create_password_credential(u.id, "alice@example.com", "pw")
        sw1 = store.create_session(u.id, cred.id, ttl_seconds=3600)
        sw2 = store.refresh_session(sw1.session.id)
        assert sw1.session.id != sw2.session.id
        # Old token no longer verifies.
        with pytest.raises(InvalidTokenError):
            store.verify_session_token(sw1.token)
        # New token does.
        store.verify_session_token(sw2.token)

    def test_rotation_terminates_sessions_bound_to_old_cred(
        self, store: InMemoryIdentityStore
    ) -> None:
        u = store.create_user()
        cred = store.create_password_credential(u.id, "alice@example.com", "v1")
        sw = store.create_session(u.id, cred.id, ttl_seconds=3600)
        store.rotate_password(cred.id, "v2")
        with pytest.raises(InvalidTokenError):
            store.verify_session_token(sw.token)

    def test_rejects_ttl_below_60s(self, store: InMemoryIdentityStore) -> None:
        u = store.create_user()
        cred = store.create_password_credential(u.id, "alice@example.com", "pw")
        with pytest.raises(PreconditionError):
            store.create_session(u.id, cred.id, ttl_seconds=30)

    def test_revoke_session_invalidates_token(
        self, store: InMemoryIdentityStore
    ) -> None:
        u = store.create_user()
        cred = store.create_password_credential(u.id, "alice@example.com", "pw")
        sw = store.create_session(u.id, cred.id, ttl_seconds=3600)
        store.revoke_session(sw.session.id)
        with pytest.raises((InvalidTokenError, SessionExpiredError)):
            store.verify_session_token(sw.token)

    def test_suspending_credential_terminates_sessions(
        self, store: InMemoryIdentityStore
    ) -> None:
        u = store.create_user()
        cred = store.create_password_credential(u.id, "alice@example.com", "pw")
        sw = store.create_session(u.id, cred.id, ttl_seconds=3600)
        store.suspend_credential(cred.id)
        with pytest.raises(InvalidTokenError):
            store.verify_session_token(sw.token)


class TestHashingHelpers:
    def test_hash_then_verify_round_trip(self) -> None:
        phc = hash_password("correcthorsebatterystaple")
        assert phc.startswith("$argon2id$")
        assert verify_password_hash(phc, "correcthorsebatterystaple") is True
        assert verify_password_hash(phc, "wrong") is False

    def test_verify_returns_false_on_garbage_input(self) -> None:
        assert verify_password_hash("not a phc string", "anything") is False
        assert verify_password_hash("", "") is False
