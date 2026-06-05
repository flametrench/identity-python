# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for Personal Access Token (PAT) support — ADR 0016."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from flametrench_identity import (
    AuthKind,
    CreatePatResult,
    InMemoryIdentityStore,
    InvalidPatTokenError,
    NotFoundError,
    PatExpiredError,
    PatRevokedError,
    PatStatus,
    PersonalAccessToken,
    Status,
    classify_bearer,
    is_structurally_valid_pat_token,
)


def _store() -> InMemoryIdentityStore:
    return InMemoryIdentityStore()


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


# ─── classify_bearer ─────────────────────────────────────────────────────────


class TestClassifyBearer:
    def test_pat_prefix(self) -> None:
        assert classify_bearer("pat_abc_xyz") == AuthKind.PAT

    def test_shr_prefix(self) -> None:
        assert classify_bearer("shr_abc") == AuthKind.SHARE

    def test_default_is_session(self) -> None:
        assert classify_bearer("ses_abc") == AuthKind.SESSION
        assert classify_bearer("anything") == AuthKind.SESSION

    def test_authkind_values_are_byte_identical(self) -> None:
        assert AuthKind.PAT == "pat"
        assert AuthKind.SHARE == "share"
        assert AuthKind.SESSION == "session"
        assert AuthKind.SYSTEM == "system"


# ─── is_structurally_valid_pat_token ─────────────────────────────────────────


class TestIsStructurallyValidPatToken:
    def test_valid_token(self) -> None:
        # 32 lowercase hex chars, then base64url secret
        token = "pat_" + "a" * 32 + "_" + "AbCdEf0123456789-_"
        assert is_structurally_valid_pat_token(token) is True

    def test_secret_with_underscore(self) -> None:
        # underscore in secret is valid (base64url charset)
        token = "pat_" + "0" * 32 + "_Ab_Cd_Ef"
        assert is_structurally_valid_pat_token(token) is True

    def test_wrong_prefix(self) -> None:
        token = "usr_" + "a" * 32 + "_secret"
        assert is_structurally_valid_pat_token(token) is False

    def test_uppercase_hex_in_id(self) -> None:
        token = "pat_" + "A" * 32 + "_secret"
        assert is_structurally_valid_pat_token(token) is False

    def test_short_id(self) -> None:
        token = "pat_" + "a" * 31 + "_secret"
        assert is_structurally_valid_pat_token(token) is False

    def test_empty_secret(self) -> None:
        token = "pat_" + "a" * 32 + "_"
        assert is_structurally_valid_pat_token(token) is False

    def test_no_secret_separator(self) -> None:
        token = "pat_" + "a" * 32
        assert is_structurally_valid_pat_token(token) is False


# ─── create_pat ──────────────────────────────────────────────────────────────


class TestCreatePat:
    def test_returns_result_with_valid_token(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "ci-bot", ["read"])
        assert isinstance(result, CreatePatResult)
        assert isinstance(result.pat, PersonalAccessToken)
        assert result.pat.usr_id == u.id
        assert result.pat.name == "ci-bot"
        assert result.pat.scope == ["read"]
        assert result.pat.status == PatStatus.ACTIVE
        assert is_structurally_valid_pat_token(result.token)

    def test_token_positional_parse(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "bot", ["write"])
        token = result.token
        # pat_id is first 36 chars (pat_ + 32 hex)
        assert token[:4] == "pat_"
        assert len(token[:36]) == 36
        assert token[36] == "_"
        assert len(token[37:]) > 0

    def test_with_expires_at(self) -> None:
        s = _store()
        u = s.create_user()
        exp = _now() + timedelta(days=30)
        result = s.create_pat(u.id, "expiring", [], expires_at=exp)
        assert result.pat.expires_at == exp

    def test_user_not_found_raises(self) -> None:
        s = _store()
        with pytest.raises(NotFoundError):
            s.create_pat("usr_" + "0" * 32, "bot", [])

    def test_expires_in_past_raises(self) -> None:
        from flametrench_identity import PreconditionError
        s = _store()
        u = s.create_user()
        past = _now() - timedelta(seconds=1)
        with pytest.raises(PreconditionError):
            s.create_pat(u.id, "bad", [], expires_at=past)

    def test_expires_beyond_365_days_raises(self) -> None:
        from flametrench_identity import PreconditionError
        s = _store()
        u = s.create_user()
        too_far = _now() + timedelta(days=366)
        with pytest.raises(PreconditionError):
            s.create_pat(u.id, "bad", [], expires_at=too_far)


# ─── get_pat / list_pats_for_user ────────────────────────────────────────────


class TestGetAndListPats:
    def test_get_pat_round_trip(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "bot", ["read"])
        fetched = s.get_pat(result.pat.id)
        assert fetched.id == result.pat.id

    def test_get_pat_not_found(self) -> None:
        s = _store()
        with pytest.raises(NotFoundError):
            s.get_pat("pat_" + "0" * 32)

    def test_list_pats_for_user(self) -> None:
        s = _store()
        u = s.create_user()
        r1 = s.create_pat(u.id, "a", [])
        r2 = s.create_pat(u.id, "b", [])
        page = s.list_pats_for_user(u.id)
        ids = [p.id for p in page.data]
        assert r1.pat.id in ids
        assert r2.pat.id in ids

    def test_list_pats_other_user_excluded(self) -> None:
        s = _store()
        u1 = s.create_user()
        u2 = s.create_user()
        s.create_pat(u1.id, "a", [])
        page = s.list_pats_for_user(u2.id)
        assert page.data == []


# ─── verify_pat_token ────────────────────────────────────────────────────────


class TestVerifyPatToken:
    def test_valid_token_returns_verified_pat(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "bot", ["read", "write"])
        vp = s.verify_pat_token(result.token)
        assert vp.pat_id == result.pat.id
        assert vp.usr_id == u.id
        assert vp.scope == ["read", "write"]

    def test_invalid_token_format_raises(self) -> None:
        s = _store()
        with pytest.raises(InvalidPatTokenError):
            s.verify_pat_token("not-a-pat-token")

    def test_unknown_pat_id_raises(self) -> None:
        s = _store()
        # Structurally valid but unknown ID
        token = "pat_" + "0" * 32 + "_AAAAAAAAAAAAAAAAAAAAAAAAA"
        with pytest.raises(InvalidPatTokenError):
            s.verify_pat_token(token)

    def test_wrong_secret_raises(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "bot", [])
        token = result.token
        # Corrupt the secret
        bad_token = token[:-3] + "XXX"
        with pytest.raises(InvalidPatTokenError):
            s.verify_pat_token(bad_token)

    def test_revoked_pat_raises_pat_revoked(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "bot", [])
        s.revoke_pat(result.pat.id)
        with pytest.raises(PatRevokedError):
            s.verify_pat_token(result.token)

    def test_expired_pat_raises_pat_expired(self) -> None:
        now = _now()
        s = InMemoryIdentityStore(clock=lambda: now)
        u = s.create_user()
        exp = now + timedelta(seconds=1)
        result = s.create_pat(u.id, "bot", [], expires_at=exp)

        # Advance clock past expiry
        future = now + timedelta(seconds=2)
        s2 = InMemoryIdentityStore(clock=lambda: future)
        # Re-inject the PAT into s2 for clock-advanced verification
        s2._pats[result.pat.id] = result.pat
        s2._pat_secret_hashes[result.pat.id] = s._pat_secret_hashes[result.pat.id]
        with pytest.raises(PatExpiredError):
            s2.verify_pat_token(result.token)


# ─── revoke_pat ──────────────────────────────────────────────────────────────


class TestRevokePat:
    def test_revoke_makes_verify_fail(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "bot", [])
        s.revoke_pat(result.pat.id)
        with pytest.raises(PatRevokedError):
            s.verify_pat_token(result.token)

    def test_revoke_is_idempotent(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "bot", [])
        s.revoke_pat(result.pat.id)
        s.revoke_pat(result.pat.id)  # should not raise

    def test_revoke_not_found_raises(self) -> None:
        s = _store()
        with pytest.raises(NotFoundError):
            s.revoke_pat("pat_" + "0" * 32)

    def test_revoked_status_is_revoked(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "bot", [])
        revoked = s.revoke_pat(result.pat.id)
        assert revoked.status == PatStatus.REVOKED
        assert revoked.revoked_at is not None


# ─── cascade revoke (user revoke cascades to PATs) ───────────────────────────


class TestCascadeRevoke:
    def test_revoking_user_revokes_pats(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "bot", [])
        s.revoke_user(u.id)
        with pytest.raises(PatRevokedError):
            s.verify_pat_token(result.token)

    def test_suspending_user_preserves_pats(self) -> None:
        s = _store()
        u = s.create_user()
        result = s.create_pat(u.id, "bot", ["read"])
        s.suspend_user(u.id)
        pat = s.get_pat(result.pat.id)
        assert pat.status == PatStatus.ACTIVE
