# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for v0.2 IdentityStore MFA operations.

Exercises the enroll → confirm → verify lifecycle for TOTP, WebAuthn,
and recovery-code factors, plus usr_mfa_policy CRUD. The cross-SDK
parity layer (TOTP RFC vectors, WebAuthn signature verification,
recovery format) is already covered by the conformance suite — this
file focuses on the store-level orchestration that ADR 0008 specifies.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from flametrench_identity import (
    FactorStatus,
    FactorType,
    InMemoryIdentityStore,
    InvalidCredentialError,
    PreconditionError,
    RecoveryProof,
    TotpProof,
    UserMfaPolicy,
    WebAuthnProof,
    cose_key_es256,
    is_valid_recovery_code,
    totp_compute,
)
from flametrench_identity.webauthn import b64url_encode


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_clock(start: datetime):
    """Mutable mock clock — `+t(seconds)` advances it."""
    state = {"now": start}
    def clock() -> datetime:
        return state["now"]
    def advance(seconds: float) -> None:
        state["now"] = state["now"] + timedelta(seconds=seconds)
    clock.advance = advance  # type: ignore[attr-defined]
    return clock


# ─── Recovery codes ─────────────────────────────────────────────


def test_recovery_enrollment_returns_10_codes_active_immediately() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    result = store.enroll_recovery_factor(user.id)
    assert result.factor.status == FactorStatus.ACTIVE
    assert len(result.codes) == 10
    for code in result.codes:
        assert is_valid_recovery_code(code)
    # All 10 unconsumed at start.
    assert result.factor.remaining == 10


def test_recovery_verify_consumes_a_slot() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    enroll = store.enroll_recovery_factor(user.id)
    code = enroll.codes[3]
    out = store.verify_mfa(user.id, RecoveryProof(code=code))
    assert out.type == FactorType.RECOVERY
    # Same code MUST NOT be reusable (the slot is consumed).
    with pytest.raises(InvalidCredentialError):
        store.verify_mfa(user.id, RecoveryProof(code=code))
    # Remaining count reflects consumption.
    factor = store.get_mfa_factor(enroll.factor.id)
    assert factor.remaining == 9


def test_recovery_verify_normalizes_input() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    enroll = store.enroll_recovery_factor(user.id)
    code = enroll.codes[0]
    # Lowercase + whitespace should normalize and verify.
    store.verify_mfa(
        user.id, RecoveryProof(code=f"  {code.lower()}  ")
    )


def test_recovery_at_most_one_active_per_user() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    store.enroll_recovery_factor(user.id)
    with pytest.raises(PreconditionError):
        store.enroll_recovery_factor(user.id)


def test_recovery_revoke_frees_singleton() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    first = store.enroll_recovery_factor(user.id)
    store.revoke_mfa_factor(first.factor.id)
    # Re-enrollment now succeeds.
    second = store.enroll_recovery_factor(user.id)
    assert second.factor.id != first.factor.id


# ─── TOTP ────────────────────────────────────────────────────────


def test_totp_enrollment_returns_pending_factor() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    enroll = store.enroll_totp_factor(user.id, identifier="iPhone")
    assert enroll.factor.status == FactorStatus.PENDING
    assert enroll.secret_b32  # base32-encoded
    assert enroll.otpauth_uri.startswith("otpauth://totp/")


def test_totp_confirm_with_correct_code_activates() -> None:
    clock = _make_clock(_now())
    store = InMemoryIdentityStore(clock=clock)
    user = store.create_user()
    enroll = store.enroll_totp_factor(user.id, identifier="iPhone")
    # Compute the current code using the same secret the SDK generated.
    secret = base64.b32decode(enroll.secret_b32 + "=" * (-len(enroll.secret_b32) % 8))
    code = totp_compute(secret, int(clock().timestamp()))
    confirmed = store.confirm_totp_factor(enroll.factor.id, code)
    assert confirmed.status == FactorStatus.ACTIVE


def test_totp_confirm_wrong_code_rejects() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    enroll = store.enroll_totp_factor(user.id, identifier="iPhone")
    with pytest.raises(InvalidCredentialError):
        store.confirm_totp_factor(enroll.factor.id, "000000")


def test_totp_confirm_after_pending_window_rejects() -> None:
    # Audit M1: pending factor expiry.
    clock = _make_clock(_now())
    store = InMemoryIdentityStore(clock=clock)
    user = store.create_user()
    enroll = store.enroll_totp_factor(user.id, identifier="iPhone")
    secret = base64.b32decode(enroll.secret_b32 + "=" * (-len(enroll.secret_b32) % 8))
    # Jump past 10 minutes.
    clock.advance(700)
    code = totp_compute(secret, int(clock().timestamp()))
    with pytest.raises(PreconditionError) as info:
        store.confirm_totp_factor(enroll.factor.id, code)
    assert info.value.reason == "pending_factor_expired"


def test_totp_at_most_one_active_per_user() -> None:
    # Confirm the first TOTP factor, then a second enrollment must be
    # rejected. Pending-but-not-confirmed factors don't count toward
    # the singleton constraint — they expire on the 10-min TTL.
    clock = _make_clock(_now())
    store = InMemoryIdentityStore(clock=clock)
    user = store.create_user()
    enroll = store.enroll_totp_factor(user.id, identifier="iPhone")
    secret = base64.b32decode(enroll.secret_b32 + "=" * (-len(enroll.secret_b32) % 8))
    store.confirm_totp_factor(
        enroll.factor.id, totp_compute(secret, int(clock().timestamp()))
    )
    with pytest.raises(PreconditionError):
        store.enroll_totp_factor(user.id, identifier="Backup phone")


def test_totp_verify_after_confirm() -> None:
    clock = _make_clock(_now())
    store = InMemoryIdentityStore(clock=clock)
    user = store.create_user()
    enroll = store.enroll_totp_factor(user.id, identifier="iPhone")
    secret = base64.b32decode(enroll.secret_b32 + "=" * (-len(enroll.secret_b32) % 8))
    store.confirm_totp_factor(
        enroll.factor.id, totp_compute(secret, int(clock().timestamp()))
    )
    # Now verify_mfa succeeds.
    result = store.verify_mfa(
        user.id, TotpProof(code=totp_compute(secret, int(clock().timestamp())))
    )
    assert result.type == FactorType.TOTP
    assert result.mfa_id == enroll.factor.id


def test_totp_verify_with_no_active_factor_rejects() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    with pytest.raises(InvalidCredentialError):
        store.verify_mfa(user.id, TotpProof(code="123456"))


# ─── WebAuthn ────────────────────────────────────────────────────


def _make_webauthn_assertion(
    private_key, *, rp_id: str, origin: str, challenge: bytes, sign_count: int
):
    rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = 0x05  # UP + UV
    auth_data = rp_hash + bytes([flags]) + struct.pack(">I", sign_count)
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": b64url_encode(challenge), "origin": origin},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signed = auth_data + hashlib.sha256(client_data).digest()
    sig = private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    return auth_data, client_data, sig


def test_webauthn_enroll_then_confirm_then_verify() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    private = ec.generate_private_key(ec.SECP256R1())
    pub = private.public_key().public_numbers()
    cose = cose_key_es256(pub.x.to_bytes(32, "big"), pub.y.to_bytes(32, "big"))
    cred_id = "test-credential-id"
    rp_id = "test.example"
    origin = "https://test.example"

    enroll = store.enroll_webauthn_factor(
        user.id,
        identifier=cred_id,
        public_key=cose,
        sign_count=0,
        rp_id=rp_id,
    )
    assert enroll.factor.status == FactorStatus.PENDING

    challenge = b"confirm-challenge"
    auth_data, client_data, sig = _make_webauthn_assertion(
        private, rp_id=rp_id, origin=origin, challenge=challenge, sign_count=1
    )
    confirmed = store.confirm_webauthn_factor(
        enroll.factor.id,
        authenticator_data=auth_data,
        client_data_json=client_data,
        signature=sig,
        expected_challenge=challenge,
        expected_origin=origin,
    )
    assert confirmed.status == FactorStatus.ACTIVE
    assert confirmed.sign_count == 1

    # Now verify_mfa with another assertion advancing the counter further.
    challenge2 = b"verify-challenge"
    auth_data2, client_data2, sig2 = _make_webauthn_assertion(
        private, rp_id=rp_id, origin=origin, challenge=challenge2, sign_count=2
    )
    result = store.verify_mfa(
        user.id,
        WebAuthnProof(
            credential_id=cred_id,
            authenticator_data=auth_data2,
            client_data_json=client_data2,
            signature=sig2,
            expected_challenge=challenge2,
            expected_origin=origin,
        ),
    )
    assert result.type == FactorType.WEBAUTHN
    assert result.new_sign_count == 2


def test_webauthn_multiple_active_factors_allowed_per_user() -> None:
    # ADR 0008: WebAuthn allows multiple per user (phone + laptop + key).
    store = InMemoryIdentityStore()
    user = store.create_user()

    def cose_for(seed: int) -> bytes:
        priv = ec.derive_private_key(seed, ec.SECP256R1())
        pub = priv.public_key().public_numbers()
        return cose_key_es256(pub.x.to_bytes(32, "big"), pub.y.to_bytes(32, "big"))

    e1 = store.enroll_webauthn_factor(
        user.id, identifier="cred-a", public_key=cose_for(123), sign_count=0, rp_id="x"
    )
    e2 = store.enroll_webauthn_factor(
        user.id, identifier="cred-b", public_key=cose_for(456), sign_count=0, rp_id="x"
    )
    assert e1.factor.id != e2.factor.id


def test_webauthn_duplicate_credential_id_rejects() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    cose = cose_key_es256(b"\x01" * 32, b"\x02" * 32)
    store.enroll_webauthn_factor(
        user.id, identifier="dup", public_key=cose, sign_count=0, rp_id="x"
    )
    with pytest.raises(PreconditionError):
        store.enroll_webauthn_factor(
            user.id, identifier="dup", public_key=cose, sign_count=0, rp_id="x"
        )


# ─── Listing + revoke ──────────────────────────────────────────


def test_list_mfa_factors_returns_user_scoped_set() -> None:
    store = InMemoryIdentityStore()
    a = store.create_user()
    b = store.create_user()
    store.enroll_recovery_factor(a.id)
    store.enroll_totp_factor(a.id, identifier="iPhone")
    store.enroll_recovery_factor(b.id)
    a_factors = store.list_mfa_factors(a.id)
    b_factors = store.list_mfa_factors(b.id)
    assert len(a_factors) == 2
    assert len(b_factors) == 1


# ─── usr_mfa_policy ─────────────────────────────────────────────


def test_get_mfa_policy_defaults_to_none() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    assert store.get_mfa_policy(user.id) is None


def test_set_mfa_policy_round_trip() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    grace = _now() + timedelta(days=14)
    policy = store.set_mfa_policy(user.id, required=True, grace_until=grace)
    assert isinstance(policy, UserMfaPolicy)
    assert policy.required is True
    assert policy.grace_until == grace
    again = store.get_mfa_policy(user.id)
    assert again == policy


def test_set_mfa_policy_overwrites() -> None:
    store = InMemoryIdentityStore()
    user = store.create_user()
    store.set_mfa_policy(user.id, required=True, grace_until=None)
    store.set_mfa_policy(user.id, required=False, grace_until=None)
    policy = store.get_mfa_policy(user.id)
    assert policy is not None
    assert policy.required is False
