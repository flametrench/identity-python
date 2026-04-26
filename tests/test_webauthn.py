# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for v0.2 WebAuthn primitives.

The cross-SDK conformance corpus is what guarantees parity; these are
in-SDK property tests for behavior the conformance fixtures do not (and
should not) pin: COSE-key parsing edge cases, error code shape, and
auxiliary helpers.
"""

from __future__ import annotations

import hashlib
import json
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from flametrench_identity import (
    WebAuthnAssertionResult,
    WebAuthnChallengeMismatchError,
    WebAuthnCounterRegressionError,
    WebAuthnError,
    WebAuthnMalformedError,
    WebAuthnOriginMismatchError,
    WebAuthnRpIdMismatchError,
    WebAuthnSignatureError,
    WebAuthnTypeMismatchError,
    WebAuthnUnsupportedKeyError,
    WebAuthnUserNotPresentError,
    WebAuthnUserNotVerifiedError,
    cose_key_es256,
    webauthn_verify_assertion,
)
from flametrench_identity.webauthn import b64url_encode

RP_ID = "test.example"
ORIGIN = "https://test.example"
CHALLENGE = b"unit-test-challenge"


def _build_keypair():
    """Fresh ES256 keypair per test (avoids cross-test ordering issues)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub = private_key.public_key().public_numbers()
    cose = cose_key_es256(pub.x.to_bytes(32, "big"), pub.y.to_bytes(32, "big"))
    return private_key, cose


def _make_auth_data(rp_id: str = RP_ID, flags: int = 0x05, sign_count: int = 1) -> bytes:
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", sign_count)


def _make_client_data(challenge: bytes = CHALLENGE, origin: str = ORIGIN, type_: str = "webauthn.get") -> bytes:
    return json.dumps(
        {"type": type_, "challenge": b64url_encode(challenge), "origin": origin},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _sign(private_key, auth_data: bytes, client_data: bytes) -> bytes:
    return private_key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))


# ─── Happy path ─────────────────────────────────────────────────


def test_verifies_well_formed_assertion_and_returns_new_count() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(sign_count=42)
    client = _make_client_data()
    sig = _sign(private_key, auth, client)
    result = webauthn_verify_assertion(
        cose_public_key=cose,
        stored_sign_count=10,
        stored_rp_id=RP_ID,
        expected_challenge=CHALLENGE,
        expected_origin=ORIGIN,
        authenticator_data=auth,
        client_data_json=client,
        signature=sig,
    )
    assert isinstance(result, WebAuthnAssertionResult)
    assert result.new_sign_count == 42


def test_both_zero_counter_is_accepted() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(sign_count=0)
    client = _make_client_data()
    sig = _sign(private_key, auth, client)
    result = webauthn_verify_assertion(
        cose_public_key=cose,
        stored_sign_count=0,
        stored_rp_id=RP_ID,
        expected_challenge=CHALLENGE,
        expected_origin=ORIGIN,
        authenticator_data=auth,
        client_data_json=client,
        signature=sig,
    )
    assert result.new_sign_count == 0


# ─── Counter regression ─────────────────────────────────────────


def test_equal_counter_rejected() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(sign_count=10)
    client = _make_client_data()
    sig = _sign(private_key, auth, client)
    with pytest.raises(WebAuthnCounterRegressionError) as info:
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=10,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=auth,
            client_data_json=client,
            signature=sig,
        )
    assert info.value.code == "webauthn.counter_regression"


def test_decreasing_counter_rejected() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(sign_count=5)
    client = _make_client_data()
    sig = _sign(private_key, auth, client)
    with pytest.raises(WebAuthnCounterRegressionError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=10,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=auth,
            client_data_json=client,
            signature=sig,
        )


# ─── Flag enforcement ───────────────────────────────────────────


def test_user_verified_required_by_default() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(flags=0x01, sign_count=2)  # UP only
    client = _make_client_data()
    sig = _sign(private_key, auth, client)
    with pytest.raises(WebAuthnUserNotVerifiedError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=1,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=auth,
            client_data_json=client,
            signature=sig,
        )


def test_user_present_required_by_default() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(flags=0x04, sign_count=2)  # UV only, no UP
    client = _make_client_data()
    sig = _sign(private_key, auth, client)
    with pytest.raises(WebAuthnUserNotPresentError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=1,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=auth,
            client_data_json=client,
            signature=sig,
        )


def test_uv_can_be_disabled_for_legacy_2fa() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(flags=0x01, sign_count=2)  # UP only
    client = _make_client_data()
    sig = _sign(private_key, auth, client)
    result = webauthn_verify_assertion(
        cose_public_key=cose,
        stored_sign_count=1,
        stored_rp_id=RP_ID,
        expected_challenge=CHALLENGE,
        expected_origin=ORIGIN,
        authenticator_data=auth,
        client_data_json=client,
        signature=sig,
        require_user_verified=False,
    )
    assert result.new_sign_count == 2


# ─── RP / origin / challenge / type mismatches ──────────────────


def test_rp_id_mismatch() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(rp_id="evil.test", sign_count=2)
    client = _make_client_data()
    sig = _sign(private_key, auth, client)
    with pytest.raises(WebAuthnRpIdMismatchError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=1,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=auth,
            client_data_json=client,
            signature=sig,
        )


def test_origin_mismatch() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(sign_count=2)
    client = _make_client_data(origin="https://evil.test")
    sig = _sign(private_key, auth, client)
    with pytest.raises(WebAuthnOriginMismatchError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=1,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=auth,
            client_data_json=client,
            signature=sig,
        )


def test_challenge_mismatch() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(sign_count=2)
    client = _make_client_data(challenge=b"different")
    sig = _sign(private_key, auth, client)
    with pytest.raises(WebAuthnChallengeMismatchError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=1,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=auth,
            client_data_json=client,
            signature=sig,
        )


def test_type_must_be_webauthn_get() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(sign_count=2)
    client = _make_client_data(type_="webauthn.create")
    sig = _sign(private_key, auth, client)
    with pytest.raises(WebAuthnTypeMismatchError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=1,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=auth,
            client_data_json=client,
            signature=sig,
        )


# ─── Signature verification ─────────────────────────────────────


def test_tampered_signature_rejected() -> None:
    private_key, cose = _build_keypair()
    auth = _make_auth_data(sign_count=2)
    client = _make_client_data()
    sig = bytearray(_sign(private_key, auth, client))
    sig[-1] ^= 0x01
    with pytest.raises(WebAuthnSignatureError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=1,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=auth,
            client_data_json=client,
            signature=bytes(sig),
        )


def test_signature_from_different_keypair_rejected() -> None:
    _, cose = _build_keypair()
    other_private = ec.generate_private_key(ec.SECP256R1())
    auth = _make_auth_data(sign_count=2)
    client = _make_client_data()
    sig = _sign(other_private, auth, client)
    with pytest.raises(WebAuthnSignatureError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=1,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=auth,
            client_data_json=client,
            signature=sig,
        )


# ─── Malformed inputs ───────────────────────────────────────────


def test_truncated_authenticator_data() -> None:
    _, cose = _build_keypair()
    with pytest.raises(WebAuthnMalformedError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=0,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=b"\x00" * 10,
            client_data_json=_make_client_data(),
            signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
        )


def test_invalid_client_data_json() -> None:
    _, cose = _build_keypair()
    with pytest.raises(WebAuthnMalformedError):
        webauthn_verify_assertion(
            cose_public_key=cose,
            stored_sign_count=0,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=_make_auth_data(),
            client_data_json=b"not json",
            signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
        )


def test_unsupported_cose_key_kty() -> None:
    # kty=1 (OKP) is not supported in v0.2 (only EC2/ES256).
    bad_key = b"\xa5\x01\x01\x03\x26\x20\x01\x21\x58\x20" + b"\x00" * 32 + b"\x22\x58\x20" + b"\x00" * 32
    with pytest.raises(WebAuthnUnsupportedKeyError):
        webauthn_verify_assertion(
            cose_public_key=bad_key,
            stored_sign_count=0,
            stored_rp_id=RP_ID,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            authenticator_data=_make_auth_data(),
            client_data_json=_make_client_data(),
            signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
        )


# ─── Error code shape ───────────────────────────────────────────


def test_error_codes_carry_webauthn_prefix() -> None:
    err = WebAuthnSignatureError()
    assert err.code == "webauthn.signature_invalid"
    assert isinstance(err, WebAuthnError)
