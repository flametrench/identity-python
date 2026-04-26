# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Flametrench v0.2 conformance suite — MFA fixtures (Python harness).

Four fixture files exercised here:

- ``identity/mfa/totp-rfc6238.json`` — RFC 6238 §B test vectors.
  Pins TOTP byte-identically to the RFC, which transitively pins it
  byte-identically across Flametrench SDKs.
- ``identity/mfa/recovery-code-format.json`` — recovery-code format
  invariants (alphabet, group size, hyphen separators).
- ``identity/mfa/webauthn-assertion.json`` — WebAuthn assertion
  verification: happy path + RP-ID/UV/origin/challenge/signature/type
  failure modes against a pinned ES256 keypair.
- ``identity/mfa/webauthn-counter-decrease-rejected.json`` — WebAuthn
  signature-counter monotonicity (cloned-authenticator detection).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from flametrench_identity import (
    WebAuthnError,
    is_valid_recovery_code,
    totp_compute,
    webauthn_verify_assertion,
)

_FIXTURES_DIR = Path(__file__).parent / "conformance" / "fixtures"


def _load_fixture(relative_path: str) -> dict[str, Any]:
    raw = (_FIXTURES_DIR / relative_path).read_text(encoding="utf-8")
    return json.loads(raw)


def _params(relative_path: str) -> list[Any]:
    fixture = _load_fixture(relative_path)
    return [pytest.param(t, id=t["id"]) for t in fixture["tests"]]


# ─── identity.totp_compute ──────────────────────────────────────


@pytest.mark.parametrize("test_case", _params("identity/mfa/totp-rfc6238.json"))
def test_totp_rfc6238_conformance(test_case: dict[str, Any]) -> None:
    inp = test_case["input"]
    secret = inp["secret_ascii"].encode("ascii")
    result = totp_compute(
        secret,
        timestamp=inp["timestamp"],
        digits=inp["digits"],
        algorithm=inp["algorithm"],
    )
    assert result == test_case["expected"]["result"]


# ─── identity.generate_recovery_code (format predicate) ─────────


@pytest.mark.parametrize(
    "test_case", _params("identity/mfa/recovery-code-format.json")
)
def test_recovery_code_format_conformance(test_case: dict[str, Any]) -> None:
    expected = test_case["expected"]["result"]
    assert is_valid_recovery_code(test_case["input"]["code"]) is expected


# ─── identity.webauthn_verify_assertion ─────────────────────────


def _load_with_shared(relative_path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fixture = _load_fixture(relative_path)
    shared = fixture.get("shared", {})
    return shared, fixture["tests"]


def _run_webauthn(shared: dict[str, Any], test_case: dict[str, Any]) -> dict[str, Any]:
    """Execute one WebAuthn fixture test and return ``{ok, ...}``."""
    inp = {**shared, **test_case["input"]}
    try:
        result = webauthn_verify_assertion(
            cose_public_key=bytes.fromhex(inp["cose_public_key_hex"]),
            stored_sign_count=inp["stored_sign_count"],
            stored_rp_id=inp["stored_rp_id"],
            expected_challenge=bytes.fromhex(inp["expected_challenge_hex"]),
            expected_origin=inp["expected_origin"],
            authenticator_data=bytes.fromhex(inp["authenticator_data_hex"]),
            client_data_json=bytes.fromhex(inp["client_data_json_hex"]),
            signature=bytes.fromhex(inp["signature_hex"]),
            require_user_verified=inp.get("require_user_verified", True),
            require_user_present=inp.get("require_user_present", True),
        )
    except WebAuthnError as exc:
        return {"ok": False, "reason": exc.reason}
    return {"ok": True, "new_sign_count": result.new_sign_count}


_WEBAUTHN_ASSERT_SHARED, _WEBAUTHN_ASSERT_TESTS = _load_with_shared(
    "identity/mfa/webauthn-assertion.json"
)
_WEBAUTHN_COUNTER_SHARED, _WEBAUTHN_COUNTER_TESTS = _load_with_shared(
    "identity/mfa/webauthn-counter-decrease-rejected.json"
)


@pytest.mark.parametrize(
    "test_case",
    [pytest.param(t, id=t["id"]) for t in _WEBAUTHN_ASSERT_TESTS],
)
def test_webauthn_assertion_conformance(test_case: dict[str, Any]) -> None:
    actual = _run_webauthn(_WEBAUTHN_ASSERT_SHARED, test_case)
    assert actual == test_case["expected"]["result"]


@pytest.mark.parametrize(
    "test_case",
    [pytest.param(t, id=t["id"]) for t in _WEBAUTHN_COUNTER_TESTS],
)
def test_webauthn_counter_conformance(test_case: dict[str, Any]) -> None:
    actual = _run_webauthn(_WEBAUTHN_COUNTER_SHARED, test_case)
    assert actual == test_case["expected"]["result"]
