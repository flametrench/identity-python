# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Flametrench v0.2 conformance suite — MFA fixtures (Python harness).

Two fixture files in this push:

- ``identity/mfa/totp-rfc6238.json`` — RFC 6238 §B test vectors.
  Pins TOTP byte-identically to the RFC, which transitively pins it
  byte-identically across Flametrench SDKs.
- ``identity/mfa/recovery-code-format.json`` — recovery-code format
  invariants (alphabet, group size, hyphen separators).

WebAuthn assertion verification is deferred to a follow-up commit;
its fixture corpus and harness will land alongside the SDK
implementation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from flametrench_identity import (
    is_valid_recovery_code,
    totp_compute,
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
