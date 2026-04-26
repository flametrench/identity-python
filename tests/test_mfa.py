# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for v0.2 MFA primitives.

Covers TOTP RFC 6238 vectors, drift tolerance + replay rejection,
recovery-code format and consumption semantics. WebAuthn assertion
verification is deferred to a follow-up; only the factor-record
shape is exercised here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from flametrench_identity import (
    DEFAULT_TOTP_DIGITS,
    DEFAULT_TOTP_PERIOD,
    RECOVERY_CODE_COUNT,
    RECOVERY_CODE_LENGTH,
    UserMfaPolicy,
    generate_recovery_code,
    generate_recovery_codes,
    generate_totp_secret,
    normalize_recovery_input,
    totp_compute,
    totp_otpauth_uri,
    totp_verify,
)


# ─── TOTP ─────────────────────────────────────────────────────────


class TestTotpRfc6238Vectors:
    """RFC 6238 §B test vectors. The shared secret is the ASCII bytes of
    "12345678901234567890" for SHA-1, "12345678901234567890123456789012"
    for SHA-256, and 64 ASCII bytes for SHA-512. These are the canonical
    test inputs every conforming TOTP implementation MUST satisfy."""

    SECRET_SHA1 = b"12345678901234567890"
    SECRET_SHA256 = b"12345678901234567890123456789012"
    SECRET_SHA512 = b"1234567890123456789012345678901234567890123456789012345678901234"

    @pytest.mark.parametrize(
        "timestamp,expected",
        [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ],
    )
    def test_sha1_8digit(self, timestamp: int, expected: str) -> None:
        # RFC 6238 §B test vectors are at 8 digits.
        assert (
            totp_compute(self.SECRET_SHA1, timestamp, digits=8, algorithm="sha1")
            == expected
        )

    @pytest.mark.parametrize(
        "timestamp,expected",
        [
            (59, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ],
    )
    def test_sha256_8digit(self, timestamp: int, expected: str) -> None:
        assert (
            totp_compute(self.SECRET_SHA256, timestamp, digits=8, algorithm="sha256")
            == expected
        )

    @pytest.mark.parametrize(
        "timestamp,expected",
        [
            (59, "90693936"),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ],
    )
    def test_sha512_8digit(self, timestamp: int, expected: str) -> None:
        assert (
            totp_compute(self.SECRET_SHA512, timestamp, digits=8, algorithm="sha512")
            == expected
        )


class TestTotpVerify:
    def test_verify_current_window(self) -> None:
        secret = b"12345678901234567890"
        # Compute a code at a known timestamp, verify it within drift.
        ts = 1234567890
        code = totp_compute(secret, ts, digits=6)
        assert totp_verify(secret, code, timestamp=ts, digits=6) is True

    def test_verify_drift_minus_one_window(self) -> None:
        secret = b"12345678901234567890"
        ts = 1234567890
        # Code from one window earlier should still verify with default drift=1.
        prev_code = totp_compute(secret, ts - DEFAULT_TOTP_PERIOD, digits=6)
        assert totp_verify(secret, prev_code, timestamp=ts, digits=6) is True

    def test_verify_drift_plus_one_window(self) -> None:
        secret = b"12345678901234567890"
        ts = 1234567890
        next_code = totp_compute(secret, ts + DEFAULT_TOTP_PERIOD, digits=6)
        assert totp_verify(secret, next_code, timestamp=ts, digits=6) is True

    def test_verify_drift_two_windows_rejected_with_default_drift(self) -> None:
        secret = b"12345678901234567890"
        ts = 1234567890
        # Two windows in the past should NOT verify with drift=1.
        old_code = totp_compute(secret, ts - 2 * DEFAULT_TOTP_PERIOD, digits=6)
        assert totp_verify(secret, old_code, timestamp=ts, digits=6) is False

    def test_verify_garbage_input(self) -> None:
        secret = b"12345678901234567890"
        assert totp_verify(secret, "abc", timestamp=1234567890) is False
        assert totp_verify(secret, "", timestamp=1234567890) is False
        assert totp_verify(secret, "12345", timestamp=1234567890) is False  # wrong length

    def test_verify_wrong_code(self) -> None:
        secret = b"12345678901234567890"
        ts = 1234567890
        assert totp_verify(secret, "000000", timestamp=ts, digits=6) is False


class TestTotpSecretGeneration:
    def test_default_length_is_20_bytes(self) -> None:
        s = generate_totp_secret()
        assert len(s) == 20

    def test_secrets_are_unique(self) -> None:
        secrets_set = {generate_totp_secret() for _ in range(50)}
        assert len(secrets_set) == 50


class TestOtpauthUri:
    def test_uri_contains_secret_label_and_issuer(self) -> None:
        secret = b"12345678901234567890"
        uri = totp_otpauth_uri(
            secret=secret,
            label="alice@example.com",
            issuer="Flametrench",
        )
        assert uri.startswith("otpauth://totp/")
        assert "Flametrench" in uri
        # Encoded "@" → "%40"
        assert "alice%40example.com" in uri
        assert "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" in uri  # base32 of secret


# ─── Recovery codes ──────────────────────────────────────────────


class TestRecoveryCodeFormat:
    def test_one_code_has_correct_format(self) -> None:
        code = generate_recovery_code()
        # XXXX-XXXX-XXXX
        assert len(code) == RECOVERY_CODE_LENGTH + 2  # 12 chars + 2 hyphens
        parts = code.split("-")
        assert len(parts) == 3
        for part in parts:
            assert len(part) == 4

    def test_alphabet_excludes_ambiguous_chars(self) -> None:
        code = generate_recovery_code()
        # No 0, O, 1, I, L
        for ch in "01OIL":
            assert ch not in code

    def test_only_uppercase(self) -> None:
        code = generate_recovery_code()
        for ch in code.replace("-", ""):
            assert ch.isupper() or ch.isdigit()

    def test_set_has_correct_count(self) -> None:
        codes = generate_recovery_codes()
        assert len(codes) == RECOVERY_CODE_COUNT

    def test_set_codes_are_unique(self) -> None:
        codes = generate_recovery_codes()
        assert len(set(codes)) == RECOVERY_CODE_COUNT

    def test_normalize_uppercases_and_strips(self) -> None:
        assert normalize_recovery_input("  abcd-efgh-jkmn  ") == "ABCD-EFGH-JKMN"

    def test_normalize_preserves_hyphens(self) -> None:
        assert normalize_recovery_input("abcd-efgh-jkmn") == "ABCD-EFGH-JKMN"


# ─── User MFA policy ─────────────────────────────────────────────


class TestUserMfaPolicy:
    def test_required_with_no_grace_is_active(self) -> None:
        now = datetime.now(timezone.utc)
        p = UserMfaPolicy(
            usr_id="usr_x",
            required=True,
            grace_until=None,
            updated_at=now,
        )
        assert p.is_active_now(now) is True

    def test_required_with_future_grace_is_inactive(self) -> None:
        now = datetime.now(timezone.utc)
        p = UserMfaPolicy(
            usr_id="usr_x",
            required=True,
            grace_until=now + timedelta(days=7),
            updated_at=now,
        )
        assert p.is_active_now(now) is False

    def test_required_with_past_grace_is_active(self) -> None:
        now = datetime.now(timezone.utc)
        p = UserMfaPolicy(
            usr_id="usr_x",
            required=True,
            grace_until=now - timedelta(days=1),
            updated_at=now,
        )
        assert p.is_active_now(now) is True

    def test_not_required_is_inactive(self) -> None:
        now = datetime.now(timezone.utc)
        p = UserMfaPolicy(
            usr_id="usr_x",
            required=False,
            grace_until=None,
            updated_at=now,
        )
        assert p.is_active_now(now) is False
