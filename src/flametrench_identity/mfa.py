# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Multi-factor authentication primitives — v0.2 reference per ADR 0008.

Three first-class factor types:

- TOTP (RFC 6238) — 30-second window, 6-digit codes by default,
  HMAC-SHA1 / HMAC-SHA256 / HMAC-SHA512 supported.
- Recovery codes — 10 single-use codes, each Argon2id-hashed at the
  spec floor; constant-time verification across all 10 slots.
- WebAuthn — factor *records* are supported in this push (enroll +
  pending → active confirmation flow); assertion verification itself
  is deferred to a follow-up PR (the cryptographic surface is large
  enough to deserve its own commit).

The `mfa_` ID prefix is registered in v0.2 (ADR 0008). Until v0.2
ships, this module is non-normative reference code.
"""

from __future__ import annotations

import base64
import hmac
import secrets
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

# ─── Factor types ─────────────────────────────────────────────────


class FactorType(str, Enum):
    """The three v0.2 factor variants."""

    TOTP = "totp"
    WEBAUTHN = "webauthn"
    RECOVERY = "recovery"


class FactorStatus(str, Enum):
    """Lifecycle status of a single factor.

    `pending` — for TOTP/WebAuthn, between enroll() and confirmEnrollment().
    `active` — usable for verifyMfa(). Recovery codes start active.
    `suspended` / `revoked` — terminal-ish (per ADR 0005 lifecycle).
    """

    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


# ─── Public factor records (sensitive payload stripped) ───────────


@dataclass(frozen=True)
class TotpFactor:
    id: str
    usr_id: str
    identifier: str  # human-readable label
    status: FactorStatus
    replaces: str | None
    created_at: datetime
    updated_at: datetime
    type: FactorType = FactorType.TOTP


@dataclass(frozen=True)
class WebAuthnFactor:
    id: str
    usr_id: str
    identifier: str  # WebAuthn credential ID, base64url-encoded
    status: FactorStatus
    replaces: str | None
    rp_id: str
    sign_count: int
    created_at: datetime
    updated_at: datetime
    type: FactorType = FactorType.WEBAUTHN


@dataclass(frozen=True)
class RecoveryFactor:
    id: str
    usr_id: str
    status: FactorStatus
    replaces: str | None
    created_at: datetime
    updated_at: datetime
    # The number of unconsumed codes remaining; the actual hashes are
    # internal to the store. Useful for UI ("3 of 10 codes remaining").
    remaining: int
    type: FactorType = FactorType.RECOVERY
    identifier: str | None = None


Factor = TotpFactor | WebAuthnFactor | RecoveryFactor


# ─── User MFA policy ─────────────────────────────────────────────


@dataclass(frozen=True)
class UserMfaPolicy:
    """Per-user enforcement policy.

    When ``required`` is true and ``grace_until`` is null or past,
    `verifyPassword` produces an MFA-required signal instead of
    minting a session directly.
    """

    usr_id: str
    required: bool
    grace_until: datetime | None
    updated_at: datetime

    def is_active_now(self, now: datetime) -> bool:
        """True when MFA enforcement is active for this user as of `now`."""
        if not self.required:
            return False
        if self.grace_until is None:
            return True
        return now >= self.grace_until


# ─── TOTP (RFC 6238) ──────────────────────────────────────────────

# Default parameters per RFC 6238. Apps MAY override these per factor at
# enrollment time but the spec recommends sticking to defaults for the
# broadest authenticator-app compatibility.

DEFAULT_TOTP_PERIOD = 30  # seconds per code window
DEFAULT_TOTP_DIGITS = 6
DEFAULT_TOTP_ALGORITHM = "sha1"

_TOTP_HASH_LENGTHS = {"sha1": 20, "sha256": 32, "sha512": 64}


def totp_compute(
    secret: bytes,
    timestamp: int,
    *,
    period: int = DEFAULT_TOTP_PERIOD,
    digits: int = DEFAULT_TOTP_DIGITS,
    algorithm: Literal["sha1", "sha256", "sha512"] = DEFAULT_TOTP_ALGORITHM,
) -> str:
    """Compute the TOTP code for a given secret and timestamp.

    Implements the RFC 6238 / RFC 4226 dynamic-truncation algorithm
    directly. Cross-SDK byte-identical because the algorithm is
    deterministic and exhaustively spec'd.

    :param secret: Raw shared-secret bytes (NOT base32-encoded).
    :param timestamp: Unix seconds at which to compute the code.
    :param period: Seconds per code window. Default 30.
    :param digits: Code length. Default 6.
    :param algorithm: HMAC algorithm. Default sha1 for compatibility.
    :returns: Zero-padded numeric code as a string.
    """
    counter = timestamp // period
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.digest(secret, counter_bytes, algorithm)
    offset = digest[-1] & 0x0F
    code_bytes = digest[offset : offset + 4]
    code_int = struct.unpack(">I", code_bytes)[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def totp_verify(
    secret: bytes,
    candidate: str,
    *,
    timestamp: int | None = None,
    period: int = DEFAULT_TOTP_PERIOD,
    digits: int = DEFAULT_TOTP_DIGITS,
    algorithm: Literal["sha1", "sha256", "sha512"] = DEFAULT_TOTP_ALGORITHM,
    drift_windows: int = 1,
) -> bool:
    """Verify a candidate TOTP code with drift tolerance.

    Accepts the code from the current window plus +/- `drift_windows`
    surrounding windows (default ±1, i.e. one window before and one
    window after). Uses constant-time comparison.

    Returns False on length mismatch, non-numeric input, or no match.
    """
    if timestamp is None:
        timestamp = int(datetime.now(timezone.utc).timestamp())
    if not candidate or len(candidate) != digits or not candidate.isdigit():
        return False
    for window_offset in range(-drift_windows, drift_windows + 1):
        ts = timestamp + window_offset * period
        expected = totp_compute(
            secret, ts, period=period, digits=digits, algorithm=algorithm
        )
        if hmac.compare_digest(expected, candidate):
            return True
    return False


def generate_totp_secret(*, num_bytes: int = 20) -> bytes:
    """Generate a fresh TOTP shared secret.

    20 bytes (160 bits) is the RFC 6238 recommended minimum for SHA-1.
    """
    return secrets.token_bytes(num_bytes)


def totp_otpauth_uri(
    *,
    secret: bytes,
    label: str,
    issuer: str,
    algorithm: str = DEFAULT_TOTP_ALGORITHM,
    digits: int = DEFAULT_TOTP_DIGITS,
    period: int = DEFAULT_TOTP_PERIOD,
) -> str:
    """Build the otpauth:// URI for QR-code rendering at enrollment.

    Format follows the de-facto Google Authenticator key URI standard.
    """
    secret_b32 = base64.b32encode(secret).rstrip(b"=").decode("ascii")
    from urllib.parse import quote

    label_q = quote(f"{issuer}:{label}", safe="")
    issuer_q = quote(issuer, safe="")
    return (
        f"otpauth://totp/{label_q}"
        f"?secret={secret_b32}"
        f"&issuer={issuer_q}"
        f"&algorithm={algorithm.upper()}"
        f"&digits={digits}"
        f"&period={period}"
    )


# ─── Recovery codes ──────────────────────────────────────────────

# 12-character codes in three groups of four, separated by hyphens.
# Alphabet excludes 0/O/1/I/L for reading clarity. Generated from
# random bytes with rejection sampling; constant-time-verified
# across all 10 slots.

_RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # 31 chars
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_LENGTH = 12  # raw chars, not counting hyphens


def generate_recovery_code() -> str:
    """Generate one fresh 12-char recovery code, formatted XXXX-XXXX-XXXX."""
    chars = "".join(
        secrets.choice(_RECOVERY_ALPHABET) for _ in range(RECOVERY_CODE_LENGTH)
    )
    return f"{chars[0:4]}-{chars[4:8]}-{chars[8:12]}"


def generate_recovery_codes() -> list[str]:
    """Generate a fresh set of 10 recovery codes."""
    return [generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]


def normalize_recovery_input(code: str) -> str:
    """Normalize user-input recovery code: uppercase, strip whitespace.

    Hyphens are preserved. Implementations MAY accept codes without
    hyphens too, but normalization shouldn't strip them.
    """
    return code.strip().upper()


def is_valid_recovery_code(code: str) -> bool:
    """Predicate: does ``code`` match the canonical 12-char three-group form?

    True iff:
      - exactly 14 chars (12 alphabet + 2 hyphens)
      - three groups of four, hyphen-separated
      - every group consists of characters from the recovery alphabet
        (excludes 0/O/1/I/L)
      - all chars are uppercase ASCII

    Used for spec-pinned format validation. The canonical form is what
    the SDK generates and what the conformance fixture exercises.
    Apps that want to accept lowercase or hyphen-stripped input MUST
    normalize first via :func:`normalize_recovery_input`.
    """
    if len(code) != RECOVERY_CODE_LENGTH + 2:  # 12 chars + 2 hyphens
        return False
    parts = code.split("-")
    if len(parts) != 3:
        return False
    for part in parts:
        if len(part) != 4:
            return False
        for ch in part:
            if ch not in _RECOVERY_ALPHABET:
                return False
    return True
