# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Identity entity types.

Frozen dataclasses for cross-language parity with the readonly classes
used in the PHP and Node SDKs. Status and CredentialType are str-valued
enums so wire serialization is trivial.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Generic, TypeVar, Union

T = TypeVar("T")


class Status(str, Enum):
    """User and credential lifecycle status."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class CredentialType(str, Enum):
    """The three credential variants supported in v0.1."""

    PASSWORD = "password"
    PASSKEY = "passkey"
    OIDC = "oidc"


# ─── Argon2id parameter floors (spec-required) ───

# Minimum Argon2id parameters for password hashing. Implementations MUST
# use values at or above these. See spec/docs/identity.md §"Hashing
# requirements" and ADR 0004.
ARGON2ID_FLOOR = {
    "memory_cost": 19456,  # KiB (= 19 MiB)
    "time_cost": 2,
    "parallelism": 1,
}


# ─── Entities ───


@dataclass(frozen=True)
class User:
    id: str
    status: Status
    created_at: datetime
    updated_at: datetime
    #: ADR 0014 (v0.2) — optional human-meaningful render string.
    display_name: str | None = None

    def with_status(self, status: Status, updated_at: datetime) -> "User":
        return User(
            id=self.id,
            status=status,
            created_at=self.created_at,
            updated_at=updated_at,
            display_name=self.display_name,
        )


@dataclass(frozen=True)
class PasswordCredential:
    id: str
    usr_id: str
    identifier: str
    status: Status
    replaces: str | None
    created_at: datetime
    updated_at: datetime
    type: CredentialType = CredentialType.PASSWORD


@dataclass(frozen=True)
class PasskeyCredential:
    id: str
    usr_id: str
    identifier: str
    status: Status
    replaces: str | None
    passkey_sign_count: int
    passkey_rp_id: str
    created_at: datetime
    updated_at: datetime
    type: CredentialType = CredentialType.PASSKEY


@dataclass(frozen=True)
class OidcCredential:
    id: str
    usr_id: str
    identifier: str
    status: Status
    replaces: str | None
    oidc_issuer: str
    oidc_subject: str
    created_at: datetime
    updated_at: datetime
    type: CredentialType = CredentialType.OIDC


# Public union — safe to expose to callers. Excludes sensitive material
# (password hashes, passkey public keys are stored internally only).
Credential = Union[PasswordCredential, PasskeyCredential, OidcCredential]


@dataclass(frozen=True)
class Session:
    id: str
    usr_id: str
    cred_id: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None

    def with_revoked_at(self, at: datetime) -> "Session":
        return Session(
            id=self.id,
            usr_id=self.usr_id,
            cred_id=self.cred_id,
            created_at=self.created_at,
            expires_at=self.expires_at,
            revoked_at=at,
        )


@dataclass(frozen=True)
class SessionWithToken:
    """Returned by create_session / refresh_session.

    ``token`` is the opaque bearer credential — the only chance to
    capture it. Implementations store only its SHA-256 hash.
    """

    session: Session
    token: str


@dataclass(frozen=True)
class VerifiedCredential:
    usr_id: str
    cred_id: str
    # ``True`` when ``usr_mfa_policy.required`` is true AND the grace
    # window has elapsed (or was never set). Applications MUST call
    # ``verify_mfa`` before ``create_session`` when this is true.
    # Defaults to ``False`` so adopters who never enable a policy see
    # no behavioral change. (ADR 0008.)
    mfa_required: bool = False


@dataclass(frozen=True)
class Page(Generic[T]):
    data: list[T]
    next_cursor: str | None
