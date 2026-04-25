# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""flametrench-identity — users, credentials, and user-bound sessions.

The spec-normative identity layer for Flametrench v0.1. See the upstream
specification at
https://github.com/flametrench/spec/blob/main/docs/identity.md.

Argon2id is pinned at the OWASP floor (m=19456 KiB, t=2, p=1). PHC-encoded
hashes produced by this SDK verify identically under the Node and PHP
SDKs — the conformance suite proves it mechanically.
"""

from .errors import (
    AlreadyTerminalError,
    CredentialNotActiveError,
    CredentialTypeMismatchError,
    DuplicateCredentialError,
    IdentityError,
    InvalidCredentialError,
    InvalidTokenError,
    NotFoundError,
    PreconditionError,
    SessionExpiredError,
)
from .hashing import hash_password, verify_password_hash
from .in_memory import InMemoryIdentityStore
from .store import IdentityStore
from .types import (
    ARGON2ID_FLOOR,
    Credential,
    CredentialType,
    OidcCredential,
    Page,
    PasskeyCredential,
    PasswordCredential,
    Session,
    SessionWithToken,
    Status,
    User,
    VerifiedCredential,
)

__all__ = [
    "ARGON2ID_FLOOR",
    "AlreadyTerminalError",
    "Credential",
    "CredentialNotActiveError",
    "CredentialType",
    "CredentialTypeMismatchError",
    "DuplicateCredentialError",
    "IdentityError",
    "IdentityStore",
    "InMemoryIdentityStore",
    "InvalidCredentialError",
    "InvalidTokenError",
    "NotFoundError",
    "OidcCredential",
    "Page",
    "PasskeyCredential",
    "PasswordCredential",
    "PreconditionError",
    "Session",
    "SessionExpiredError",
    "SessionWithToken",
    "Status",
    "User",
    "VerifiedCredential",
    "hash_password",
    "verify_password_hash",
]

__version__ = "0.1.0"
