# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Error types raised by the identity layer.

Every error carries a stable `code` matching the OpenAPI Error envelope.
"""

from __future__ import annotations


class IdentityError(Exception):
    """Base class for every identity-layer error."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class NotFoundError(IdentityError):
    """The requested entity does not exist."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="not_found")


class DuplicateCredentialError(IdentityError):
    """An active credential of the same type and identifier already exists."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="conflict.duplicate_credential")


class InvalidCredentialError(IdentityError):
    """The candidate credential failed verification.

    Raised for both unknown identifiers and bad passwords — the message is
    intentionally generic to avoid disclosing which arm failed.
    """

    def __init__(self, message: str = "Invalid credential") -> None:
        super().__init__(message, code="invalid_credential")


class InvalidTokenError(IdentityError):
    """The bearer token is unknown or malformed."""

    def __init__(self, message: str = "Invalid token") -> None:
        super().__init__(message, code="invalid_token")


class SessionExpiredError(IdentityError):
    """The session is past its expiry or has been revoked."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="session_expired")


class CredentialNotActiveError(IdentityError):
    """Operation requires an active credential, but it is suspended/revoked."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="cred_not_active")


class CredentialTypeMismatchError(IdentityError):
    """Operation expected a different credential type."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="cred_type_mismatch")


class AlreadyTerminalError(IdentityError):
    """Cannot transition; the entity is already in a terminal state."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="already_terminal")


class PreconditionError(IdentityError):
    """A precondition for the requested transition was not met.

    Carries an additional ``reason`` token (e.g. ``user_not_active``,
    ``invalid_transition``) to disambiguate.
    """

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message, code=f"precondition.{reason}")
        self.reason = reason


class InvalidPatTokenError(IdentityError):
    """Raised by verify_pat_token when the bearer is malformed, references
    a non-existent pat row, or carries the wrong secret (ADR 0016).

    The "no row" and "wrong secret" cases MUST conflate to this single
    error class with an identical message — distinguishable errors leak
    token-presence as a timing oracle. See ADR 0016
    §"Verification semantics".
    """

    def __init__(self, message: str = "invalid personal access token") -> None:
        super().__init__(message, code="pat.invalid")


class PatExpiredError(IdentityError):
    """Raised by verify_pat_token when the pat row exists, has not been
    revoked, but is past its expires_at (ADR 0016)."""

    def __init__(self, pat_id: str) -> None:
        super().__init__(
            f"personal access token {pat_id} is expired",
            code="pat.expired",
        )


class PatRevokedError(IdentityError):
    """Raised by verify_pat_token when the pat row has been explicitly
    revoked via revoke_pat (ADR 0016). Terminal."""

    def __init__(self, pat_id: str) -> None:
        super().__init__(
            f"personal access token {pat_id} is revoked",
            code="pat.revoked",
        )
