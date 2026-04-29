# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""IdentityStore — the contract every identity backend implements.

Cascade guarantees (spec-required):

- Revoking a user revokes every active credential AND terminates every
  active session.
- Suspending a user terminates active sessions but preserves credentials.
- Rotating a credential terminates every session bound to the old.
- Revoking or suspending a credential terminates every session bound to it.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .types import (
    Credential,
    CredentialType,
    OidcCredential,
    Page,
    PasskeyCredential,
    PasswordCredential,
    Session,
    SessionWithToken,
    User,
    VerifiedCredential,
)


@runtime_checkable
class IdentityStore(Protocol):
    # ─── Users ───
    def create_user(self, *, display_name: str | None = None) -> User: ...
    def get_user(self, usr_id: str) -> User: ...
    def update_user(
        self,
        usr_id: str,
        *,
        display_name: object = ...,
    ) -> User:
        """ADR 0014 partial update of v0.2 user metadata.

        Omitted parameter (sentinel) means "don't change"; explicit
        ``None`` means "set to null." Implementations export the
        sentinel as a module-level constant for callers that need to
        forward partial inputs.
        """
        ...
    def suspend_user(self, usr_id: str) -> User: ...
    def reinstate_user(self, usr_id: str) -> User: ...
    def revoke_user(self, usr_id: str) -> User: ...

    # ─── Credentials ───
    def create_password_credential(
        self, usr_id: str, identifier: str, password: str
    ) -> PasswordCredential: ...

    def create_passkey_credential(
        self,
        usr_id: str,
        identifier: str,
        public_key: bytes,
        sign_count: int,
        rp_id: str,
    ) -> PasskeyCredential: ...

    def create_oidc_credential(
        self,
        usr_id: str,
        identifier: str,
        oidc_issuer: str,
        oidc_subject: str,
    ) -> OidcCredential: ...

    def get_credential(self, cred_id: str) -> Credential: ...

    def list_credentials_for_user(self, usr_id: str) -> list[Credential]: ...

    def find_credential_by_identifier(
        self, type: CredentialType, identifier: str
    ) -> Credential | None: ...

    def rotate_password(self, cred_id: str, new_password: str) -> PasswordCredential: ...
    def rotate_passkey(
        self, cred_id: str, public_key: bytes, sign_count: int, rp_id: str
    ) -> PasskeyCredential: ...
    def rotate_oidc(
        self, cred_id: str, oidc_issuer: str, oidc_subject: str
    ) -> OidcCredential: ...

    def suspend_credential(self, cred_id: str) -> Credential: ...
    def reinstate_credential(self, cred_id: str) -> Credential: ...
    def revoke_credential(self, cred_id: str) -> Credential: ...

    def verify_password(self, identifier: str, password: str) -> VerifiedCredential: ...

    # ─── Sessions ───
    def create_session(
        self, usr_id: str, cred_id: str, ttl_seconds: int
    ) -> SessionWithToken: ...

    def get_session(self, ses_id: str) -> Session: ...

    def list_sessions_for_user(
        self, usr_id: str, *, cursor: str | None = None, limit: int = 50
    ) -> Page[Session]: ...

    def verify_session_token(self, token: str) -> Session: ...

    def refresh_session(self, ses_id: str) -> SessionWithToken: ...

    def revoke_session(self, ses_id: str) -> Session: ...
