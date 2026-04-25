# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Reference in-memory IdentityStore implementation.

Argon2id passwords use argon2-cffi at the spec floor (m=19456, t=2, p=1).
Bearer tokens are 32 random bytes, base64url-encoded; only the SHA-256
hash is persisted, never the token itself.

Internally tracks public Credential objects alongside type-specific
sensitive material (password hashes, passkey public keys) in separate
dicts so the public surface never leaks them.
"""

from __future__ import annotations

import hmac
import secrets
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Callable

from flametrench_ids import generate

from .errors import (
    AlreadyTerminalError,
    CredentialNotActiveError,
    CredentialTypeMismatchError,
    DuplicateCredentialError,
    InvalidCredentialError,
    InvalidTokenError,
    NotFoundError,
    PreconditionError,
    SessionExpiredError,
)
from .hashing import hash_password, verify_password_hash
from .types import (
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


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


class InMemoryIdentityStore:
    """Reference in-memory implementation of IdentityStore."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._users: dict[str, User] = {}
        self._credentials: dict[str, Credential] = {}
        self._password_hashes: dict[str, str] = {}  # cred_id → PHC hash
        self._passkey_public_keys: dict[str, bytes] = {}
        # Natural-key index: f"{type.value}|{identifier}" → cred_id (active only)
        self._active_cred_by_identifier: dict[str, str] = {}
        self._sessions: dict[str, Session] = {}
        self._session_token_hashes: dict[str, str] = {}  # ses_id → token-hash
        self._session_by_token_hash: dict[str, str] = {}  # token-hash → ses_id
        self._clock = clock or _default_clock

    # ─── Internal helpers ───

    def _now(self) -> datetime:
        return self._clock()

    @staticmethod
    def _identifier_key(type: CredentialType, identifier: str) -> str:
        return f"{type.value}|{identifier}"

    def _require_user(self, usr_id: str) -> User:
        u = self._users.get(usr_id)
        if u is None:
            raise NotFoundError(f"User {usr_id} not found")
        return u

    def _require_credential(self, cred_id: str) -> Credential:
        c = self._credentials.get(cred_id)
        if c is None:
            raise NotFoundError(f"Credential {cred_id} not found")
        return c

    def _require_session(self, ses_id: str) -> Session:
        s = self._sessions.get(ses_id)
        if s is None:
            raise NotFoundError(f"Session {ses_id} not found")
        return s

    def _cascade_revoke_sessions_for_credential(self, cred_id: str) -> None:
        now = self._now()
        for ses_id, ses in list(self._sessions.items()):
            if ses.cred_id == cred_id and ses.revoked_at is None:
                self._sessions[ses_id] = ses.with_revoked_at(now)
                token_hash = self._session_token_hashes.pop(ses_id, None)
                if token_hash is not None:
                    self._session_by_token_hash.pop(token_hash, None)

    def _cascade_revoke_sessions_for_user(self, usr_id: str) -> None:
        now = self._now()
        for ses_id, ses in list(self._sessions.items()):
            if ses.usr_id == usr_id and ses.revoked_at is None:
                self._sessions[ses_id] = ses.with_revoked_at(now)
                token_hash = self._session_token_hashes.pop(ses_id, None)
                if token_hash is not None:
                    self._session_by_token_hash.pop(token_hash, None)

    @staticmethod
    def _with_credential_status(
        cred: Credential, status: Status, updated_at: datetime
    ) -> Credential:
        if isinstance(cred, PasswordCredential):
            return PasswordCredential(
                id=cred.id,
                usr_id=cred.usr_id,
                identifier=cred.identifier,
                status=status,
                replaces=cred.replaces,
                created_at=cred.created_at,
                updated_at=updated_at,
            )
        if isinstance(cred, PasskeyCredential):
            return PasskeyCredential(
                id=cred.id,
                usr_id=cred.usr_id,
                identifier=cred.identifier,
                status=status,
                replaces=cred.replaces,
                passkey_sign_count=cred.passkey_sign_count,
                passkey_rp_id=cred.passkey_rp_id,
                created_at=cred.created_at,
                updated_at=updated_at,
            )
        # OidcCredential
        return OidcCredential(
            id=cred.id,
            usr_id=cred.usr_id,
            identifier=cred.identifier,
            status=status,
            replaces=cred.replaces,
            oidc_issuer=cred.oidc_issuer,
            oidc_subject=cred.oidc_subject,
            created_at=cred.created_at,
            updated_at=updated_at,
        )

    def _ensure_user_active_and_unique_identifier(
        self, usr_id: str, type: CredentialType, identifier: str
    ) -> None:
        user = self._require_user(usr_id)
        if user.status != Status.ACTIVE:
            raise PreconditionError(
                f"Cannot create credentials for {user.status.value} user",
                reason="user_not_active",
            )
        key = self._identifier_key(type, identifier)
        if key in self._active_cred_by_identifier:
            raise DuplicateCredentialError(
                f"An active {type.value} credential already exists for identifier {identifier}",
            )

    # ─── Users ───

    def create_user(self) -> User:
        now = self._now()
        u = User(id=generate("usr"), status=Status.ACTIVE, created_at=now, updated_at=now)
        self._users[u.id] = u
        return u

    def get_user(self, usr_id: str) -> User:
        return self._require_user(usr_id)

    def suspend_user(self, usr_id: str) -> User:
        u = self._require_user(usr_id)
        if u.status == Status.REVOKED:
            raise AlreadyTerminalError(f"User {usr_id} is revoked")
        if u.status == Status.SUSPENDED:
            return u
        now = self._now()
        updated = u.with_status(Status.SUSPENDED, now)
        self._users[usr_id] = updated
        self._cascade_revoke_sessions_for_user(usr_id)
        return updated

    def reinstate_user(self, usr_id: str) -> User:
        u = self._require_user(usr_id)
        if u.status != Status.SUSPENDED:
            raise PreconditionError(
                f"User {usr_id} is {u.status.value}; only suspended users can be reinstated",
                reason="invalid_transition",
            )
        updated = u.with_status(Status.ACTIVE, self._now())
        self._users[usr_id] = updated
        return updated

    def revoke_user(self, usr_id: str) -> User:
        u = self._require_user(usr_id)
        if u.status == Status.REVOKED:
            raise AlreadyTerminalError(f"User {usr_id} is already revoked")
        now = self._now()
        # Cascade: revoke all active credentials.
        for cred_id, cred in list(self._credentials.items()):
            if cred.usr_id == usr_id and cred.status == Status.ACTIVE:
                self._credentials[cred_id] = self._with_credential_status(
                    cred, Status.REVOKED, now
                )
                self._active_cred_by_identifier.pop(
                    self._identifier_key(cred.type, cred.identifier), None
                )
        self._cascade_revoke_sessions_for_user(usr_id)
        updated = u.with_status(Status.REVOKED, now)
        self._users[usr_id] = updated
        return updated

    # ─── Credentials ───

    def create_password_credential(
        self, usr_id: str, identifier: str, password: str
    ) -> PasswordCredential:
        self._ensure_user_active_and_unique_identifier(
            usr_id, CredentialType.PASSWORD, identifier
        )
        now = self._now()
        cred_id = generate("cred")
        phc = hash_password(password)
        cred = PasswordCredential(
            id=cred_id,
            usr_id=usr_id,
            identifier=identifier,
            status=Status.ACTIVE,
            replaces=None,
            created_at=now,
            updated_at=now,
        )
        self._credentials[cred_id] = cred
        self._password_hashes[cred_id] = phc
        self._active_cred_by_identifier[
            self._identifier_key(CredentialType.PASSWORD, identifier)
        ] = cred_id
        return cred

    def create_passkey_credential(
        self,
        usr_id: str,
        identifier: str,
        public_key: bytes,
        sign_count: int,
        rp_id: str,
    ) -> PasskeyCredential:
        self._ensure_user_active_and_unique_identifier(
            usr_id, CredentialType.PASSKEY, identifier
        )
        now = self._now()
        cred_id = generate("cred")
        cred = PasskeyCredential(
            id=cred_id,
            usr_id=usr_id,
            identifier=identifier,
            status=Status.ACTIVE,
            replaces=None,
            passkey_sign_count=sign_count,
            passkey_rp_id=rp_id,
            created_at=now,
            updated_at=now,
        )
        self._credentials[cred_id] = cred
        self._passkey_public_keys[cred_id] = public_key
        self._active_cred_by_identifier[
            self._identifier_key(CredentialType.PASSKEY, identifier)
        ] = cred_id
        return cred

    def create_oidc_credential(
        self,
        usr_id: str,
        identifier: str,
        oidc_issuer: str,
        oidc_subject: str,
    ) -> OidcCredential:
        self._ensure_user_active_and_unique_identifier(
            usr_id, CredentialType.OIDC, identifier
        )
        now = self._now()
        cred_id = generate("cred")
        cred = OidcCredential(
            id=cred_id,
            usr_id=usr_id,
            identifier=identifier,
            status=Status.ACTIVE,
            replaces=None,
            oidc_issuer=oidc_issuer,
            oidc_subject=oidc_subject,
            created_at=now,
            updated_at=now,
        )
        self._credentials[cred_id] = cred
        self._active_cred_by_identifier[
            self._identifier_key(CredentialType.OIDC, identifier)
        ] = cred_id
        return cred

    def get_credential(self, cred_id: str) -> Credential:
        return self._require_credential(cred_id)

    def list_credentials_for_user(self, usr_id: str) -> list[Credential]:
        return [c for c in self._credentials.values() if c.usr_id == usr_id]

    def find_credential_by_identifier(
        self, type: CredentialType, identifier: str
    ) -> Credential | None:
        cred_id = self._active_cred_by_identifier.get(
            self._identifier_key(type, identifier)
        )
        if cred_id is None:
            return None
        return self._require_credential(cred_id)

    def rotate_password(self, cred_id: str, new_password: str) -> PasswordCredential:
        old = self._require_credential(cred_id)
        if old.status != Status.ACTIVE:
            raise CredentialNotActiveError(
                f"Credential {cred_id} is {old.status.value}"
            )
        if not isinstance(old, PasswordCredential):
            raise CredentialTypeMismatchError(
                f"Cannot rotate {old.type.value} credential as password",
            )
        now = self._now()
        # Revoke old.
        self._credentials[old.id] = self._with_credential_status(old, Status.REVOKED, now)
        self._active_cred_by_identifier.pop(
            self._identifier_key(CredentialType.PASSWORD, old.identifier), None
        )
        self._password_hashes.pop(old.id, None)
        self._cascade_revoke_sessions_for_credential(old.id)
        # Insert new.
        new_id = generate("cred")
        phc = hash_password(new_password)
        fresh = PasswordCredential(
            id=new_id,
            usr_id=old.usr_id,
            identifier=old.identifier,
            status=Status.ACTIVE,
            replaces=old.id,
            created_at=now,
            updated_at=now,
        )
        self._credentials[new_id] = fresh
        self._password_hashes[new_id] = phc
        self._active_cred_by_identifier[
            self._identifier_key(CredentialType.PASSWORD, old.identifier)
        ] = new_id
        return fresh

    def rotate_passkey(
        self, cred_id: str, public_key: bytes, sign_count: int, rp_id: str
    ) -> PasskeyCredential:
        old = self._require_credential(cred_id)
        if old.status != Status.ACTIVE:
            raise CredentialNotActiveError(
                f"Credential {cred_id} is {old.status.value}"
            )
        if not isinstance(old, PasskeyCredential):
            raise CredentialTypeMismatchError(
                f"Cannot rotate {old.type.value} credential as passkey",
            )
        now = self._now()
        self._credentials[old.id] = self._with_credential_status(old, Status.REVOKED, now)
        self._active_cred_by_identifier.pop(
            self._identifier_key(CredentialType.PASSKEY, old.identifier), None
        )
        self._passkey_public_keys.pop(old.id, None)
        self._cascade_revoke_sessions_for_credential(old.id)
        new_id = generate("cred")
        fresh = PasskeyCredential(
            id=new_id,
            usr_id=old.usr_id,
            identifier=old.identifier,
            status=Status.ACTIVE,
            replaces=old.id,
            passkey_sign_count=sign_count,
            passkey_rp_id=rp_id,
            created_at=now,
            updated_at=now,
        )
        self._credentials[new_id] = fresh
        self._passkey_public_keys[new_id] = public_key
        self._active_cred_by_identifier[
            self._identifier_key(CredentialType.PASSKEY, old.identifier)
        ] = new_id
        return fresh

    def rotate_oidc(
        self, cred_id: str, oidc_issuer: str, oidc_subject: str
    ) -> OidcCredential:
        old = self._require_credential(cred_id)
        if old.status != Status.ACTIVE:
            raise CredentialNotActiveError(
                f"Credential {cred_id} is {old.status.value}"
            )
        if not isinstance(old, OidcCredential):
            raise CredentialTypeMismatchError(
                f"Cannot rotate {old.type.value} credential as oidc",
            )
        now = self._now()
        self._credentials[old.id] = self._with_credential_status(old, Status.REVOKED, now)
        self._active_cred_by_identifier.pop(
            self._identifier_key(CredentialType.OIDC, old.identifier), None
        )
        self._cascade_revoke_sessions_for_credential(old.id)
        new_id = generate("cred")
        fresh = OidcCredential(
            id=new_id,
            usr_id=old.usr_id,
            identifier=old.identifier,
            status=Status.ACTIVE,
            replaces=old.id,
            oidc_issuer=oidc_issuer,
            oidc_subject=oidc_subject,
            created_at=now,
            updated_at=now,
        )
        self._credentials[new_id] = fresh
        self._active_cred_by_identifier[
            self._identifier_key(CredentialType.OIDC, old.identifier)
        ] = new_id
        return fresh

    def suspend_credential(self, cred_id: str) -> Credential:
        c = self._require_credential(cred_id)
        if c.status != Status.ACTIVE:
            raise PreconditionError(
                f"Credential {cred_id} is {c.status.value}; only active credentials can be suspended",
                reason="cred_not_active",
            )
        now = self._now()
        updated = self._with_credential_status(c, Status.SUSPENDED, now)
        self._credentials[cred_id] = updated
        self._active_cred_by_identifier.pop(
            self._identifier_key(c.type, c.identifier), None
        )
        self._cascade_revoke_sessions_for_credential(cred_id)
        return updated

    def reinstate_credential(self, cred_id: str) -> Credential:
        c = self._require_credential(cred_id)
        if c.status != Status.SUSPENDED:
            raise PreconditionError(
                f"Credential {cred_id} is {c.status.value}; only suspended credentials can be reinstated",
                reason="invalid_transition",
            )
        key = self._identifier_key(c.type, c.identifier)
        if key in self._active_cred_by_identifier:
            raise DuplicateCredentialError(
                f"Another active {c.type.value} credential already exists for {c.identifier}; cannot reinstate",
            )
        now = self._now()
        updated = self._with_credential_status(c, Status.ACTIVE, now)
        self._credentials[cred_id] = updated
        self._active_cred_by_identifier[key] = cred_id
        return updated

    def revoke_credential(self, cred_id: str) -> Credential:
        c = self._require_credential(cred_id)
        if c.status == Status.REVOKED:
            raise AlreadyTerminalError(f"Credential {cred_id} is already revoked")
        now = self._now()
        updated = self._with_credential_status(c, Status.REVOKED, now)
        self._credentials[cred_id] = updated
        self._active_cred_by_identifier.pop(
            self._identifier_key(c.type, c.identifier), None
        )
        self._cascade_revoke_sessions_for_credential(cred_id)
        return updated

    def verify_password(self, identifier: str, password: str) -> VerifiedCredential:
        cred_id = self._active_cred_by_identifier.get(
            self._identifier_key(CredentialType.PASSWORD, identifier)
        )
        if cred_id is None:
            raise InvalidCredentialError()
        cred = self._require_credential(cred_id)
        if not isinstance(cred, PasswordCredential):
            # Type-scoped index makes this defensive.
            raise InvalidCredentialError()
        phc = self._password_hashes.get(cred_id)
        if phc is None or not verify_password_hash(phc, password):
            raise InvalidCredentialError()
        return VerifiedCredential(usr_id=cred.usr_id, cred_id=cred.id)

    # ─── Sessions ───

    @staticmethod
    def _generate_token() -> str:
        return secrets.token_urlsafe(32)

    def create_session(
        self, usr_id: str, cred_id: str, ttl_seconds: int
    ) -> SessionWithToken:
        user = self._require_user(usr_id)
        if user.status != Status.ACTIVE:
            raise PreconditionError(
                f"Cannot create session for {user.status.value} user",
                reason="user_not_active",
            )
        cred = self._require_credential(cred_id)
        if cred.status != Status.ACTIVE:
            raise CredentialNotActiveError(
                f"Credential {cred_id} is {cred.status.value}"
            )
        if cred.usr_id != usr_id:
            raise PreconditionError(
                f"Credential {cred_id} does not belong to {usr_id}",
                reason="cred_user_mismatch",
            )
        if ttl_seconds < 60:
            raise PreconditionError(
                "ttl_seconds must be >= 60", reason="ttl_too_short"
            )
        now = self._now()
        token = self._generate_token()
        token_hash = _hash_token(token)
        session = Session(
            id=generate("ses"),
            usr_id=usr_id,
            cred_id=cred_id,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            revoked_at=None,
        )
        self._sessions[session.id] = session
        self._session_token_hashes[session.id] = token_hash
        self._session_by_token_hash[token_hash] = session.id
        return SessionWithToken(session=session, token=token)

    def get_session(self, ses_id: str) -> Session:
        return self._require_session(ses_id)

    def list_sessions_for_user(
        self, usr_id: str, *, cursor: str | None = None, limit: int = 50
    ) -> Page[Session]:
        matching = sorted(
            (s for s in self._sessions.values() if s.usr_id == usr_id),
            key=lambda s: s.id,
        )
        if cursor is not None:
            start = 0
            for i, item in enumerate(matching):
                if item.id > cursor:
                    start = i
                    break
                start = i + 1
        else:
            start = 0
        slice_ = matching[start : start + limit]
        next_cursor = (
            slice_[-1].id
            if (start + limit) < len(matching) and len(slice_) > 0
            else None
        )
        return Page(data=slice_, next_cursor=next_cursor)

    def verify_session_token(self, token: str) -> Session:
        token_hash = _hash_token(token)
        ses_id = self._session_by_token_hash.get(token_hash)
        if ses_id is None:
            raise InvalidTokenError()
        session = self._require_session(ses_id)
        stored_hash = self._session_token_hashes.get(ses_id, "")
        if not hmac.compare_digest(token_hash, stored_hash):
            raise InvalidTokenError()
        if session.revoked_at is not None:
            raise SessionExpiredError("Session is revoked")
        if self._now() > session.expires_at:
            raise SessionExpiredError("Session has expired")
        return session

    def refresh_session(self, ses_id: str) -> SessionWithToken:
        session = self._require_session(ses_id)
        if session.revoked_at is not None:
            raise SessionExpiredError("Session is already revoked")
        if self._now() > session.expires_at:
            raise SessionExpiredError("Session has expired")
        now = self._now()
        # Revoke old.
        self._sessions[ses_id] = session.with_revoked_at(now)
        old_hash = self._session_token_hashes.pop(ses_id, None)
        if old_hash is not None:
            self._session_by_token_hash.pop(old_hash, None)
        # Issue new with the same TTL window as the original.
        ttl = session.expires_at - session.created_at
        token = self._generate_token()
        token_hash = _hash_token(token)
        fresh = Session(
            id=generate("ses"),
            usr_id=session.usr_id,
            cred_id=session.cred_id,
            created_at=now,
            expires_at=now + ttl,
            revoked_at=None,
        )
        self._sessions[fresh.id] = fresh
        self._session_token_hashes[fresh.id] = token_hash
        self._session_by_token_hash[token_hash] = fresh.id
        return SessionWithToken(session=fresh, token=token)

    def revoke_session(self, ses_id: str) -> Session:
        session = self._require_session(ses_id)
        if session.revoked_at is not None:
            return session
        now = self._now()
        updated = session.with_revoked_at(now)
        self._sessions[ses_id] = updated
        old_hash = self._session_token_hashes.pop(ses_id, None)
        if old_hash is not None:
            self._session_by_token_hash.pop(old_hash, None)
        return updated
