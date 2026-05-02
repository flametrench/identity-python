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

import base64
import re
from .errors import (
    AlreadyTerminalError,
    CredentialNotActiveError,
    CredentialTypeMismatchError,
    DuplicateCredentialError,
    InvalidCredentialError,
    InvalidPatTokenError,
    InvalidTokenError,
    NotFoundError,
    PatExpiredError,
    PatRevokedError,
    PreconditionError,
    SessionExpiredError,
)
from .hashing import hash_password, verify_password_hash
from .pat import PAT_DUMMY_PHC_HASH, PAT_MAX_LIFETIME_SECONDS, PAT_MAX_SECRET_LENGTH, PatStatus, PersonalAccessToken, VerifiedPat
from .mfa import (
    Factor,
    FactorStatus,
    FactorType,
    MfaProof,
    MfaVerifyResult,
    RecoveryEnrollmentResult,
    RecoveryFactor,
    RecoveryProof,
    TotpEnrollmentResult,
    TotpFactor,
    TotpProof,
    UserMfaPolicy,
    WebAuthnEnrollmentResult,
    WebAuthnFactor,
    WebAuthnProof,
    generate_recovery_codes,
    generate_totp_secret,
    is_valid_recovery_code,
    normalize_recovery_input,
    totp_otpauth_uri,
    totp_verify,
)
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
from .webauthn import (
    WebAuthnError,
    webauthn_verify_assertion,
)


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


class _Unset:
    """Sentinel for partial-update parameters (ADR 0014). Distinguishes
    "field omitted" from an explicit "set to None"."""

    _instance: "_Unset | None" = None

    def __new__(cls) -> "_Unset":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "_UNSET"


_UNSET = _Unset()


class InMemoryIdentityStore:
    """Reference in-memory implementation of IdentityStore."""

    UNSET: "_Unset" = _UNSET

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        pat_last_used_coalesce_seconds: int = 60,
    ) -> None:
        self._users: dict[str, User] = {}
        self._credentials: dict[str, Credential] = {}
        self._password_hashes: dict[str, str] = {}  # cred_id → PHC hash
        self._passkey_public_keys: dict[str, bytes] = {}
        # Natural-key index: f"{type.value}|{identifier}" → cred_id (active only)
        self._active_cred_by_identifier: dict[str, str] = {}
        self._sessions: dict[str, Session] = {}
        self._session_token_hashes: dict[str, str] = {}  # ses_id → token-hash
        self._session_by_token_hash: dict[str, str] = {}  # token-hash → ses_id
        # ─── v0.2 MFA (ADR 0008) ───
        self._mfa_factors: dict[str, "Factor"] = {}
        self._mfa_totp_secrets: dict[str, bytes] = {}  # mfa_id → raw secret
        self._mfa_webauthn_keys: dict[str, bytes] = {}  # mfa_id → COSE pubkey
        self._mfa_recovery_hashes: dict[str, list[str]] = {}  # mfa_id → 10 PHC
        self._mfa_recovery_consumed: dict[str, list[bool]] = {}  # parallel array
        # mfa_id by (usr_id, type) — only for singleton types (totp, recovery)
        self._mfa_active_singleton: dict[str, str] = {}
        # mfa_id by webauthn credential_id (active factors only)
        self._mfa_webauthn_by_credential_id: dict[str, str] = {}
        self._mfa_policies: dict[str, "UserMfaPolicy"] = {}
        # ─── v0.3 PATs (ADR 0016) ───
        self._pats: dict[str, PersonalAccessToken] = {}
        self._pat_secret_hashes: dict[str, str] = {}  # pat_id → PHC hash
        self._pat_last_used_persisted: dict[str, datetime] = {}
        self._pat_last_used_coalesce_seconds = max(0, pat_last_used_coalesce_seconds)
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

    def create_user(self, *, display_name: str | None = None) -> User:
        now = self._now()
        u = User(
            id=generate("usr"),
            status=Status.ACTIVE,
            created_at=now,
            updated_at=now,
            display_name=display_name,
        )
        self._users[u.id] = u
        return u

    def get_user(self, usr_id: str) -> User:
        return self._require_user(usr_id)

    def update_user(
        self,
        usr_id: str,
        *,
        display_name: str | None | _Unset = _UNSET,
    ) -> User:
        """Partial update of v0.2 user metadata.

        ADR 0014 semantics: an omitted parameter (sentinel ``_UNSET``)
        means "don't change"; an explicit ``None`` means "set to null."
        Returns the updated user. Raises:

        - :class:`AlreadyTerminalError` if the user is revoked.
        - :class:`NotFoundError` if the user does not exist.
        """
        u = self._require_user(usr_id)
        if u.status == Status.REVOKED:
            raise AlreadyTerminalError(
                f"User {usr_id} is revoked; cannot update"
            )
        new_display_name = (
            u.display_name if isinstance(display_name, _Unset) else display_name
        )
        if new_display_name == u.display_name:
            return u
        updated = User(
            id=u.id,
            status=u.status,
            created_at=u.created_at,
            updated_at=self._now(),
            display_name=new_display_name,
        )
        self._users[usr_id] = updated
        return updated

    def list_users(
        self,
        *,
        cursor: str | None = None,
        limit: int = 50,
        query: str | None = None,
        status: Status | None = None,
    ) -> Page[User]:
        limit = max(1, min(limit, 200))
        needle = query.lower() if query is not None else None
        matching: list[User] = []
        for u in self._users.values():
            if status is not None and u.status != status:
                continue
            if needle is not None:
                hit = False
                for cred in self._credentials.values():
                    if cred.usr_id != u.id:
                        continue
                    if cred.status != Status.ACTIVE:
                        continue
                    if needle in cred.identifier.lower():
                        hit = True
                        break
                if not hit:
                    continue
            matching.append(u)
        matching.sort(key=lambda u: u.id)
        if cursor is not None:
            start = next(
                (i for i, u in enumerate(matching) if u.id > cursor),
                len(matching),
            )
        else:
            start = 0
        page = matching[start : start + limit]
        next_cursor = (
            page[-1].id if start + limit < len(matching) and page else None
        )
        return Page(data=page, next_cursor=next_cursor)

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
        # ADR 0008: surface usr_mfa_policy state.
        policy = self._mfa_policies.get(cred.usr_id)
        mfa_required = False
        if policy is not None and policy.required:
            if policy.grace_until is None or policy.grace_until <= self._now():
                mfa_required = True
        return VerifiedCredential(
            usr_id=cred.usr_id,
            cred_id=cred.id,
            mfa_required=mfa_required,
        )

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

    # ─── v0.2 MFA store operations (ADR 0008) ──────────────────────

    # Two-step enrollment for TOTP and WebAuthn (ADR 0008 §"Two-step
    # enrollment"); recovery codes are single-step. Pending factors
    # expire after this window if not confirmed; expired-pending
    # confirmations are rejected. Audit M1: this is the only spot in
    # the SDK that enforces the expiry — the schema CHECK ensures
    # consistency at the row level but doesn't auto-revoke.
    PENDING_FACTOR_TTL_SECONDS = 600  # 10 minutes per ADR 0008.

    def _require_factor(self, mfa_id: str) -> Factor:
        factor = self._mfa_factors.get(mfa_id)
        if factor is None:
            raise NotFoundError(f"MFA factor {mfa_id} not found")
        return factor

    def _check_user_active(self, usr_id: str) -> None:
        user = self._require_user(usr_id)
        if user.status != Status.ACTIVE:
            raise PreconditionError(
                f"User {usr_id} is {user.status.value}; cannot enroll MFA",
                reason="user_not_active",
            )

    def _enforce_no_active_singleton(
        self, usr_id: str, type_: FactorType
    ) -> None:
        # TOTP and Recovery are singletons per usr — at most one active
        # at a time. WebAuthn allows multiple (phone + laptop + key).
        if type_ in (FactorType.TOTP, FactorType.RECOVERY):
            key = f"{usr_id}|{type_.value}"
            if key in self._mfa_active_singleton:
                raise PreconditionError(
                    f"User {usr_id} already has an active {type_.value} factor; "
                    "revoke before re-enrolling",
                    reason="active_singleton_exists",
                )

    def enroll_totp_factor(
        self, usr_id: str, identifier: str
    ) -> TotpEnrollmentResult:
        """Begin TOTP enrollment.

        Generates a fresh secret, stores it on a pending factor, and
        returns the secret + otpauth URI for QR rendering. Confirmation
        comes from a successful ``confirm_totp_factor`` against a code
        the user types from their authenticator app.
        """
        self._check_user_active(usr_id)
        self._enforce_no_active_singleton(usr_id, FactorType.TOTP)
        now = self._now()
        secret = generate_totp_secret()
        mfa_id = generate("mfa")
        factor = TotpFactor(
            id=mfa_id,
            usr_id=usr_id,
            identifier=identifier,
            status=FactorStatus.PENDING,
            replaces=None,
            created_at=now,
            updated_at=now,
        )
        self._mfa_factors[mfa_id] = factor
        self._mfa_totp_secrets[mfa_id] = secret
        import base64

        secret_b32 = base64.b32encode(secret).rstrip(b"=").decode("ascii")
        otpauth_uri = totp_otpauth_uri(
            secret=secret, label=identifier, issuer="Flametrench"
        )
        return TotpEnrollmentResult(
            factor=factor, secret_b32=secret_b32, otpauth_uri=otpauth_uri
        )

    def enroll_webauthn_factor(
        self,
        usr_id: str,
        identifier: str,
        *,
        public_key: bytes,
        sign_count: int,
        rp_id: str,
        aaguid: str | None = None,
        transports: list[str] | None = None,
    ) -> WebAuthnEnrollmentResult:
        """Begin WebAuthn enrollment.

        Caller passes the COSE public key bytes and sign_count from the
        registration ceremony (the assertion the browser returned to
        ``navigator.credentials.create()``). Confirmation comes from a
        successful ``confirm_webauthn_factor`` against a follow-up
        assertion from the same authenticator.

        ``identifier`` is the base64url-encoded WebAuthn credential ID;
        the SDK indexes on it for verifyMfa lookup.
        """
        self._check_user_active(usr_id)
        if identifier in self._mfa_webauthn_by_credential_id:
            raise PreconditionError(
                f"WebAuthn credential {identifier!r} is already enrolled",
                reason="duplicate_webauthn_credential",
            )
        now = self._now()
        mfa_id = generate("mfa")
        factor = WebAuthnFactor(
            id=mfa_id,
            usr_id=usr_id,
            identifier=identifier,
            status=FactorStatus.PENDING,
            replaces=None,
            rp_id=rp_id,
            sign_count=sign_count,
            created_at=now,
            updated_at=now,
        )
        self._mfa_factors[mfa_id] = factor
        self._mfa_webauthn_keys[mfa_id] = public_key
        # The credential_id index is set even for pending factors so a
        # second enrollment of the same credential is rejected
        # immediately (above), and the verify path can find the factor
        # after confirmation flips status to active.
        self._mfa_webauthn_by_credential_id[identifier] = mfa_id
        return WebAuthnEnrollmentResult(factor=factor)

    def enroll_recovery_factor(self, usr_id: str) -> RecoveryEnrollmentResult:
        """Mint a fresh set of 10 recovery codes — active immediately.

        Codes are returned ONCE in plaintext; the SDK stores Argon2id
        hashes only. If the user already has an active recovery set,
        callers must revoke it first (ADR 0008 — at most one active
        recovery factor per user).
        """
        self._check_user_active(usr_id)
        self._enforce_no_active_singleton(usr_id, FactorType.RECOVERY)
        now = self._now()
        codes = generate_recovery_codes()
        hashes = [hash_password(code) for code in codes]
        consumed = [False] * len(codes)
        mfa_id = generate("mfa")
        factor = RecoveryFactor(
            id=mfa_id,
            usr_id=usr_id,
            status=FactorStatus.ACTIVE,
            replaces=None,
            created_at=now,
            updated_at=now,
            remaining=len(codes),
        )
        self._mfa_factors[mfa_id] = factor
        self._mfa_recovery_hashes[mfa_id] = hashes
        self._mfa_recovery_consumed[mfa_id] = consumed
        self._mfa_active_singleton[f"{usr_id}|recovery"] = mfa_id
        return RecoveryEnrollmentResult(factor=factor, codes=codes)

    def get_mfa_factor(self, mfa_id: str) -> Factor:
        return self._require_factor(mfa_id)

    def list_mfa_factors(self, usr_id: str) -> list[Factor]:
        return [
            f for f in self._mfa_factors.values() if f.usr_id == usr_id
        ]

    def confirm_totp_factor(self, mfa_id: str, code: str) -> TotpFactor:
        factor = self._require_factor(mfa_id)
        if not isinstance(factor, TotpFactor):
            raise CredentialTypeMismatchError(
                f"Factor {mfa_id} is {factor.type.value}, not totp"
            )
        if factor.status != FactorStatus.PENDING:
            raise PreconditionError(
                f"Factor {mfa_id} is {factor.status.value}; only pending factors confirm",
                reason="factor_not_pending",
            )
        self._check_pending_not_expired(factor)
        secret = self._mfa_totp_secrets[mfa_id]
        if not totp_verify(secret, code, timestamp=int(self._now().timestamp())):
            raise InvalidCredentialError("TOTP code did not verify")
        active = TotpFactor(
            id=factor.id,
            usr_id=factor.usr_id,
            identifier=factor.identifier,
            status=FactorStatus.ACTIVE,
            replaces=factor.replaces,
            created_at=factor.created_at,
            updated_at=self._now(),
        )
        self._mfa_factors[mfa_id] = active
        self._mfa_active_singleton[f"{factor.usr_id}|totp"] = mfa_id
        return active

    def confirm_webauthn_factor(
        self,
        mfa_id: str,
        *,
        authenticator_data: bytes,
        client_data_json: bytes,
        signature: bytes,
        expected_challenge: bytes,
        expected_origin: str,
    ) -> WebAuthnFactor:
        factor = self._require_factor(mfa_id)
        if not isinstance(factor, WebAuthnFactor):
            raise CredentialTypeMismatchError(
                f"Factor {mfa_id} is {factor.type.value}, not webauthn"
            )
        if factor.status != FactorStatus.PENDING:
            raise PreconditionError(
                f"Factor {mfa_id} is {factor.status.value}; only pending factors confirm",
                reason="factor_not_pending",
            )
        self._check_pending_not_expired(factor)
        # Run the assertion verifier with the stored public key and rp_id.
        # The verifier raises on signature/origin/challenge/etc. failures;
        # let those propagate so the host can react with a typed error.
        result = webauthn_verify_assertion(
            cose_public_key=self._mfa_webauthn_keys[mfa_id],
            stored_sign_count=factor.sign_count,
            stored_rp_id=factor.rp_id,
            expected_challenge=expected_challenge,
            expected_origin=expected_origin,
            authenticator_data=authenticator_data,
            client_data_json=client_data_json,
            signature=signature,
        )
        active = WebAuthnFactor(
            id=factor.id,
            usr_id=factor.usr_id,
            identifier=factor.identifier,
            status=FactorStatus.ACTIVE,
            replaces=factor.replaces,
            rp_id=factor.rp_id,
            sign_count=result.new_sign_count,
            created_at=factor.created_at,
            updated_at=self._now(),
        )
        self._mfa_factors[mfa_id] = active
        return active

    def revoke_mfa_factor(self, mfa_id: str) -> Factor:
        factor = self._require_factor(mfa_id)
        if factor.status == FactorStatus.REVOKED:
            return factor
        revoked = self._with_factor_status(factor, FactorStatus.REVOKED)
        self._mfa_factors[mfa_id] = revoked
        # Clean up indexes so freed singleton slots are reusable, and
        # the WebAuthn credential_id is freed for re-enrollment.
        if isinstance(factor, TotpFactor):
            self._mfa_active_singleton.pop(f"{factor.usr_id}|totp", None)
        elif isinstance(factor, RecoveryFactor):
            self._mfa_active_singleton.pop(f"{factor.usr_id}|recovery", None)
        elif isinstance(factor, WebAuthnFactor):
            self._mfa_webauthn_by_credential_id.pop(factor.identifier, None)
        return revoked

    def verify_mfa(self, usr_id: str, proof: MfaProof) -> MfaVerifyResult:
        """Verify an MFA proof and return the matched factor's id + type.

        Does NOT mint a session — the spec's three-step session flow is
        ``verify_password → verify_mfa → create_session``. On a WebAuthn
        proof the result includes the new sign count, which the caller
        persists alongside the session decision.
        """
        if isinstance(proof, TotpProof):
            return self._verify_totp(usr_id, proof.code)
        if isinstance(proof, WebAuthnProof):
            return self._verify_webauthn(usr_id, proof)
        if isinstance(proof, RecoveryProof):
            return self._verify_recovery(usr_id, proof.code)
        raise TypeError(f"Unknown proof type: {type(proof).__name__}")

    def _verify_totp(self, usr_id: str, code: str) -> MfaVerifyResult:
        mfa_id = self._mfa_active_singleton.get(f"{usr_id}|totp")
        if mfa_id is None:
            raise InvalidCredentialError("No active TOTP factor for user")
        secret = self._mfa_totp_secrets[mfa_id]
        if not totp_verify(secret, code, timestamp=int(self._now().timestamp())):
            raise InvalidCredentialError("TOTP code did not verify")
        return MfaVerifyResult(
            mfa_id=mfa_id,
            type=FactorType.TOTP,
            mfa_verified_at=self._now(),
            new_sign_count=None,
        )

    def _verify_webauthn(
        self, usr_id: str, proof: WebAuthnProof
    ) -> MfaVerifyResult:
        mfa_id = self._mfa_webauthn_by_credential_id.get(proof.credential_id)
        if mfa_id is None:
            raise InvalidCredentialError(
                "No WebAuthn factor for credential id"
            )
        factor = self._mfa_factors[mfa_id]
        if not isinstance(factor, WebAuthnFactor):
            raise InvalidCredentialError("Factor is not WebAuthn")
        if factor.usr_id != usr_id:
            # Don't leak which user owns the credential — generic invalid.
            raise InvalidCredentialError("WebAuthn factor does not belong to user")
        if factor.status != FactorStatus.ACTIVE:
            raise InvalidCredentialError(
                f"WebAuthn factor is {factor.status.value}, not active"
            )
        result = webauthn_verify_assertion(
            cose_public_key=self._mfa_webauthn_keys[mfa_id],
            stored_sign_count=factor.sign_count,
            stored_rp_id=factor.rp_id,
            expected_challenge=proof.expected_challenge,
            expected_origin=proof.expected_origin,
            authenticator_data=proof.authenticator_data,
            client_data_json=proof.client_data_json,
            signature=proof.signature,
        )
        # Persist the advanced counter atomically with the verify.
        updated = WebAuthnFactor(
            id=factor.id,
            usr_id=factor.usr_id,
            identifier=factor.identifier,
            status=factor.status,
            replaces=factor.replaces,
            rp_id=factor.rp_id,
            sign_count=result.new_sign_count,
            created_at=factor.created_at,
            updated_at=self._now(),
        )
        self._mfa_factors[mfa_id] = updated
        return MfaVerifyResult(
            mfa_id=mfa_id,
            type=FactorType.WEBAUTHN,
            mfa_verified_at=self._now(),
            new_sign_count=result.new_sign_count,
        )

    def _verify_recovery(self, usr_id: str, code: str) -> MfaVerifyResult:
        mfa_id = self._mfa_active_singleton.get(f"{usr_id}|recovery")
        if mfa_id is None:
            raise InvalidCredentialError("No active recovery factor for user")
        normalized = normalize_recovery_input(code)
        if not is_valid_recovery_code(normalized):
            raise InvalidCredentialError("Recovery code is malformed")
        hashes = self._mfa_recovery_hashes[mfa_id]
        consumed = self._mfa_recovery_consumed[mfa_id]
        # Walk every active slot regardless of an early match — keeps the
        # work constant relative to the active set so timing doesn't leak
        # which slot matched. We tally the matched slot index and only
        # use it if no earlier-active slot matched first.
        matched_slot = -1
        for i, (h, c) in enumerate(zip(hashes, consumed)):
            if c:
                continue
            if verify_password_hash(h, normalized) and matched_slot == -1:
                matched_slot = i
        if matched_slot == -1:
            raise InvalidCredentialError("Recovery code did not verify")
        # Consume the matched slot.
        consumed[matched_slot] = True
        # Update the public RecoveryFactor's `remaining`.
        factor = self._mfa_factors[mfa_id]
        if isinstance(factor, RecoveryFactor):
            self._mfa_factors[mfa_id] = RecoveryFactor(
                id=factor.id,
                usr_id=factor.usr_id,
                status=factor.status,
                replaces=factor.replaces,
                created_at=factor.created_at,
                updated_at=self._now(),
                remaining=sum(1 for c in consumed if not c),
            )
        return MfaVerifyResult(
            mfa_id=mfa_id,
            type=FactorType.RECOVERY,
            mfa_verified_at=self._now(),
            new_sign_count=None,
        )

    # ─── usr_mfa_policy ─────────────────────────────────────────────

    def get_mfa_policy(self, usr_id: str) -> UserMfaPolicy | None:
        # Existence-check the user, but return None for the absence-of-row
        # case — the spec is "absent row means MFA not required."
        self._require_user(usr_id)
        return self._mfa_policies.get(usr_id)

    def set_mfa_policy(
        self,
        usr_id: str,
        *,
        required: bool,
        grace_until: datetime | None = None,
    ) -> UserMfaPolicy:
        self._require_user(usr_id)
        policy = UserMfaPolicy(
            usr_id=usr_id,
            required=required,
            grace_until=grace_until,
            updated_at=self._now(),
        )
        self._mfa_policies[usr_id] = policy
        return policy

    # ─── private helpers ────────────────────────────────────────────

    def _check_pending_not_expired(self, factor: Factor) -> None:
        # Pending TOTP/WebAuthn factors expire after PENDING_FACTOR_TTL_SECONDS
        # past their created_at timestamp. This is the audit M1 enforcement
        # spot — the schema CHECK constrains row consistency but does not
        # auto-revoke.
        if factor.status != FactorStatus.PENDING:
            return
        age = (self._now() - factor.created_at).total_seconds()
        if age > self.PENDING_FACTOR_TTL_SECONDS:
            raise PreconditionError(
                f"Pending factor {factor.id} expired "
                f"({age:.0f}s > {self.PENDING_FACTOR_TTL_SECONDS}s)",
                reason="pending_factor_expired",
            )

    def _with_factor_status(self, factor: Factor, status: FactorStatus) -> Factor:
        now = self._now()
        if isinstance(factor, TotpFactor):
            return TotpFactor(
                id=factor.id,
                usr_id=factor.usr_id,
                identifier=factor.identifier,
                status=status,
                replaces=factor.replaces,
                created_at=factor.created_at,
                updated_at=now,
            )
        if isinstance(factor, WebAuthnFactor):
            return WebAuthnFactor(
                id=factor.id,
                usr_id=factor.usr_id,
                identifier=factor.identifier,
                status=status,
                replaces=factor.replaces,
                rp_id=factor.rp_id,
                sign_count=factor.sign_count,
                created_at=factor.created_at,
                updated_at=now,
            )
        if isinstance(factor, RecoveryFactor):
            return RecoveryFactor(
                id=factor.id,
                usr_id=factor.usr_id,
                status=status,
                replaces=factor.replaces,
                created_at=factor.created_at,
                updated_at=now,
                remaining=factor.remaining,
            )
        raise TypeError(f"Unknown factor type: {type(factor).__name__}")

    # ─── v0.3 personal access tokens (ADR 0016) ───

    def create_pat(
        self,
        usr_id: str,
        name: str,
        scope: list[str],
        *,
        expires_at: datetime | None = None,
    ) -> tuple[PersonalAccessToken, str]:
        """Mint a new PAT bound to ``usr_id``.

        Returns a tuple of ``(record, plaintext_token)``. The plaintext
        token is in ``pat_<32hex>_<base64url>`` form and is returned
        ONCE — the server stores only an Argon2id hash of the secret
        segment.

        Security:
            Adopter MUST gate this call so the requesting principal
            either owns ``usr_id`` OR is a sysadmin acting on the
            user's behalf. The SDK does not enforce. Without
            route-layer gating, any authenticated user can mint PATs
            in any other user's name. (security-audit-v0.3.md H7.)
        """
        u = self._require_user(usr_id)
        if u.status == Status.REVOKED:
            raise AlreadyTerminalError(
                f"User {usr_id} is revoked; cannot issue PATs"
            )
        if not (1 <= len(name) <= 120):
            raise PreconditionError(
                f"PAT name must be 1–120 characters (got {len(name)})",
                reason="pat.name_invalid",
            )
        now = self._now()
        if expires_at is not None and expires_at <= now:
            raise PreconditionError(
                "PAT expires_at must be strictly in the future",
                reason="pat.expires_in_past",
            )
        # security-audit-v0.3.md H1: 365-day cap from ADR 0016 §"Constraints".
        if (
            expires_at is not None
            and (expires_at - now).total_seconds() > PAT_MAX_LIFETIME_SECONDS
        ):
            raise PreconditionError(
                f"PAT expires_at exceeds the spec cap of {PAT_MAX_LIFETIME_SECONDS} seconds (365 days) from creation",
                reason="pat.expires_too_far",
            )
        pat_id = generate("pat")
        id_hex_segment = pat_id[4:]  # strip 'pat_' → 32 hex
        secret_bytes = secrets.token_bytes(32)
        secret_segment = _base64url_encode(secret_bytes)
        token = f"pat_{id_hex_segment}_{secret_segment}"
        secret_hash = hash_password(secret_segment)

        pat = PersonalAccessToken(
            id=pat_id,
            usr_id=usr_id,
            name=name,
            scope=list(scope),
            status=PatStatus.ACTIVE,
            expires_at=expires_at,
            last_used_at=None,
            revoked_at=None,
            created_at=now,
            updated_at=now,
        )
        self._pats[pat_id] = pat
        self._pat_secret_hashes[pat_id] = secret_hash
        return pat, token

    def get_pat(self, pat_id: str) -> PersonalAccessToken:
        """Read a single PAT row by id.

        Security:
            Adopter MUST gate so the requesting principal either owns
            the PAT (matches ``usr_id`` of the row) OR is a sysadmin.
            The SDK returns the row regardless — without gating, an
            unauthenticated / wrong-principal request leaks the PAT's
            existence, scope, and metadata. (security-audit-v0.3.md H7.)
        """
        pat = self._pats.get(pat_id)
        if pat is None:
            raise NotFoundError(f"PAT {pat_id} not found")
        return self._with_derived_status(pat)

    def list_pats_for_user(
        self,
        usr_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        status: PatStatus | None = None,
    ) -> Page[PersonalAccessToken]:
        """Cursor-paginated PAT list for ``usr_id``.

        Security:
            Adopter MUST gate so the requesting principal either is
            ``usr_id`` OR is a sysadmin. Without gating, any caller
            can enumerate any user's PATs.
            (security-audit-v0.3.md H7.)
        """
        limit = max(1, min(limit, 200))
        matching: list[PersonalAccessToken] = []
        for pat in self._pats.values():
            if pat.usr_id != usr_id:
                continue
            derived = self._with_derived_status(pat)
            if status is not None and derived.status != status:
                continue
            matching.append(derived)
        matching.sort(key=lambda p: p.id)
        if cursor is not None:
            start_idx = next(
                (i for i, p in enumerate(matching) if p.id > cursor),
                len(matching),
            )
        else:
            start_idx = 0
        slice_ = matching[start_idx : start_idx + limit]
        next_cursor = (
            slice_[-1].id
            if (start_idx + limit) < len(matching) and slice_
            else None
        )
        return Page(data=slice_, next_cursor=next_cursor)

    def revoke_pat(self, pat_id: str) -> PersonalAccessToken:
        """Terminal-state revoke; idempotent.

        Security:
            Adopter MUST gate so the requesting principal either owns
            the PAT OR is a sysadmin. Without gating, any caller can
            revoke any user's PAT — locking the legitimate owner out
            of their own automation. (security-audit-v0.3.md H7.)
        """
        pat = self._pats.get(pat_id)
        if pat is None:
            raise NotFoundError(f"PAT {pat_id} not found")
        if pat.revoked_at is not None:
            # Idempotent: already revoked.
            return self._with_derived_status(pat)
        now = self._now()
        updated = PersonalAccessToken(
            id=pat.id,
            usr_id=pat.usr_id,
            name=pat.name,
            scope=pat.scope,
            status=PatStatus.REVOKED,
            expires_at=pat.expires_at,
            last_used_at=pat.last_used_at,
            revoked_at=now,
            created_at=pat.created_at,
            updated_at=now,
        )
        self._pats[pat_id] = updated
        return updated

    def verify_pat_token(self, token: str) -> VerifiedPat:
        """Verify a PAT bearer per ADR 0016 §"Verification semantics".

        The 8-step normative ordering is implemented here:
        prefix → split → lookup → revoked → expired → secret → coalesce.
        Missing-row and wrong-secret cases conflate to
        :class:`InvalidPatTokenError` to defend against a token-presence
        timing oracle.
        """
        # Step 1–2: structural decode.
        if not token.startswith("pat_"):
            raise InvalidPatTokenError()
        if len(token) < 4 + 32 + 1 + 1:
            raise InvalidPatTokenError()
        id_hex = token[4:36]
        if not re.fullmatch(r"[0-9a-f]{32}", id_hex):
            raise InvalidPatTokenError()
        if token[36] != "_":
            raise InvalidPatTokenError()
        secret_segment = token[37:]
        # security-audit-v0.3.md H6: cap on secret-segment length so
        # an attacker with a known pat_id cannot force unbounded
        # Argon2id work by submitting MB-sized secrets.
        if not secret_segment or len(secret_segment) > PAT_MAX_SECRET_LENGTH:
            raise InvalidPatTokenError()
        pat_id = f"pat_{id_hex}"

        # Step 3–4: lookup; conflate "no row" with "wrong secret".
        # security-audit-v0.3.md H2: when the row is missing we still
        # perform an Argon2id verify against a dummy hash so the
        # wall-clock time of "no such pat_id" matches the
        # row-exists-but-wrong-secret path.
        pat = self._pats.get(pat_id)
        if pat is None:
            verify_password_hash(PAT_DUMMY_PHC_HASH, secret_segment)
            raise InvalidPatTokenError()
        # Step 5: revoked terminal check.
        if pat.revoked_at is not None:
            raise PatRevokedError(pat_id)
        # Step 6: expiry.
        now = self._now()
        if pat.expires_at is not None and pat.expires_at <= now:
            raise PatExpiredError(pat_id)
        # Step 7: Argon2id verify; conflated error shape.
        hash_ = self._pat_secret_hashes.get(pat_id)
        if hash_ is None or not verify_password_hash(hash_, secret_segment):
            raise InvalidPatTokenError()
        # Step 8: last_used_at update with coalescing.
        persisted = self._pat_last_used_persisted.get(pat_id)
        should_update = (
            persisted is None
            or self._pat_last_used_coalesce_seconds == 0
            or (now - persisted).total_seconds() >= self._pat_last_used_coalesce_seconds
        )
        if should_update:
            self._pats[pat_id] = PersonalAccessToken(
                id=pat.id,
                usr_id=pat.usr_id,
                name=pat.name,
                scope=pat.scope,
                status=pat.status,
                expires_at=pat.expires_at,
                last_used_at=now,
                revoked_at=pat.revoked_at,
                created_at=pat.created_at,
                updated_at=now,
            )
            self._pat_last_used_persisted[pat_id] = now
        return VerifiedPat(
            pat_id=pat_id,
            usr_id=pat.usr_id,
            scope=list(pat.scope),
        )

    def _with_derived_status(self, pat: PersonalAccessToken) -> PersonalAccessToken:
        """Re-derive status from lifecycle columns (revoked / expired / now)."""
        if pat.revoked_at is not None:
            derived = PatStatus.REVOKED
        elif pat.expires_at is not None and pat.expires_at <= self._now():
            derived = PatStatus.EXPIRED
        else:
            derived = PatStatus.ACTIVE
        if derived == pat.status:
            return pat
        return PersonalAccessToken(
            id=pat.id,
            usr_id=pat.usr_id,
            name=pat.name,
            scope=pat.scope,
            status=derived,
            expires_at=pat.expires_at,
            last_used_at=pat.last_used_at,
            revoked_at=pat.revoked_at,
            created_at=pat.created_at,
            updated_at=pat.updated_at,
        )


def _base64url_encode(buf: bytes) -> str:
    """RFC 4648 §5 base64url, no padding."""
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")
