# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""PostgresIdentityStore — Postgres-backed implementation of IdentityStore.

Mirrors :class:`InMemoryIdentityStore` byte-for-byte at the SDK boundary;
the difference is durability and concurrency. Schema lives in
``spec/reference/postgres.sql``.

Bearer tokens are SHA-256 hashed and stored as 32 raw bytes (BYTEA).
Plaintext tokens are returned ONCE on create/refresh and never persisted.

Multi-statement ops (``revoke_user`` cascade, rotation, ``refresh_session``,
MFA confirm/verify) run inside a transaction so state transitions are
atomic.

Connection handling: this store accepts any object that quacks like a
psycopg3 connection — ``cursor()``, ``commit()``, ``rollback()``.
"""

from __future__ import annotations

import hashlib
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator, Sequence

from flametrench_ids import decode as _decode, encode as _encode, generate as _generate

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
from .mfa import (
    DEFAULT_TOTP_ALGORITHM,
    DEFAULT_TOTP_DIGITS,
    DEFAULT_TOTP_PERIOD,
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
from .webauthn import webauthn_verify_assertion

_UNIQUE_VIOLATION = "23505"

# Pending TOTP/WebAuthn factor TTL per ADR 0008.
PENDING_FACTOR_TTL_SECONDS = 600

_CRED_COLS = (
    "id, usr_id, type, identifier, status, replaces, password_hash, "
    "passkey_public_key, passkey_sign_count, passkey_rp_id, "
    "oidc_issuer, oidc_subject, created_at, updated_at"
)
_SES_COLS = (
    "id, usr_id, cred_id, created_at, expires_at, revoked_at, token_hash, mfa_verified_at"
)
_MFA_COLS = (
    "id, usr_id, type, status, replaces, identifier, "
    "totp_secret, totp_algorithm, totp_digits, totp_period, "
    "webauthn_public_key, webauthn_sign_count, webauthn_rp_id, "
    "webauthn_aaguid, webauthn_transports, "
    "recovery_hashes, recovery_consumed, pending_expires_at, "
    "created_at, updated_at"
)


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _wire_to_uuid(wire_id: str) -> str:
    return _decode(wire_id).uuid


def _is_unique_violation(exc: Exception) -> bool:
    sqlstate = getattr(exc, "sqlstate", None) or getattr(getattr(exc, "diag", None), "sqlstate", None)
    return sqlstate == _UNIQUE_VIOLATION


def _hash_token_bytes(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _generate_token() -> str:
    raw = secrets.token_bytes(32)
    import base64
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _to_bytes(value: Any) -> bytes:
    """psycopg returns BYTEA as ``bytes`` or ``memoryview`` depending on driver."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


# ─── Row → entity mappers ───


def _row_to_user(row: Sequence[Any]) -> User:
    # Columns: id, status, display_name, created_at, updated_at
    return User(
        id=_encode("usr", str(row[0])),
        status=Status(row[1]),
        display_name=row[2] if row[2] is None else str(row[2]),
        created_at=row[3] if isinstance(row[3], datetime) else datetime.fromisoformat(str(row[3])),
        updated_at=row[4] if isinstance(row[4], datetime) else datetime.fromisoformat(str(row[4])),
    )


def _row_to_cred(row: Sequence[Any]) -> Credential:
    cred_id = _encode("cred", str(row[0]))
    usr_id = _encode("usr", str(row[1]))
    type_ = str(row[2])
    identifier = str(row[3])
    status = Status(row[4])
    replaces = _encode("cred", str(row[5])) if row[5] is not None else None
    created_at = row[12] if isinstance(row[12], datetime) else datetime.fromisoformat(str(row[12]))
    updated_at = row[13] if isinstance(row[13], datetime) else datetime.fromisoformat(str(row[13]))
    if type_ == "password":
        return PasswordCredential(
            id=cred_id, usr_id=usr_id, identifier=identifier,
            status=status, replaces=replaces,
            created_at=created_at, updated_at=updated_at,
        )
    if type_ == "passkey":
        return PasskeyCredential(
            id=cred_id, usr_id=usr_id, identifier=identifier,
            status=status, replaces=replaces,
            passkey_sign_count=int(row[8] or 0),
            passkey_rp_id=str(row[9] or ""),
            created_at=created_at, updated_at=updated_at,
        )
    return OidcCredential(
        id=cred_id, usr_id=usr_id, identifier=identifier,
        status=status, replaces=replaces,
        oidc_issuer=str(row[10] or ""),
        oidc_subject=str(row[11] or ""),
        created_at=created_at, updated_at=updated_at,
    )


def _row_to_session(row: Sequence[Any]) -> Session:
    return Session(
        id=_encode("ses", str(row[0])),
        usr_id=_encode("usr", str(row[1])),
        cred_id=_encode("cred", str(row[2])),
        created_at=row[3] if isinstance(row[3], datetime) else datetime.fromisoformat(str(row[3])),
        expires_at=row[4] if isinstance(row[4], datetime) else datetime.fromisoformat(str(row[4])),
        revoked_at=(
            row[5] if isinstance(row[5], datetime)
            else (datetime.fromisoformat(str(row[5])) if row[5] is not None else None)
        ),
    )


def _row_to_factor(row: Sequence[Any]) -> Factor:
    factor_id = _encode("mfa", str(row[0]))
    usr_id = _encode("usr", str(row[1]))
    type_ = str(row[2])
    status = FactorStatus(row[3])
    replaces = _encode("mfa", str(row[4])) if row[4] is not None else None
    created_at = row[18] if isinstance(row[18], datetime) else datetime.fromisoformat(str(row[18]))
    updated_at = row[19] if isinstance(row[19], datetime) else datetime.fromisoformat(str(row[19]))
    if type_ == "totp":
        return TotpFactor(
            id=factor_id, usr_id=usr_id,
            identifier=str(row[5] or ""),
            status=status, replaces=replaces,
            created_at=created_at, updated_at=updated_at,
        )
    if type_ == "webauthn":
        return WebAuthnFactor(
            id=factor_id, usr_id=usr_id,
            identifier=str(row[5] or ""),
            status=status, replaces=replaces,
            rp_id=str(row[12] or ""),
            sign_count=int(row[11] or 0),
            created_at=created_at, updated_at=updated_at,
        )
    consumed = list(row[16] or [])
    remaining = sum(1 for c in consumed if not c)
    return RecoveryFactor(
        id=factor_id, usr_id=usr_id,
        status=status, replaces=replaces,
        created_at=created_at, updated_at=updated_at,
        remaining=remaining,
    )


def _row_to_policy(row: Sequence[Any]) -> UserMfaPolicy:
    return UserMfaPolicy(
        usr_id=_encode("usr", str(row[0])),
        required=bool(row[1]),
        grace_until=(
            row[2] if isinstance(row[2], datetime)
            else (datetime.fromisoformat(str(row[2])) if row[2] is not None else None)
        ),
        updated_at=row[3] if isinstance(row[3], datetime) else datetime.fromisoformat(str(row[3])),
    )


class _Unset:
    """Sentinel for partial-update parameters (ADR 0014)."""

    _instance: "_Unset | None" = None

    def __new__(cls) -> "_Unset":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "_UNSET"


_UNSET = _Unset()


class PostgresIdentityStore:
    UNSET: "_Unset" = _UNSET

    """Postgres-backed IdentityStore. See module docstring."""

    PENDING_FACTOR_TTL_SECONDS = PENDING_FACTOR_TTL_SECONDS

    def __init__(
        self,
        connection: Any,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._conn = connection
        self._clock = clock or _default_clock

    def _now(self) -> datetime:
        return self._clock()

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        """Run the wrapped block inside an explicit transaction.

        Uses psycopg3's ``connection.transaction()`` context manager
        rather than ``commit()``/``rollback()`` directly. This is
        correct under BOTH ``autocommit=False`` (the default) AND
        ``autocommit=True``: under autocommit=True, the bare
        commit-on-success / rollback-on-error pattern would NOT hold
        ``FOR UPDATE`` row locks across statements, breaking the
        atomicity guarantees the spec requires for revoke_user
        cascade, credential rotation, refresh_session, MFA confirm/
        verify, and recovery-slot consumption. ``transaction()``
        issues an explicit ``BEGIN``/``COMMIT`` regardless of the
        connection's autocommit setting.
        """
        with self._conn.transaction():
            yield self._conn

    # ─── Users ───

    def create_user(self, *, display_name: str | None = None) -> User:
        usr_uuid = _decode(_generate("usr")).uuid
        with self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO usr (id, display_name) VALUES (%s, %s)
                RETURNING id, status, display_name, created_at, updated_at
                """,
                (usr_uuid, display_name),
            )
            row = cur.fetchone()
        self._conn.commit()
        assert row is not None
        return _row_to_user(row)

    def get_user(self, usr_id: str) -> User:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT id, status, display_name, created_at, updated_at FROM usr WHERE id = %s",
                (_wire_to_uuid(usr_id),),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"User {usr_id} not found")
        return _row_to_user(row)

    def update_user(
        self,
        usr_id: str,
        *,
        display_name: object = _UNSET,
    ) -> User:
        """ADR 0014 partial update of v0.2 user metadata.

        Omitted parameter (sentinel) means "don't change"; explicit
        ``None`` means "set to null." Suspended users MAY be updated;
        revoked users raise AlreadyTerminalError.
        """
        uuid = _wire_to_uuid(usr_id)
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, status, display_name, created_at, updated_at
                    FROM usr WHERE id = %s FOR UPDATE
                    """,
                    (uuid,),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"User {usr_id} not found")
                current_status = row[1]
                current_display = row[2]
                if current_status == Status.REVOKED.value:
                    raise AlreadyTerminalError(
                        f"User {usr_id} is revoked; cannot update"
                    )
                new_display = (
                    current_display
                    if isinstance(display_name, _Unset)
                    else display_name
                )
                if new_display == current_display:
                    return _row_to_user(row)
                cur.execute(
                    """
                    UPDATE usr SET display_name = %s, updated_at = now()
                    WHERE id = %s
                    RETURNING id, status, display_name, created_at, updated_at
                    """,
                    (new_display, uuid),
                )
                updated = cur.fetchone()
        assert updated is not None
        return _row_to_user(updated)

    def suspend_user(self, usr_id: str) -> User:
        with self._tx() as conn:
            uuid = _wire_to_uuid(usr_id)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status, display_name, created_at, updated_at FROM usr WHERE id = %s FOR UPDATE",
                    (uuid,),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"User {usr_id} not found")
                if row[1] == Status.REVOKED.value:
                    raise AlreadyTerminalError(f"User {usr_id} is revoked")
                if row[1] == Status.SUSPENDED.value:
                    return _row_to_user(row)
                cur.execute(
                    "UPDATE usr SET status = 'suspended' WHERE id = %s "
                    "RETURNING id, status, display_name, created_at, updated_at",
                    (uuid,),
                )
                updated = cur.fetchone()
                cur.execute(
                    "UPDATE ses SET revoked_at = %s WHERE usr_id = %s AND revoked_at IS NULL",
                    (self._now(), uuid),
                )
        assert updated is not None
        return _row_to_user(updated)

    def reinstate_user(self, usr_id: str) -> User:
        with self._tx() as conn:
            uuid = _wire_to_uuid(usr_id)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status, display_name, created_at, updated_at FROM usr WHERE id = %s FOR UPDATE",
                    (uuid,),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"User {usr_id} not found")
                if row[1] != Status.SUSPENDED.value:
                    raise PreconditionError(
                        f"User {usr_id} is {row[1]}; only suspended users can be reinstated",
                        reason="invalid_transition",
                    )
                cur.execute(
                    "UPDATE usr SET status = 'active' WHERE id = %s "
                    "RETURNING id, status, display_name, created_at, updated_at",
                    (uuid,),
                )
                updated = cur.fetchone()
        assert updated is not None
        return _row_to_user(updated)

    def revoke_user(self, usr_id: str) -> User:
        with self._tx() as conn:
            uuid = _wire_to_uuid(usr_id)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status, display_name, created_at, updated_at FROM usr WHERE id = %s FOR UPDATE",
                    (uuid,),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"User {usr_id} not found")
                if row[1] == Status.REVOKED.value:
                    raise AlreadyTerminalError(f"User {usr_id} is already revoked")
                now = self._now()
                cur.execute(
                    "UPDATE cred SET status = 'revoked' WHERE usr_id = %s AND status = 'active'",
                    (uuid,),
                )
                cur.execute(
                    "UPDATE ses SET revoked_at = %s WHERE usr_id = %s AND revoked_at IS NULL",
                    (now, uuid),
                )
                cur.execute(
                    "UPDATE usr SET status = 'revoked' WHERE id = %s "
                    "RETURNING id, status, display_name, created_at, updated_at",
                    (uuid,),
                )
                updated = cur.fetchone()
        assert updated is not None
        return _row_to_user(updated)

    # ─── Credentials ───

    def _ensure_user_active(self, conn: Any, usr_id: str) -> str:
        usr_uuid = _wire_to_uuid(usr_id)
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM usr WHERE id = %s", (usr_uuid,))
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"User {usr_id} not found")
        if row[0] != Status.ACTIVE.value:
            raise PreconditionError(
                f"Cannot create credentials for {row[0]} user",
                reason="user_not_active",
            )
        return usr_uuid

    def create_password_credential(
        self, usr_id: str, identifier: str, password: str,
    ) -> PasswordCredential:
        usr_uuid = self._ensure_user_active(self._conn, usr_id)
        cred_uuid = _decode(_generate("cred")).uuid
        password_hash = hash_password(password)
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO cred (id, usr_id, type, identifier, password_hash)
                    VALUES (%s, %s, 'password', %s, %s)
                    RETURNING {_CRED_COLS}
                    """,
                    (cred_uuid, usr_uuid, identifier, password_hash),
                )
                row = cur.fetchone()
            self._conn.commit()
            assert row is not None
            cred = _row_to_cred(row)
            assert isinstance(cred, PasswordCredential)
            return cred
        except Exception as exc:
            self._conn.rollback()
            if _is_unique_violation(exc):
                raise DuplicateCredentialError(
                    f"An active password credential already exists for identifier {identifier}",
                ) from exc
            raise

    def create_passkey_credential(
        self,
        usr_id: str,
        identifier: str,
        public_key: bytes,
        sign_count: int,
        rp_id: str,
    ) -> PasskeyCredential:
        usr_uuid = self._ensure_user_active(self._conn, usr_id)
        cred_uuid = _decode(_generate("cred")).uuid
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO cred (id, usr_id, type, identifier,
                                      passkey_public_key, passkey_sign_count, passkey_rp_id)
                    VALUES (%s, %s, 'passkey', %s, %s, %s, %s)
                    RETURNING {_CRED_COLS}
                    """,
                    (cred_uuid, usr_uuid, identifier, public_key, sign_count, rp_id),
                )
                row = cur.fetchone()
            self._conn.commit()
            assert row is not None
            cred = _row_to_cred(row)
            assert isinstance(cred, PasskeyCredential)
            return cred
        except Exception as exc:
            self._conn.rollback()
            if _is_unique_violation(exc):
                raise DuplicateCredentialError(
                    f"An active passkey credential already exists for identifier {identifier}",
                ) from exc
            raise

    def create_oidc_credential(
        self,
        usr_id: str,
        identifier: str,
        oidc_issuer: str,
        oidc_subject: str,
    ) -> OidcCredential:
        usr_uuid = self._ensure_user_active(self._conn, usr_id)
        cred_uuid = _decode(_generate("cred")).uuid
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO cred (id, usr_id, type, identifier, oidc_issuer, oidc_subject)
                    VALUES (%s, %s, 'oidc', %s, %s, %s)
                    RETURNING {_CRED_COLS}
                    """,
                    (cred_uuid, usr_uuid, identifier, oidc_issuer, oidc_subject),
                )
                row = cur.fetchone()
            self._conn.commit()
            assert row is not None
            cred = _row_to_cred(row)
            assert isinstance(cred, OidcCredential)
            return cred
        except Exception as exc:
            self._conn.rollback()
            if _is_unique_violation(exc):
                raise DuplicateCredentialError(
                    f"An active oidc credential already exists for identifier {identifier}",
                ) from exc
            raise

    def get_credential(self, cred_id: str) -> Credential:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {_CRED_COLS} FROM cred WHERE id = %s",
                (_wire_to_uuid(cred_id),),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"Credential {cred_id} not found")
        return _row_to_cred(row)

    def list_credentials_for_user(self, usr_id: str) -> list[Credential]:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {_CRED_COLS} FROM cred WHERE usr_id = %s ORDER BY created_at",
                (_wire_to_uuid(usr_id),),
            )
            rows = cur.fetchall()
        return [_row_to_cred(r) for r in rows]

    def find_credential_by_identifier(
        self, type: CredentialType, identifier: str,
    ) -> Credential | None:
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT {_CRED_COLS} FROM cred
                WHERE type = %s AND identifier = %s AND status = 'active'
                """,
                (type.value, identifier),
            )
            row = cur.fetchone()
        return _row_to_cred(row) if row is not None else None

    def _lock_cred_for_rotation(
        self, conn: Any, cred_id: str, expected: CredentialType,
    ) -> Sequence[Any]:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_CRED_COLS} FROM cred WHERE id = %s FOR UPDATE",
                (_wire_to_uuid(cred_id),),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"Credential {cred_id} not found")
        if row[4] != Status.ACTIVE.value:
            raise CredentialNotActiveError(f"Credential {cred_id} is {row[4]}")
        if row[2] != expected.value:
            raise CredentialTypeMismatchError(
                f"Cannot rotate {row[2]} credential with {expected.value} payload",
            )
        return row

    def _revoke_old_on_rotation(self, conn: Any, old: Sequence[Any], now: datetime) -> None:
        with conn.cursor() as cur:
            cur.execute("UPDATE cred SET status = 'revoked' WHERE id = %s", (old[0],))
            cur.execute(
                "UPDATE ses SET revoked_at = %s WHERE cred_id = %s AND revoked_at IS NULL",
                (now, old[0]),
            )

    def rotate_password(self, cred_id: str, new_password: str) -> PasswordCredential:
        with self._tx() as conn:
            old = self._lock_cred_for_rotation(conn, cred_id, CredentialType.PASSWORD)
            now = self._now()
            self._revoke_old_on_rotation(conn, old, now)
            new_uuid = _decode(_generate("cred")).uuid
            password_hash = hash_password(new_password)
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO cred (id, usr_id, type, identifier, password_hash, replaces)
                    VALUES (%s, %s, 'password', %s, %s, %s)
                    RETURNING {_CRED_COLS}
                    """,
                    (new_uuid, old[1], old[3], password_hash, old[0]),
                )
                row = cur.fetchone()
        assert row is not None
        cred = _row_to_cred(row)
        assert isinstance(cred, PasswordCredential)
        return cred

    def rotate_passkey(
        self, cred_id: str, public_key: bytes, sign_count: int, rp_id: str,
    ) -> PasskeyCredential:
        with self._tx() as conn:
            old = self._lock_cred_for_rotation(conn, cred_id, CredentialType.PASSKEY)
            now = self._now()
            self._revoke_old_on_rotation(conn, old, now)
            new_uuid = _decode(_generate("cred")).uuid
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO cred (id, usr_id, type, identifier,
                                      passkey_public_key, passkey_sign_count, passkey_rp_id, replaces)
                    VALUES (%s, %s, 'passkey', %s, %s, %s, %s, %s)
                    RETURNING {_CRED_COLS}
                    """,
                    (new_uuid, old[1], old[3], public_key, sign_count, rp_id, old[0]),
                )
                row = cur.fetchone()
        assert row is not None
        cred = _row_to_cred(row)
        assert isinstance(cred, PasskeyCredential)
        return cred

    def rotate_oidc(
        self, cred_id: str, oidc_issuer: str, oidc_subject: str,
    ) -> OidcCredential:
        with self._tx() as conn:
            old = self._lock_cred_for_rotation(conn, cred_id, CredentialType.OIDC)
            now = self._now()
            self._revoke_old_on_rotation(conn, old, now)
            new_uuid = _decode(_generate("cred")).uuid
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO cred (id, usr_id, type, identifier, oidc_issuer, oidc_subject, replaces)
                    VALUES (%s, %s, 'oidc', %s, %s, %s, %s)
                    RETURNING {_CRED_COLS}
                    """,
                    (new_uuid, old[1], old[3], oidc_issuer, oidc_subject, old[0]),
                )
                row = cur.fetchone()
        assert row is not None
        cred = _row_to_cred(row)
        assert isinstance(cred, OidcCredential)
        return cred

    def suspend_credential(self, cred_id: str) -> Credential:
        with self._tx() as conn:
            uuid = _wire_to_uuid(cred_id)
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {_CRED_COLS} FROM cred WHERE id = %s FOR UPDATE",
                    (uuid,),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"Credential {cred_id} not found")
                if row[4] != Status.ACTIVE.value:
                    raise PreconditionError(
                        f"Credential {cred_id} is {row[4]}; only active credentials can be suspended",
                        reason="cred_not_active",
                    )
                now = self._now()
                cur.execute(
                    f"""
                    UPDATE cred SET status = 'suspended' WHERE id = %s
                    RETURNING {_CRED_COLS}
                    """,
                    (uuid,),
                )
                updated = cur.fetchone()
                cur.execute(
                    "UPDATE ses SET revoked_at = %s WHERE cred_id = %s AND revoked_at IS NULL",
                    (now, uuid),
                )
        assert updated is not None
        return _row_to_cred(updated)

    def reinstate_credential(self, cred_id: str) -> Credential:
        with self._tx() as conn:
            uuid = _wire_to_uuid(cred_id)
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {_CRED_COLS} FROM cred WHERE id = %s FOR UPDATE",
                    (uuid,),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"Credential {cred_id} not found")
                if row[4] != Status.SUSPENDED.value:
                    raise PreconditionError(
                        f"Credential {cred_id} is {row[4]}; only suspended credentials can be reinstated",
                        reason="invalid_transition",
                    )
                try:
                    cur.execute(
                        f"""
                        UPDATE cred SET status = 'active' WHERE id = %s
                        RETURNING {_CRED_COLS}
                        """,
                        (uuid,),
                    )
                    updated = cur.fetchone()
                except Exception as exc:
                    if _is_unique_violation(exc):
                        raise DuplicateCredentialError(
                            f"Another active {row[2]} credential already exists for {row[3]}; cannot reinstate",
                        ) from exc
                    raise
        assert updated is not None
        return _row_to_cred(updated)

    def revoke_credential(self, cred_id: str) -> Credential:
        with self._tx() as conn:
            uuid = _wire_to_uuid(cred_id)
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {_CRED_COLS} FROM cred WHERE id = %s FOR UPDATE",
                    (uuid,),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"Credential {cred_id} not found")
                if row[4] == Status.REVOKED.value:
                    raise AlreadyTerminalError(f"Credential {cred_id} is already revoked")
                now = self._now()
                cur.execute(
                    f"""
                    UPDATE cred SET status = 'revoked' WHERE id = %s
                    RETURNING {_CRED_COLS}
                    """,
                    (uuid,),
                )
                updated = cur.fetchone()
                cur.execute(
                    "UPDATE ses SET revoked_at = %s WHERE cred_id = %s AND revoked_at IS NULL",
                    (now, uuid),
                )
        assert updated is not None
        return _row_to_cred(updated)

    def verify_password(self, identifier: str, password: str) -> VerifiedCredential:
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT {_CRED_COLS} FROM cred
                WHERE type = 'password' AND identifier = %s AND status = 'active'
                """,
                (identifier,),
            )
            row = cur.fetchone()
        if row is None or row[6] is None:
            raise InvalidCredentialError("Invalid credential")
        if not verify_password_hash(str(row[6]), password):
            raise InvalidCredentialError("Invalid credential")
        usr_uuid = str(row[1])
        # ADR 0008: surface usr_mfa_policy state. Applications MUST
        # gate create_session on mfa_required by calling verify_mfa
        # first when this is true.
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT required, grace_until FROM usr_mfa_policy WHERE usr_id = %s",
                (usr_uuid,),
            )
            policy_row = cur.fetchone()
        mfa_required = False
        if policy_row is not None and bool(policy_row[0]):
            grace = policy_row[1]
            if grace is None or grace <= self._now():
                mfa_required = True
        return VerifiedCredential(
            usr_id=_encode("usr", usr_uuid),
            cred_id=_encode("cred", str(row[0])),
            mfa_required=mfa_required,
        )

    # ─── Sessions ───

    def create_session(
        self, usr_id: str, cred_id: str, ttl_seconds: int,
    ) -> SessionWithToken:
        if ttl_seconds < 60:
            raise PreconditionError(
                "ttl_seconds must be >= 60",
                reason="ttl_too_short",
            )
        with self._tx() as conn:
            usr_uuid = _wire_to_uuid(usr_id)
            cred_uuid = _wire_to_uuid(cred_id)
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM usr WHERE id = %s", (usr_uuid,))
                user_row = cur.fetchone()
                if user_row is None:
                    raise NotFoundError(f"User {usr_id} not found")
                if user_row[0] != Status.ACTIVE.value:
                    raise PreconditionError(
                        f"Cannot create session for {user_row[0]} user",
                        reason="user_not_active",
                    )
                cur.execute("SELECT status, usr_id FROM cred WHERE id = %s", (cred_uuid,))
                cred_row = cur.fetchone()
                if cred_row is None:
                    raise NotFoundError(f"Credential {cred_id} not found")
                if cred_row[0] != Status.ACTIVE.value:
                    raise CredentialNotActiveError(f"Credential {cred_id} is {cred_row[0]}")
                if str(cred_row[1]) != usr_uuid:
                    raise PreconditionError(
                        f"Credential {cred_id} does not belong to {usr_id}",
                        reason="cred_user_mismatch",
                    )
                now = self._now()
                expires_at = now + timedelta(seconds=ttl_seconds)
                ses_uuid = _decode(_generate("ses")).uuid
                token = _generate_token()
                token_hash = _hash_token_bytes(token)
                cur.execute(
                    f"""
                    INSERT INTO ses (id, usr_id, cred_id, created_at, expires_at, token_hash)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING {_SES_COLS}
                    """,
                    (ses_uuid, usr_uuid, cred_uuid, now, expires_at, token_hash),
                )
                row = cur.fetchone()
        assert row is not None
        return SessionWithToken(session=_row_to_session(row), token=token)

    def get_session(self, ses_id: str) -> Session:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SES_COLS} FROM ses WHERE id = %s",
                (_wire_to_uuid(ses_id),),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"Session {ses_id} not found")
        return _row_to_session(row)

    def list_sessions_for_user(
        self, usr_id: str, *, cursor: str | None = None, limit: int = 50,
    ) -> Page[Session]:
        params: list[Any] = [_wire_to_uuid(usr_id)]
        sql = f"SELECT {_SES_COLS} FROM ses WHERE usr_id = %s"
        if cursor is not None:
            sql += " AND id > %s"
            params.append(_wire_to_uuid(cursor))
        params.append(min(limit, 200) + 1)
        sql += " ORDER BY id LIMIT %s"
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        page = rows[:limit]
        sessions = [_row_to_session(r) for r in page]
        next_cursor = sessions[-1].id if len(rows) > limit and sessions else None
        return Page(data=sessions, next_cursor=next_cursor)

    def verify_session_token(self, token: str) -> Session:
        token_hash = _hash_token_bytes(token)
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SES_COLS} FROM ses WHERE token_hash = %s",
                (token_hash,),
            )
            row = cur.fetchone()
        if row is None:
            raise InvalidTokenError("Invalid token")
        stored = _to_bytes(row[6]) if row[6] is not None else None
        if stored is None or not secrets.compare_digest(stored, token_hash):
            raise InvalidTokenError("Invalid token")
        if row[5] is not None:
            raise SessionExpiredError("Session is revoked")
        expires_at = (
            row[4] if isinstance(row[4], datetime)
            else datetime.fromisoformat(str(row[4]))
        )
        if self._now() > expires_at:
            raise SessionExpiredError("Session has expired")
        return _row_to_session(row)

    def refresh_session(self, ses_id: str) -> SessionWithToken:
        with self._tx() as conn:
            uuid = _wire_to_uuid(ses_id)
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT {_SES_COLS} FROM ses WHERE id = %s FOR UPDATE",
                    (uuid,),
                )
                row = cur.fetchone()
                if row is None:
                    raise NotFoundError(f"Session {ses_id} not found")
                if row[5] is not None:
                    raise SessionExpiredError("Session is already revoked")
                now = self._now()
                created_at = (
                    row[3] if isinstance(row[3], datetime)
                    else datetime.fromisoformat(str(row[3]))
                )
                expires_at = (
                    row[4] if isinstance(row[4], datetime)
                    else datetime.fromisoformat(str(row[4]))
                )
                if now > expires_at:
                    raise SessionExpiredError("Session has expired")
                cur.execute("UPDATE ses SET revoked_at = %s WHERE id = %s", (now, uuid))
                ttl = expires_at - created_at
                new_uuid = _decode(_generate("ses")).uuid
                token = _generate_token()
                token_hash = _hash_token_bytes(token)
                cur.execute(
                    f"""
                    INSERT INTO ses (id, usr_id, cred_id, created_at, expires_at, token_hash)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING {_SES_COLS}
                    """,
                    (new_uuid, row[1], row[2], now, now + ttl, token_hash),
                )
                new_row = cur.fetchone()
        assert new_row is not None
        return SessionWithToken(session=_row_to_session(new_row), token=token)

    def revoke_session(self, ses_id: str) -> Session:
        uuid = _wire_to_uuid(ses_id)
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE ses SET revoked_at = COALESCE(revoked_at, %s)
                WHERE id = %s
                RETURNING {_SES_COLS}
                """,
                (self._now(), uuid),
            )
            row = cur.fetchone()
        self._conn.commit()
        if row is None:
            raise NotFoundError(f"Session {ses_id} not found")
        return _row_to_session(row)

    # ─── MFA ───

    def _require_user_active_for_mfa(self, conn: Any, usr_id: str) -> str:
        usr_uuid = _wire_to_uuid(usr_id)
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM usr WHERE id = %s", (usr_uuid,))
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"User {usr_id} not found")
        if row[0] != Status.ACTIVE.value:
            raise PreconditionError(
                f"User {usr_id} is {row[0]}; cannot enroll MFA",
                reason="user_not_active",
            )
        return usr_uuid

    def enroll_totp_factor(
        self, usr_id: str, identifier: str,
    ) -> TotpEnrollmentResult:
        usr_uuid = self._require_user_active_for_mfa(self._conn, usr_id)
        # The partial-unique index `mfa_unique_active_singleton` only
        # fires on status='active'; new TOTP factors are inserted as
        # 'pending', so the duplicate-active check is explicit.
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM mfa WHERE usr_id = %s AND type = 'totp' AND status = 'active'",
                (usr_uuid,),
            )
            existing = cur.fetchone()
        if existing is not None:
            raise PreconditionError(
                f"User {usr_id} already has an active totp factor; revoke before re-enrolling",
                reason="active_singleton_exists",
            )
        now = self._now()
        secret = generate_totp_secret()
        mfa_uuid = _decode(_generate("mfa")).uuid
        expires_at = now + timedelta(seconds=PENDING_FACTOR_TTL_SECONDS)
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO mfa (id, usr_id, type, status, identifier,
                                 totp_secret, totp_algorithm, totp_digits, totp_period,
                                 pending_expires_at, created_at, updated_at)
                VALUES (%s, %s, 'totp', 'pending', %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING {_MFA_COLS}
                """,
                (
                    mfa_uuid, usr_uuid, identifier, secret,
                    DEFAULT_TOTP_ALGORITHM, DEFAULT_TOTP_DIGITS, DEFAULT_TOTP_PERIOD,
                    expires_at, now, now,
                ),
            )
            row = cur.fetchone()
        self._conn.commit()
        assert row is not None
        factor = _row_to_factor(row)
        assert isinstance(factor, TotpFactor)
        import base64
        return TotpEnrollmentResult(
            factor=factor,
            secret_b32=base64.b32encode(secret).rstrip(b"=").decode("ascii"),
            otpauth_uri=totp_otpauth_uri(secret=secret, label=identifier, issuer="Flametrench"),
        )

    def enroll_webauthn_factor(
        self,
        usr_id: str,
        identifier: str,
        public_key: bytes,
        sign_count: int,
        rp_id: str,
        *,
        aaguid: str | None = None,
        transports: list[str] | None = None,
    ) -> WebAuthnEnrollmentResult:
        usr_uuid = self._require_user_active_for_mfa(self._conn, usr_id)
        now = self._now()
        mfa_uuid = _decode(_generate("mfa")).uuid
        expires_at = now + timedelta(seconds=PENDING_FACTOR_TTL_SECONDS)
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO mfa (id, usr_id, type, status, identifier,
                                     webauthn_public_key, webauthn_sign_count, webauthn_rp_id,
                                     webauthn_aaguid, webauthn_transports,
                                     pending_expires_at, created_at, updated_at)
                    VALUES (%s, %s, 'webauthn', 'pending', %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING {_MFA_COLS}
                    """,
                    (
                        mfa_uuid, usr_uuid, identifier, public_key, sign_count, rp_id,
                        aaguid, transports, expires_at, now, now,
                    ),
                )
                row = cur.fetchone()
            self._conn.commit()
            assert row is not None
            factor = _row_to_factor(row)
            assert isinstance(factor, WebAuthnFactor)
            return WebAuthnEnrollmentResult(factor=factor)
        except Exception as exc:
            self._conn.rollback()
            if _is_unique_violation(exc):
                raise PreconditionError(
                    f"WebAuthn credential {identifier!r} is already enrolled",
                    reason="duplicate_webauthn_credential",
                ) from exc
            raise

    def enroll_recovery_factor(self, usr_id: str) -> RecoveryEnrollmentResult:
        usr_uuid = self._require_user_active_for_mfa(self._conn, usr_id)
        now = self._now()
        codes = generate_recovery_codes()
        hashes = [hash_password(c) for c in codes]
        consumed = [False] * len(codes)
        mfa_uuid = _decode(_generate("mfa")).uuid
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO mfa (id, usr_id, type, status,
                                     recovery_hashes, recovery_consumed,
                                     created_at, updated_at)
                    VALUES (%s, %s, 'recovery', 'active', %s, %s, %s, %s)
                    RETURNING {_MFA_COLS}
                    """,
                    (mfa_uuid, usr_uuid, hashes, consumed, now, now),
                )
                row = cur.fetchone()
            self._conn.commit()
            assert row is not None
            factor = _row_to_factor(row)
            assert isinstance(factor, RecoveryFactor)
            return RecoveryEnrollmentResult(factor=factor, codes=codes)
        except Exception as exc:
            self._conn.rollback()
            if _is_unique_violation(exc):
                raise PreconditionError(
                    f"User {usr_id} already has an active recovery factor; revoke before re-enrolling",
                    reason="active_singleton_exists",
                ) from exc
            raise

    def get_mfa_factor(self, mfa_id: str) -> Factor:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {_MFA_COLS} FROM mfa WHERE id = %s",
                (_wire_to_uuid(mfa_id),),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"MFA factor {mfa_id} not found")
        return _row_to_factor(row)

    def list_mfa_factors(self, usr_id: str) -> list[Factor]:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {_MFA_COLS} FROM mfa WHERE usr_id = %s ORDER BY created_at",
                (_wire_to_uuid(usr_id),),
            )
            rows = cur.fetchall()
        return [_row_to_factor(r) for r in rows]

    def _lock_mfa(self, conn: Any, mfa_id: str) -> Sequence[Any]:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_MFA_COLS} FROM mfa WHERE id = %s FOR UPDATE",
                (_wire_to_uuid(mfa_id),),
            )
            row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"MFA factor {mfa_id} not found")
        return row

    def _check_pending_not_expired(self, row: Sequence[Any]) -> None:
        if row[3] != FactorStatus.PENDING.value:
            return
        expires_at = (
            row[17] if isinstance(row[17], datetime)
            else (datetime.fromisoformat(str(row[17])) if row[17] is not None else None)
        )
        if expires_at is not None and self._now() > expires_at:
            raise PreconditionError(
                f"Pending factor {_encode('mfa', str(row[0]))} expired",
                reason="pending_factor_expired",
            )

    def confirm_totp_factor(self, mfa_id: str, code: str) -> TotpFactor:
        with self._tx() as conn:
            row = self._lock_mfa(conn, mfa_id)
            if row[2] != "totp":
                raise CredentialTypeMismatchError(f"Factor {mfa_id} is {row[2]}, not totp")
            if row[3] != FactorStatus.PENDING.value:
                raise PreconditionError(
                    f"Factor {mfa_id} is {row[3]}; only pending factors confirm",
                    reason="factor_not_pending",
                )
            self._check_pending_not_expired(row)
            secret = _to_bytes(row[6]) if row[6] is not None else b""
            if not totp_verify(secret, code, timestamp=int(self._now().timestamp())):
                raise InvalidCredentialError("TOTP code did not verify")
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE mfa SET status = 'active', pending_expires_at = NULL WHERE id = %s
                    RETURNING {_MFA_COLS}
                    """,
                    (row[0],),
                )
                updated = cur.fetchone()
        assert updated is not None
        factor = _row_to_factor(updated)
        assert isinstance(factor, TotpFactor)
        return factor

    def confirm_webauthn_factor(
        self,
        mfa_id: str,
        authenticator_data: bytes,
        client_data_json: bytes,
        signature: bytes,
        expected_challenge: bytes,
        expected_origin: str,
    ) -> WebAuthnFactor:
        with self._tx() as conn:
            row = self._lock_mfa(conn, mfa_id)
            if row[2] != "webauthn":
                raise CredentialTypeMismatchError(f"Factor {mfa_id} is {row[2]}, not webauthn")
            if row[3] != FactorStatus.PENDING.value:
                raise PreconditionError(
                    f"Factor {mfa_id} is {row[3]}; only pending factors confirm",
                    reason="factor_not_pending",
                )
            self._check_pending_not_expired(row)
            public_key = _to_bytes(row[10]) if row[10] is not None else b""
            result = webauthn_verify_assertion(
                cose_public_key=public_key,
                stored_sign_count=int(row[11] or 0),
                stored_rp_id=str(row[12] or ""),
                expected_challenge=expected_challenge,
                expected_origin=expected_origin,
                authenticator_data=authenticator_data,
                client_data_json=client_data_json,
                signature=signature,
            )
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE mfa SET status = 'active', webauthn_sign_count = %s, pending_expires_at = NULL
                    WHERE id = %s
                    RETURNING {_MFA_COLS}
                    """,
                    (result.new_sign_count, row[0]),
                )
                updated = cur.fetchone()
        assert updated is not None
        factor = _row_to_factor(updated)
        assert isinstance(factor, WebAuthnFactor)
        return factor

    def revoke_mfa_factor(self, mfa_id: str) -> Factor:
        with self._tx() as conn:
            row = self._lock_mfa(conn, mfa_id)
            if row[3] == FactorStatus.REVOKED.value:
                return _row_to_factor(row)
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE mfa SET status = 'revoked', pending_expires_at = NULL WHERE id = %s
                    RETURNING {_MFA_COLS}
                    """,
                    (row[0],),
                )
                updated = cur.fetchone()
        assert updated is not None
        return _row_to_factor(updated)

    def verify_mfa(self, usr_id: str, proof: MfaProof) -> MfaVerifyResult:
        if isinstance(proof, TotpProof):
            return self._verify_totp_proof(usr_id, proof.code)
        if isinstance(proof, WebAuthnProof):
            return self._verify_webauthn_proof(usr_id, proof)
        if isinstance(proof, RecoveryProof):
            return self._verify_recovery_proof(usr_id, proof.code)
        raise InvalidCredentialError("Unsupported MFA proof type")

    def _verify_totp_proof(self, usr_id: str, code: str) -> MfaVerifyResult:
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT {_MFA_COLS} FROM mfa
                WHERE usr_id = %s AND type = 'totp' AND status = 'active'
                """,
                (_wire_to_uuid(usr_id),),
            )
            row = cur.fetchone()
        if row is None:
            raise InvalidCredentialError("No active TOTP factor for user")
        secret = _to_bytes(row[6]) if row[6] is not None else b""
        if not totp_verify(secret, code, timestamp=int(self._now().timestamp())):
            raise InvalidCredentialError("TOTP code did not verify")
        return MfaVerifyResult(
            mfa_id=_encode("mfa", str(row[0])),
            type=FactorType.TOTP,
            mfa_verified_at=self._now(),
            new_sign_count=None,
        )

    def _verify_webauthn_proof(
        self, usr_id: str, proof: WebAuthnProof,
    ) -> MfaVerifyResult:
        with self._tx() as conn:
            usr_uuid = _wire_to_uuid(usr_id)
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT {_MFA_COLS} FROM mfa
                    WHERE identifier = %s AND type = 'webauthn' AND status = 'active'
                    FOR UPDATE
                    """,
                    (proof.credential_id,),
                )
                row = cur.fetchone()
            if row is None:
                raise InvalidCredentialError("No WebAuthn factor for credential id")
            if str(row[1]) != usr_uuid:
                raise InvalidCredentialError("WebAuthn factor does not belong to user")
            public_key = _to_bytes(row[10]) if row[10] is not None else b""
            result = webauthn_verify_assertion(
                cose_public_key=public_key,
                stored_sign_count=int(row[11] or 0),
                stored_rp_id=str(row[12] or ""),
                expected_challenge=proof.expected_challenge,
                expected_origin=proof.expected_origin,
                authenticator_data=proof.authenticator_data,
                client_data_json=proof.client_data_json,
                signature=proof.signature,
            )
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE mfa SET webauthn_sign_count = %s WHERE id = %s",
                    (result.new_sign_count, row[0]),
                )
        return MfaVerifyResult(
            mfa_id=_encode("mfa", str(row[0])),
            type=FactorType.WEBAUTHN,
            mfa_verified_at=self._now(),
            new_sign_count=result.new_sign_count,
        )

    def _verify_recovery_proof(self, usr_id: str, code: str) -> MfaVerifyResult:
        normalized = normalize_recovery_input(code)
        if not is_valid_recovery_code(normalized):
            raise InvalidCredentialError("Recovery code is malformed")
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT {_MFA_COLS} FROM mfa
                    WHERE usr_id = %s AND type = 'recovery' AND status = 'active'
                    FOR UPDATE
                    """,
                    (_wire_to_uuid(usr_id),),
                )
                row = cur.fetchone()
            if row is None:
                raise InvalidCredentialError("No active recovery factor for user")
            hashes = list(row[15] or [])
            consumed = list(row[16] or [])
            # Walk every active slot regardless of an early match to keep
            # work constant relative to the active set.
            matched = -1
            for i, h in enumerate(hashes):
                if i < len(consumed) and consumed[i]:
                    continue
                if verify_password_hash(str(h), normalized) and matched == -1:
                    matched = i
            if matched == -1:
                raise InvalidCredentialError("Recovery code did not verify")
            consumed[matched] = True
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE mfa SET recovery_consumed = %s WHERE id = %s",
                    (consumed, row[0]),
                )
        return MfaVerifyResult(
            mfa_id=_encode("mfa", str(row[0])),
            type=FactorType.RECOVERY,
            mfa_verified_at=self._now(),
            new_sign_count=None,
        )

    def get_mfa_policy(self, usr_id: str) -> UserMfaPolicy | None:
        usr_uuid = _wire_to_uuid(usr_id)
        with self._conn.cursor() as cur:
            cur.execute("SELECT id FROM usr WHERE id = %s", (usr_uuid,))
            if cur.fetchone() is None:
                raise NotFoundError(f"User {usr_id} not found")
            cur.execute(
                "SELECT usr_id, required, grace_until, updated_at FROM usr_mfa_policy WHERE usr_id = %s",
                (usr_uuid,),
            )
            row = cur.fetchone()
        return _row_to_policy(row) if row is not None else None

    def set_mfa_policy(
        self,
        usr_id: str,
        required: bool,
        grace_until: datetime | None = None,
    ) -> UserMfaPolicy:
        usr_uuid = _wire_to_uuid(usr_id)
        with self._conn.cursor() as cur:
            cur.execute("SELECT id FROM usr WHERE id = %s", (usr_uuid,))
            if cur.fetchone() is None:
                raise NotFoundError(f"User {usr_id} not found")
            cur.execute(
                """
                INSERT INTO usr_mfa_policy (usr_id, required, grace_until)
                VALUES (%s, %s, %s)
                ON CONFLICT (usr_id) DO UPDATE SET
                  required = EXCLUDED.required,
                  grace_until = EXCLUDED.grace_until
                RETURNING usr_id, required, grace_until, updated_at
                """,
                (usr_uuid, required, grace_until),
            )
            row = cur.fetchone()
        self._conn.commit()
        assert row is not None
        return _row_to_policy(row)
