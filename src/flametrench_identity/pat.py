# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Personal access tokens — v0.3 reference per ADR 0016.

PATs are long-lived bearer credentials bound to a usr, intended for
non-interactive use (CLI / CI / server-to-server). They are NOT a cred
variant: different lifecycle (no rotation, no replaces chain),
different verification path (the secret IS the proof; no challenge),
different audit shape (auth.kind = 'pat').

Wire format: ``pat_<32hex-id>_<base64url-secret>``. The plaintext token
leaves the server exactly once, in :class:`CreatePatResult`; the server
stores only an Argon2id hash of the secret segment at the cred-password
parameter floor.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class PatStatus(str, Enum):
    """Lifecycle status of a PAT.

    - ``active`` — present, not expired, not revoked.
    - ``expired`` — past expires_at. Terminal.
    - ``revoked`` — revoke_pat called. Terminal.

    A PAT cannot return to active once it leaves it; re-issuance creates
    a new pat row, NOT a replaces-chain entry.
    """

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass(frozen=True)
class PersonalAccessToken:
    """Server-persisted PAT record. The secret hash is NEVER carried —
    only metadata. To obtain the plaintext token call
    :meth:`IdentityStore.create_pat`; thereafter only the owner's local
    copy holds the secret."""

    id: str
    usr_id: str
    name: str
    """Human-readable label set by the issuing user. 1–120 chars."""
    scope: list[str]
    """Application-defined scope claims; may be empty."""
    status: PatStatus
    expires_at: datetime | None
    """Optional expiry. ``None`` means no expiry; valid until revoked."""
    last_used_at: datetime | None
    """Most recent successful verify_pat_token, or None if never used.
    Eventual-consistent under burst load — the SDK coalesces writes
    within a configurable window (60s default) per ADR 0016
    §"Operational notes"."""
    revoked_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class VerifiedPat:
    """Successful result of :meth:`IdentityStore.verify_pat_token`.

    Carries only the fields a request-handling middleware needs to
    populate audit + authz context: the pat id (audit handle), the
    usr_id (the principal the request acts as), and the scope (the
    application-defined claims attached to this token).
    """

    pat_id: str
    usr_id: str
    scope: list[str]


# Spec floor: PAT ``expires_at`` MUST be no more than 365 days from
# ``created_at`` when set (ADR 0016 §"Constraints"). Implementations
# MAY enforce a tighter cap. 365 days = 31,536,000 seconds.
PAT_MAX_LIFETIME_SECONDS = 365 * 24 * 60 * 60
