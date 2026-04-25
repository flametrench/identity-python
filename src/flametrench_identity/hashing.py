# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Low-level Argon2id password-hashing primitives.

Use these when you need to hash or verify a password independently of
the IdentityStore — e.g., to bridge legacy password stores into the
Flametrench identity layer, or to satisfy the cross-language conformance
fixture (`spec/conformance/fixtures/identity/argon2id.json`).

Cross-language interop contract: a PHC-encoded Argon2id hash produced
by any conforming Flametrench identity SDK MUST verify identically here,
regardless of the language or Argon2 binding that produced it.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2 import exceptions as argon2_exceptions
from argon2.low_level import Type as Argon2Type

from .types import ARGON2ID_FLOOR

# Configure the hasher with the spec floor parameters. argon2-cffi's
# defaults are higher than the spec floor; we explicitly pin to match
# Node's argon2 package and PHP's PASSWORD_ARGON2ID at the same params.
_HASHER = PasswordHasher(
    time_cost=ARGON2ID_FLOOR["time_cost"],
    memory_cost=ARGON2ID_FLOOR["memory_cost"],
    parallelism=ARGON2ID_FLOOR["parallelism"],
    hash_len=32,
    salt_len=16,
    type=Argon2Type.ID,
)


def verify_password_hash(phc_hash: str, candidate_password: str) -> bool:
    """Verify a candidate plaintext password against a PHC-encoded Argon2id hash.

    Returns False on any verification failure (wrong password, malformed
    hash, unsupported variant) — never raises on bad input. The contract
    is "did this plaintext produce that hash?", and the answer to a
    malformed hash is "no".
    """
    try:
        return _HASHER.verify(phc_hash, candidate_password)
    except (
        argon2_exceptions.VerifyMismatchError,
        argon2_exceptions.InvalidHashError,
        argon2_exceptions.VerificationError,
        # InvalidHash was renamed to InvalidHashError in argon2-cffi 23.x.
        # Catch the broad superclass for forward compatibility.
        argon2_exceptions.Argon2Error,
    ):
        return False


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password with Argon2id at the spec floor.

    Returns a PHC-encoded string that verifies against
    ``verify_password_hash`` on any conforming Flametrench identity SDK.
    """
    return _HASHER.hash(plaintext)
