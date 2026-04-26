# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""WebAuthn assertion verification — v0.2 reference per ADR 0008.

Implements the verifier side of the FIDO2 / WebAuthn `navigator.credentials.get()`
flow. The host application has already issued a challenge and received an
``AuthenticatorAssertionResponse`` from the browser; this module owns the
server-side verification of that response.

Scope (v0.2):

- ES256 only (ECDSA P-256 + SHA-256). FIDO2 platform authenticators
  (Touch ID, Windows Hello, Android, all major hardware keys) default to
  ES256. RS256 and EdDSA are deferred to v0.3 — the conformance corpus
  pins ES256 vectors only.
- COSE_Key parsing limited to the EC2 / P-256 / ES256 shape. Other
  ``kty`` values raise.
- Counter monotonicity per WebAuthn spec §6.1.1: a strictly-greater
  counter advances the stored value; a counter that would stay equal or
  decrease (when at least one of stored/incoming is non-zero) is rejected
  as a cloned-authenticator signal.
- ``UV`` (user-verified) flag enforcement is opt-in. Most consumer
  apps want it on; some legacy second-factor flows want it off.

The verifier returns a structured result so callers can persist the
new sign count atomically with the session decision. Failures raise
typed exceptions — callers get a stable ``code`` they can map to API
responses.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .errors import IdentityError

# ─── Errors ───────────────────────────────────────────────────────


class WebAuthnError(IdentityError):
    """Base class for WebAuthn assertion verification errors."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message, code=f"webauthn.{reason}")
        self.reason = reason


class WebAuthnSignatureError(WebAuthnError):
    """The assertion signature did not verify against the stored public key."""

    def __init__(self, message: str = "Signature verification failed") -> None:
        super().__init__(message, reason="signature_invalid")


class WebAuthnCounterRegressionError(WebAuthnError):
    """The authenticator's signature counter did not strictly advance.

    A counter that decreases — or fails to advance when at least one
    side is non-zero — is the WebAuthn spec's cloned-authenticator
    signal. The credential MUST be treated as compromised.
    """

    def __init__(self, message: str = "Sign count did not advance") -> None:
        super().__init__(message, reason="counter_regression")


class WebAuthnRpIdMismatchError(WebAuthnError):
    """The RP ID hash in authenticatorData does not match the registered RP ID."""

    def __init__(self, message: str = "RP ID hash mismatch") -> None:
        super().__init__(message, reason="rp_id_mismatch")


class WebAuthnUserNotVerifiedError(WebAuthnError):
    """The UV bit is required but the assertion lacks it."""

    def __init__(self, message: str = "User-verified flag not set") -> None:
        super().__init__(message, reason="user_not_verified")


class WebAuthnUserNotPresentError(WebAuthnError):
    """The UP bit is required but the assertion lacks it."""

    def __init__(self, message: str = "User-present flag not set") -> None:
        super().__init__(message, reason="user_not_present")


class WebAuthnChallengeMismatchError(WebAuthnError):
    """The challenge in clientDataJSON does not match the issued challenge."""

    def __init__(self, message: str = "Challenge mismatch") -> None:
        super().__init__(message, reason="challenge_mismatch")


class WebAuthnOriginMismatchError(WebAuthnError):
    """The origin in clientDataJSON does not match the expected origin."""

    def __init__(self, message: str = "Origin mismatch") -> None:
        super().__init__(message, reason="origin_mismatch")


class WebAuthnTypeMismatchError(WebAuthnError):
    """clientDataJSON.type is not "webauthn.get"."""

    def __init__(self, message: str = "Type mismatch") -> None:
        super().__init__(message, reason="type_mismatch")


class WebAuthnMalformedError(WebAuthnError):
    """Malformed input bytes (truncated authenticatorData, invalid JSON, etc.)."""

    def __init__(self, message: str = "Malformed assertion input") -> None:
        super().__init__(message, reason="malformed")


class WebAuthnUnsupportedKeyError(WebAuthnError):
    """COSE public key uses a kty/alg/crv combination outside the v0.2 ES256 scope."""

    def __init__(self, message: str = "Unsupported COSE key") -> None:
        super().__init__(message, reason="unsupported_key")


# ─── Result ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class WebAuthnAssertionResult:
    """Successful verification result.

    The new sign count MUST be persisted atomically with the session
    decision; otherwise a race lets a cloned authenticator slip through.
    """

    new_sign_count: int


# ─── Authenticator data flag bits (WebAuthn §6.1) ────────────────

_FLAG_UP = 0x01  # User Present
_FLAG_UV = 0x04  # User Verified
_FLAG_AT = 0x40  # Attested Credential Data included
_FLAG_ED = 0x80  # Extension Data included


# ─── Minimal CBOR / COSE-key parsing ─────────────────────────────


def _parse_cose_es256(cose_key: bytes) -> ec.EllipticCurvePublicKey:
    """Parse a COSE_Key (RFC 8152) for the ES256 case only.

    The expected map shape is::

        {
          1 (kty):  2 (EC2),
          3 (alg): -7 (ES256),
          -1 (crv): 1 (P-256),
          -2 (x):   <32 raw bytes>,
          -3 (y):   <32 raw bytes>,
        }

    Anything else raises ``WebAuthnUnsupportedKeyError`` or
    ``WebAuthnMalformedError``.
    """
    fields = _decode_cbor_map(cose_key)
    kty = fields.get(1)
    alg = fields.get(3)
    crv = fields.get(-1)
    x = fields.get(-2)
    y = fields.get(-3)
    if kty != 2:
        raise WebAuthnUnsupportedKeyError(f"Unsupported COSE kty: {kty!r}")
    if alg != -7:
        raise WebAuthnUnsupportedKeyError(f"Unsupported COSE alg: {alg!r}")
    if crv != 1:
        raise WebAuthnUnsupportedKeyError(f"Unsupported COSE crv: {crv!r}")
    if not isinstance(x, (bytes, bytearray)) or len(x) != 32:
        raise WebAuthnMalformedError("COSE x coordinate must be 32 bytes")
    if not isinstance(y, (bytes, bytearray)) or len(y) != 32:
        raise WebAuthnMalformedError("COSE y coordinate must be 32 bytes")
    public_numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x, "big"),
        y=int.from_bytes(y, "big"),
        curve=ec.SECP256R1(),
    )
    return public_numbers.public_key()


def _decode_cbor_map(buf: bytes) -> dict[int, object]:
    """Decode a CBOR map of small-integer keys to int / bytes values.

    Implements only the subset needed for ES256 COSE keys:
      - major type 0 (unsigned int): 0..23 inline, then 1/2/4/8-byte
      - major type 1 (negative int): mirrors major 0
      - major type 2 (byte string): 0..23 inline, then 1/2/4/8-byte length
      - major type 5 (map): same length encoding

    Anything else raises WebAuthnMalformedError. The full CBOR
    universe is large; this is enough to round-trip any conforming
    ES256 COSE_Key emitted by a browser-side WebAuthn registration.
    """
    decoder = _CborDecoder(buf)
    value = decoder.decode_item()
    if decoder.offset != len(buf):
        raise WebAuthnMalformedError("Trailing bytes after CBOR map")
    if not isinstance(value, dict):
        raise WebAuthnMalformedError("Top-level COSE value is not a map")
    return value


class _CborDecoder:
    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.offset = 0

    def _read(self, n: int) -> bytes:
        if self.offset + n > len(self.buf):
            raise WebAuthnMalformedError("CBOR truncated")
        out = self.buf[self.offset : self.offset + n]
        self.offset += n
        return out

    def _read_uint(self, info: int) -> int:
        if info < 24:
            return info
        if info == 24:
            return self._read(1)[0]
        if info == 25:
            return struct.unpack(">H", self._read(2))[0]
        if info == 26:
            return struct.unpack(">I", self._read(4))[0]
        if info == 27:
            return struct.unpack(">Q", self._read(8))[0]
        raise WebAuthnMalformedError(f"Unsupported CBOR info: {info}")

    def decode_item(self) -> object:
        first = self._read(1)[0]
        major = first >> 5
        info = first & 0x1F
        if major == 0:
            return self._read_uint(info)
        if major == 1:
            return -1 - self._read_uint(info)
        if major == 2:
            length = self._read_uint(info)
            return self._read(length)
        if major == 5:
            length = self._read_uint(info)
            out: dict[int, object] = {}
            for _ in range(length):
                key = self.decode_item()
                value = self.decode_item()
                if not isinstance(key, int):
                    raise WebAuthnMalformedError("Non-int CBOR map key")
                out[key] = value
            return out
        raise WebAuthnMalformedError(f"Unsupported CBOR major type: {major}")


# ─── Authenticator data parsing ──────────────────────────────────


@dataclass(frozen=True)
class _AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int

    @property
    def user_present(self) -> bool:
        return bool(self.flags & _FLAG_UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & _FLAG_UV)


def _parse_authenticator_data(buf: bytes) -> _AuthenticatorData:
    if len(buf) < 37:
        raise WebAuthnMalformedError("authenticatorData truncated")
    rp_id_hash = buf[:32]
    flags = buf[32]
    sign_count = struct.unpack(">I", buf[33:37])[0]
    return _AuthenticatorData(rp_id_hash=rp_id_hash, flags=flags, sign_count=sign_count)


# ─── Signature decoding (DER → r/s) ──────────────────────────────


def _is_valid_der_ecdsa_signature(sig: bytes) -> bool:
    """Cheap sanity check: starts with 0x30 (SEQUENCE) and a length tag."""
    return len(sig) >= 8 and sig[0] == 0x30


# ─── Public verifier ─────────────────────────────────────────────


def webauthn_verify_assertion(
    *,
    cose_public_key: bytes,
    stored_sign_count: int,
    stored_rp_id: str,
    expected_challenge: bytes,
    expected_origin: str,
    authenticator_data: bytes,
    client_data_json: bytes,
    signature: bytes,
    require_user_verified: bool = True,
    require_user_present: bool = True,
) -> WebAuthnAssertionResult:
    """Verify a WebAuthn assertion and return the new sign count.

    :param cose_public_key: COSE_Key bytes from the credential's
        registration. v0.2 supports ES256 only.
    :param stored_sign_count: The signature counter recorded on the
        last successful assertion (or registration).
    :param stored_rp_id: The RP ID the credential was registered for.
    :param expected_challenge: The raw challenge bytes the application
        issued for this assertion. Compared against the base64url-decoded
        ``challenge`` field in clientDataJSON.
    :param expected_origin: The origin the application expects (e.g.
        ``"https://example.com"``).
    :param authenticator_data: The ``AuthenticatorAssertionResponse``
        ``authenticatorData`` bytes.
    :param client_data_json: The ``AuthenticatorAssertionResponse``
        ``clientDataJSON`` bytes (raw, NOT base64url-decoded).
    :param signature: The ``AuthenticatorAssertionResponse`` ``signature``
        bytes (DER-encoded ECDSA signature for ES256).
    :param require_user_verified: When True (default), reject assertions
        that lack the UV bit.
    :param require_user_present: When True (default), reject assertions
        that lack the UP bit. Only flip off in narrow legacy second-factor
        flows where the authenticator does not signal user presence.
    :returns: A :class:`WebAuthnAssertionResult` with the new sign count.
    :raises WebAuthnError: subclass per failure mode.
    """
    # Parse clientDataJSON.
    try:
        client_data = json.loads(client_data_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebAuthnMalformedError(f"clientDataJSON not valid JSON: {exc}") from exc
    if not isinstance(client_data, dict):
        raise WebAuthnMalformedError("clientDataJSON is not an object")
    if client_data.get("type") != "webauthn.get":
        raise WebAuthnTypeMismatchError(
            f"clientDataJSON.type must be 'webauthn.get', got {client_data.get('type')!r}"
        )
    if client_data.get("origin") != expected_origin:
        raise WebAuthnOriginMismatchError(
            f"Origin mismatch: expected {expected_origin!r}, got {client_data.get('origin')!r}"
        )
    challenge_b64u = client_data.get("challenge")
    if not isinstance(challenge_b64u, str):
        raise WebAuthnMalformedError("clientDataJSON.challenge missing or not a string")
    try:
        challenge_bytes = _b64url_decode(challenge_b64u)
    except ValueError as exc:
        raise WebAuthnMalformedError(f"clientDataJSON.challenge not base64url: {exc}") from exc
    if challenge_bytes != expected_challenge:
        raise WebAuthnChallengeMismatchError("Challenge does not match")

    # Parse authenticatorData and check RP ID + flags + counter.
    auth = _parse_authenticator_data(authenticator_data)
    expected_rp_hash = hashlib.sha256(stored_rp_id.encode("utf-8")).digest()
    if auth.rp_id_hash != expected_rp_hash:
        raise WebAuthnRpIdMismatchError("RP ID hash does not match")
    if require_user_present and not auth.user_present:
        raise WebAuthnUserNotPresentError()
    if require_user_verified and not auth.user_verified:
        raise WebAuthnUserNotVerifiedError()

    # Counter monotonicity (WebAuthn §6.1.1).
    if auth.sign_count == 0 and stored_sign_count == 0:
        # Authenticator does not track a counter; spec-permitted.
        new_sign_count = 0
    elif auth.sign_count > stored_sign_count:
        new_sign_count = auth.sign_count
    else:
        raise WebAuthnCounterRegressionError(
            f"Sign count did not advance: stored={stored_sign_count}, got={auth.sign_count}"
        )

    # Verify the ES256 signature over authData || sha256(clientDataJSON).
    public_key = _parse_cose_es256(cose_public_key)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):  # pragma: no cover
        raise WebAuthnUnsupportedKeyError("Public key is not EC")
    client_hash = hashlib.sha256(client_data_json).digest()
    signed = authenticator_data + client_hash
    if not _is_valid_der_ecdsa_signature(signature):
        raise WebAuthnSignatureError("Signature is not a DER ECDSA structure")
    try:
        public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise WebAuthnSignatureError() from exc

    return WebAuthnAssertionResult(new_sign_count=new_sign_count)


# ─── Helpers exposed for cross-SDK fixture authoring ─────────────


def cose_key_es256(x: bytes, y: bytes) -> bytes:
    """Encode a P-256 public key (32-byte x, 32-byte y) as a COSE_Key.

    Useful for fixture authors and for SDKs that store keys as raw
    coordinates rather than COSE bytes. Inverse of the ES256 path
    through :func:`_parse_cose_es256`.
    """
    if len(x) != 32 or len(y) != 32:
        raise ValueError("ES256 coordinates must be 32 bytes each")
    # CBOR map(5):
    #   1: 2          (kty=EC2)
    #   3: -7         (alg=ES256)
    #  -1: 1          (crv=P-256)
    #  -2: bytes(32)  (x)
    #  -3: bytes(32)  (y)
    return (
        b"\xa5"  # map(5)
        + b"\x01\x02"  # 1: 2
        + b"\x03\x26"  # 3: -7  (negative int: 0x20|6 = 0x26)
        + b"\x20\x01"  # -1: 1
        + b"\x21\x58\x20" + bytes(x)  # -2: bytes(32) x
        + b"\x22\x58\x20" + bytes(y)  # -3: bytes(32) y
    )


def _b64url_decode(s: str) -> bytes:
    """Decode a base64url string with optional padding."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64url_encode(buf: bytes) -> str:
    """Encode bytes as base64url with no padding (WebAuthn convention)."""
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")
