# Changelog

All notable changes to `flametrench-identity` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.2.0rc5] — 2026-04-27

### Fixed (security posture)
- `verify_password` now consults `usr_mfa_policy` and returns `VerifiedCredential.mfa_required = True` when a user has `required = True` AND the grace window has elapsed (or was never set). Previously the policy table was decorative — the SDK never read it, so an adopter configuring per-user MFA enforcement could be bypassed by application code that called `create_session` directly without checking the policy. The new field is additive (defaults to `False`), so adopters who do not configure a policy see no behavioral change. Applications MUST gate `create_session` on `mfa_required` by calling `verify_mfa` first when it is `True`. (ADR 0008.)

## [v0.2.0rc4] — 2026-04-27

### Added
- `PostgresIdentityStore` (new module `flametrench_identity.postgres`) — a Postgres-backed `IdentityStore`. Mirrors `InMemoryIdentityStore` byte-for-byte at the SDK boundary; the difference is durability and concurrency.
  - Schema: `spec/reference/postgres.sql` (the `usr`, `cred`, `ses`, `mfa`, `usr_mfa_policy` tables, plus `ses.mfa_verified_at`).
  - Connection: accepts any psycopg3-compatible connection. `psycopg[binary]>=3.1` declared as the `postgres` extra — adopters using only the in-memory store don't pull it in.
  - Token storage: SHA-256 hashed and stored as 32 raw bytes (`BYTEA`). Plaintext tokens are returned ONCE on create/refresh and never persisted.
  - Multi-statement ops (`revoke_user` cascade, credential rotation, `refresh_session`, MFA confirm/verify, recovery-slot consumption) run inside a transaction.
  - Coverage: 23 integration tests, gated on `IDENTITY_POSTGRES_URL`.

## [v0.2.0rc3] — 2026-04-26

### Added (MFA store ops, ADR 0008 Phase 1)
- `enroll_totp_factor`, `enroll_webauthn_factor`, `enroll_recovery_factor`, `confirm_totp_factor`, `confirm_webauthn_factor`, `revoke_mfa_factor`, `verify_mfa`, `get_mfa_policy`, `set_mfa_policy` on `IdentityStore`. Wires the MFA primitives behind a single store-level surface so adopters don't write the orchestration themselves.

## [v0.2.0rc2] — 2026-04-26

WebAuthn RS256 + EdDSA assertion verification per ADR 0010.

## [v0.2.0rc1] — 2026-04-25

Initial v0.2 release-candidate.

For pre-rc history, see git tags.
