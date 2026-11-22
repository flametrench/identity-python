# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Flametrench conformance suite: step-based identity fixtures.

Fixtures exercised here (vendored byte-identical from spec main):

- ``identity/mfa/totp-replay-rejected.json`` (ADR 0027)
- ``identity/user-status-gates.json`` (ADR 0029)

Each test is a sequence of steps. A step calls one store operation,
may capture values from its result into variables (``{name}`` in a
later step's input), and may expect an error. Per ADR 0027 decision 7
an expected error matches only when the raised type is exactly the
named one, not a supertype or subtype.

Every test runs against InMemoryIdentityStore and, when
IDENTITY_POSTGRES_URL is set, PostgresIdentityStore. Tests that use
PATs are skipped on Postgres: PostgresIdentityStore has no PAT methods.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import pytest

from flametrench_identity import InMemoryIdentityStore, totp_compute
from flametrench_identity.mfa import TotpProof

_FIXTURES_DIR = Path(__file__).parent / "conformance" / "fixtures"
_SCHEMA_SQL = Path(__file__).parent / "postgres-schema.sql"
POSTGRES_URL = os.environ.get("IDENTITY_POSTGRES_URL")

FIXTURE_FILES = [
    "identity/mfa/totp-replay-rejected.json",
    "identity/user-status-gates.json",
]
PAT_OPS = {"create_pat", "verify_pat_token"}


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now


def _substitute(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):
        if value.startswith("{") and value.endswith("}") and value[1:-1] in variables:
            return variables[value[1:-1]]
        return value
    if isinstance(value, dict):
        return {k: _substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, variables) for v in value]
    return value


def _extract(obj: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        obj = obj[part] if isinstance(obj, dict) else getattr(obj, part)
    return obj


def _set_clock(store: Any, clock: Clock, i: dict[str, Any]) -> Any:
    clock.now = datetime.fromisoformat(i["now"].replace("Z", "+00:00"))


def _create_user_with_password_credential(store: Any, clock: Clock, i: dict[str, Any]) -> Any:
    user = store.create_user()
    cred = store.create_password_credential(user.id, i["identifier"], i["password"])
    return {"user": user, "credential": cred}


def _enroll_totp_factor(store: Any, clock: Clock, i: dict[str, Any]) -> Any:
    # The fixtures give no identifier; the Python SDK requires a label.
    result = store.enroll_totp_factor(i["usr_id"], i.get("identifier", "fixture-totp"))
    return {"factor": result.factor, "secret": result.secret_b32}


def _compute_totp_code(store: Any, clock: Clock, i: dict[str, Any]) -> Any:
    secret = i["secret"]
    raw = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    return {"code": totp_compute(raw, int(clock.now.timestamp()))}


def _verify_mfa(store: Any, clock: Clock, i: dict[str, Any]) -> Any:
    proof = i["proof"]
    if proof["type"] != "totp":
        raise ValueError(f"unsupported proof type in fixture: {proof['type']!r}")
    return store.verify_mfa(i["usr_id"], TotpProof(code=proof["code"]))


OPS: dict[str, Callable[[Any, Clock, dict[str, Any]], Any]] = {
    "set_clock": _set_clock,
    "create_user": lambda s, c, i: {"user": s.create_user()},
    "create_user_with_password_credential": _create_user_with_password_credential,
    "enroll_totp_factor": _enroll_totp_factor,
    "compute_totp_code": _compute_totp_code,
    "confirm_totp_factor": lambda s, c, i: s.confirm_totp_factor(i["mfa_id"], i["code"]),
    "verify_mfa": _verify_mfa,
    "suspend_user": lambda s, c, i: s.suspend_user(i["usr_id"]),
    "reinstate_user": lambda s, c, i: s.reinstate_user(i["usr_id"]),
    "revoke_user": lambda s, c, i: s.revoke_user(i["usr_id"]),
    "verify_password": lambda s, c, i: s.verify_password(i["identifier"], i["password"]),
    "create_session": lambda s, c, i: s.create_session(i["usr_id"], i["cred_id"], i["ttl_seconds"]),
    "create_pat": lambda s, c, i: s.create_pat(i["usr_id"], i["name"], i["scope"]),
    "verify_pat_token": lambda s, c, i: s.verify_pat_token(i["token"]),
}


def _run_steps(store: Any, clock: Clock, test: dict[str, Any]) -> None:
    variables: dict[str, Any] = {}
    steps = test["steps"]
    for n, step in enumerate(steps):
        where = f"step {n} ({step['op']})"
        expected_error = (step.get("expected") or {}).get("error")
        op = OPS.get(step["op"])
        assert op is not None, f"{where}: op not implemented by this harness"
        inp = _substitute(step.get("input", {}), variables)
        try:
            result = op(store, clock, inp)
        except Exception as exc:
            if expected_error is None:
                raise AssertionError(f"{where}: unexpected {type(exc).__name__}: {exc}") from exc
            assert type(exc).__name__ == expected_error, (
                f"{where}: expected exactly {expected_error}, got {type(exc).__name__}: {exc}"
            )
            assert n == len(steps) - 1, f"{where}: fixture has steps after an expected error"
            return
        assert expected_error is None, f"{where}: expected {expected_error}, but the call succeeded"
        for name, path in (step.get("captures") or {}).items():
            variables[name] = _extract(result, path)


def _params() -> list[Any]:
    params = []
    for rel in FIXTURE_FILES:
        fixture = json.loads((_FIXTURES_DIR / rel).read_text(encoding="utf-8"))
        for test in fixture["tests"]:
            for backend in ("memory", "postgres"):
                params.append(pytest.param(test, backend, id=f"{backend}:{test['id']}"))
    return params


@pytest.mark.parametrize("test,backend", _params())
def test_identity_step_conformance(test: dict[str, Any], backend: str) -> None:
    clock = Clock()
    if backend == "memory":
        _run_steps(InMemoryIdentityStore(clock=clock), clock, test)
        return
    if POSTGRES_URL is None:
        pytest.skip("IDENTITY_POSTGRES_URL not set; PostgresIdentityStore tests skipped.")
    if any(step["op"] in PAT_OPS for step in test["steps"]):
        pytest.skip("PostgresIdentityStore has no PAT methods.")
    import psycopg

    from flametrench_identity.postgres import PostgresIdentityStore

    conn = psycopg.connect(POSTGRES_URL, autocommit=False)
    try:
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            cur.execute(_SCHEMA_SQL.read_text())
        conn.commit()
        _run_steps(PostgresIdentityStore(conn, clock=clock), clock, test)
    finally:
        conn.close()
