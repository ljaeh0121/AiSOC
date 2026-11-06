"""``GET /api/v1/cases/{id}/attack-chain`` through the shipped app and real PostgreSQL.

What a request does to the database is part of the contract. The route used
to upsert every computed chain into ``aisoc_attack_chains`` on a GET, behind
a comment saying later navigations would skip the traversal — but nothing
reads that table and its unique key includes the chain signature, so the
signature must be known before the row can be found: it cannot serve as a
lookup. The result was one unreadable row per distinct chain, per window,
written by a read. A GET must not write.
"""

from __future__ import annotations

import os
import socket
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("ATTACK_CHAIN_PROOF_REQUIRED", "").strip() not in ("", "0", "false")


def _postgres_is_listening() -> bool:
    parsed = urlparse(_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not ("postgres" in _DSN and _postgres_is_listening()) and not _REQUIRED,
    reason="needs a live PostgreSQL with the migration chain applied",
)

T0 = datetime(2026, 5, 14, 8, 0, 0, tzinfo=UTC)
USER = "jdoe@acme.test"


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    yield
    from app.db.database import engine

    await engine.dispose()


@pytest_asyncio.fixture
async def case_with_chain():
    """A tenant, an analyst, and a case whose alerts share a user.
    Yields ``(token, tenant_id, case_id, alert_ids)``."""
    from app.core.security import create_access_token

    engine = create_async_engine(_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant, user, case = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    suffix = tenant.hex[:8]
    ids = [uuid.uuid4() for _ in range(3)]
    async with maker() as db:
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant, "n": f"ac-{suffix}", "s": f"ac-{suffix}"},
        )
        await db.execute(
            text(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active, is_verified)"
                " VALUES (:i, :t, :e, :u, 'x', 'admin', TRUE, TRUE)"
            ),
            {"i": user, "t": tenant, "e": f"a-{suffix}@example.com", "u": f"a-{suffix}"},
        )
        for n, aid in enumerate(ids):
            await db.execute(
                text(
                    "INSERT INTO alerts (id, tenant_id, title, severity, status, event_time, affected_users, mitre_techniques)"
                    " VALUES (:i, :t, :ti, 'high', 'new', :et, CAST(:u AS JSONB), CAST(:m AS JSONB))"
                ),
                {
                    "i": aid,
                    "t": tenant,
                    "ti": f"alert {n}",
                    "et": T0 + timedelta(minutes=10 * n),
                    "u": f'["{USER}"]',
                    "m": '["T1566"]',
                },
            )
        await db.execute(
            text("INSERT INTO aisoc_cases (id, tenant_id, title, alert_ids) VALUES (:i, :t, 'case', :a)"),
            {"i": case, "t": tenant, "a": ids},
        )
        await db.commit()

    yield create_access_token({"sub": str(user)}), tenant, case, ids

    async with maker() as db:
        await db.execute(text("DELETE FROM aisoc_attack_chains WHERE tenant_id = :t"), {"t": tenant})
        await db.execute(text("DELETE FROM aisoc_cases WHERE id = :c"), {"c": case})
        await db.execute(text("DELETE FROM alerts WHERE tenant_id = :t"), {"t": tenant})
        await db.execute(text("DELETE FROM users WHERE id = :u"), {"u": user})
        await db.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tenant})
        await db.commit()
    await engine.dispose()


async def _get(token: str, case: uuid.UUID, **params):
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        return await client.get(f"/api/v1/cases/{case}/attack-chain", params=params, headers={"Authorization": f"Bearer {token}"})


async def _cached_rows(tenant: uuid.UUID) -> int:
    engine = create_async_engine(_DSN)
    try:
        async with async_sessionmaker(engine)() as db:
            return (await db.execute(text("SELECT count(*) FROM aisoc_attack_chains WHERE tenant_id = :t"), {"t": tenant})).scalar_one()
    finally:
        await engine.dispose()


async def test_the_route_returns_the_chain_and_says_whether_it_was_cut(case_with_chain) -> None:
    token, _tenant, case, ids = case_with_chain

    r = await _get(token, case)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["seed_alert_id"] == str(ids[0])
    assert {link["alert_id"] for link in body["chain"]} == {str(ids[1]), str(ids[2])}
    assert body["truncated"] is False
    assert body["truncated_reasons"] == []


async def test_a_get_leaves_no_rows_behind(case_with_chain) -> None:
    token, tenant, case, _ids = case_with_chain

    for window in ("24h", "7d"):
        assert (await _get(token, case, window=window)).status_code == 200

    assert await _cached_rows(tenant) == 0
