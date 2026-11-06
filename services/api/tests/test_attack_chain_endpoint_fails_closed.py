"""``GET /cases/{id}/attack-chain`` must say so when the database fails.

A candidate sweep that errors used to look like "no related alerts" to a
loader that swallowed it, and a bare 500 once it did not. An analyst reading
an empty chain concludes the intrusion is isolated; the honest answer is 503.

The route, ``compute_attack_chain`` and ``PostgresAttackChainLoader`` are the
shipped ones. Only the session is scripted, because the behaviour under test
is what the route does when ``execute`` raises on the candidate query — a
failure a healthy database cannot be asked to produce on demand.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from app.api.v1 import deps
from app.api.v1.endpoints import attack_chain as endpoint
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import OperationalError

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000778")
CASE_ID = uuid.uuid4()
SEED_ID = uuid.uuid4()


def _seed_row() -> SimpleNamespace:
    return SimpleNamespace(
        id=SEED_ID,
        tenant_id=TENANT,
        title="seed",
        severity="high",
        event_time=datetime(2026, 5, 14, 8, tzinfo=UTC),
        mitre_techniques=["T1566"],
        affected_users=["jdoe@acme.test"],
        affected_hosts=[],
        affected_ips=[],
        affected_assets=[],
        connector_type=None,
        source_event_ids=[],
    )


class _Result:
    def __init__(self, row=None) -> None:
        self._row = row

    def fetchone(self):
        return self._row

    def scalar_one_or_none(self):
        return self._row


class _Session:
    """Answers the case and seed lookups; fails the candidate sweep."""

    def __init__(self, *, seed_present: bool = True, fail_on_seed: bool = False) -> None:
        self._seed_present = seed_present
        self._fail_on_seed = fail_on_seed
        self._alert_selects = 0

    async def execute(self, stmt, *a, **k):
        sql = str(stmt)
        if "aisoc_cases" in sql:
            return _Result(SimpleNamespace(id=CASE_ID, tenant_id=TENANT, alert_ids=[SEED_ID]))
        if "?|" in sql:  # the entity-overlap probe == the candidate sweep
            raise OperationalError("SELECT ...", {}, Exception("connection lost"))
        # 1st alert select is the route resolving the case's seed; the 2nd is
        # the loader's ``load_seed``.
        self._alert_selects += 1
        if self._alert_selects >= 2 and self._fail_on_seed:
            raise OperationalError("SELECT ...", {}, Exception("connection lost"))
        if self._alert_selects >= 2 and not self._seed_present:
            return _Result(None)  # deleted between resolution and load
        return _Result(_seed_row())

    async def commit(self) -> None:
        return None


def _client(session: _Session) -> AsyncClient:
    app = FastAPI()
    app.include_router(endpoint.router, prefix="/v1")
    app.dependency_overrides[deps.get_db] = lambda: session
    app.dependency_overrides[deps.get_current_user] = lambda: SimpleNamespace(tenant_id=TENANT, id=uuid.uuid4())
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


@pytest.mark.asyncio
async def test_candidate_sweep_failure_is_503_not_an_empty_chain() -> None:
    async with _client(_Session()) as c:
        r = await c.get(f"/v1/cases/{CASE_ID}/attack-chain")
    assert r.status_code == 503, r.text
    assert r.json()["detail"] == "attack_chain_unavailable"


@pytest.mark.asyncio
async def test_seed_load_failure_is_503_too() -> None:
    async with _client(_Session(fail_on_seed=True)) as c:
        r = await c.get(f"/v1/cases/{CASE_ID}/attack-chain")
    assert r.status_code == 503, r.text


@pytest.mark.asyncio
async def test_missing_seed_alert_is_still_404() -> None:
    async with _client(_Session(seed_present=False)) as c:
        r = await c.get(f"/v1/cases/{CASE_ID}/attack-chain")
    assert r.status_code == 404
