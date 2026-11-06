"""`affected_assets` through the real sink and real PostgreSQL.

The scripted-pool tests in ``test_alert_sink_issue_1244.py`` prove which value
is bound to which placeholder. They cannot prove the statement itself is
valid — that ``$33::jsonb`` lands in a column that exists, that the column list
and the SELECT list still line up, that a JSONB array round-trips — because a
scripted connection accepts any SQL. This inserts a real alert through
``AlertSink.persist`` and reads the row back.
"""

from __future__ import annotations

import json
import os
import socket
import uuid
from urllib.parse import urlparse

import asyncpg
import pytest
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.alert_sink import AlertSink, PersistOutcome

_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("ALERT_SINK_PROOF_REQUIRED", "").strip() not in ("", "0", "false")


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


def _plain_dsn() -> str:
    return _DSN.replace("postgresql+asyncpg://", "postgresql://")


async def _persist_and_read(raw_event: dict) -> object:
    tenant = uuid.uuid4()
    conn = await asyncpg.connect(_plain_dsn())
    sink = AlertSink(_plain_dsn())
    try:
        await conn.execute("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)", tenant, f"assets-{tenant.hex[:8]}")
        raw = RawAlert(
            tenant_id=tenant,
            source="CloudTrail",
            title="Bucket enumeration",
            severity=AlertSeverity.MEDIUM,
            hostname="ip-10-0-0-5",
            mitre_techniques=["T1580"],
            raw_event=raw_event,
        )
        raw.id = raw.deterministic_id()
        fused = FusedAlert(id=raw.id, tenant_id=tenant, fusion_decision=FusionDecision.NEW_ALERT, alert=raw)

        await sink.start()
        assert (await sink.persist(fused)).outcome is PersistOutcome.INSERTED

        value = await conn.fetchval("SELECT affected_assets FROM alerts WHERE id = $1", raw.id)
        return json.loads(value) if isinstance(value, str) else value
    finally:
        await sink.stop()
        await conn.execute("DELETE FROM alerts WHERE tenant_id = $1", tenant)
        await conn.execute("DELETE FROM tenants WHERE id = $1", tenant)
        await conn.close()


@pytest.mark.asyncio
async def test_a_real_alert_row_carries_its_resources() -> None:
    stored = await _persist_and_read(
        {"activity": {"resource": {"type": "s3_bucket", "id": "arn:aws:s3:::acme-research"}}, "Resources": [{"Id": "arn:aws:s3:::other"}]}
    )
    assert stored == ["arn:aws:s3:::acme-research", "arn:aws:s3:::other"]


@pytest.mark.asyncio
async def test_a_real_alert_with_no_resource_stores_an_empty_array() -> None:
    assert await _persist_and_read({}) == []
