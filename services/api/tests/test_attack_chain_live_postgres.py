"""The attack-chain sweep, through the real SQL against real PostgreSQL.

Every other attack-chain test walks an in-memory list, which answers any
question the algorithm asks of it. The production loader answers with a
``?|`` JSONB probe, a tenant filter, a time window, an exclusion list and a
``LIMIT``; none of that ran anywhere until this module. What is asserted is
that the chain computed from rows in ``alerts`` is the chain the algorithm
computes from the same alerts in memory, that another tenant's rows never
join it, that entity values are bound rather than interpolated, and that a
sweep which hits its row limit says so.

Connects as the schema owner, which bypasses row-level security, so the
tenant assertions here prove the loader's *own* ``tenant_id`` filter — the
second line of defence — and not the policy.
"""

from __future__ import annotations

import json
import os
import socket
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from app.services.attack_chain import (
    DEFAULT_WINDOW,
    CandidateAlert,
    PostgresAttackChainLoader,
    compute_attack_chain,
)
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
IP = "203.0.113.42"
BUCKET = "s3://acme-research"


def _alert(tenant: uuid.UUID, title: str, minutes: int, **kw) -> CandidateAlert:
    return CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=tenant,
        title=title,
        severity=kw.pop("severity", "high"),
        event_time=T0 + timedelta(minutes=minutes),
        **kw,
    )


async def _ensure_session(db, a: CandidateAlert) -> None:
    if not a.session_id:
        return
    await db.execute(
        text(
            "INSERT INTO sessions (id, tenant_id, session_key, key_kind, source, first_seen_at, last_seen_at)"
            " VALUES (CAST(:i AS uuid), :t, :k, :kk, 'test', :et, :et) ON CONFLICT DO NOTHING"
        ),
        {"i": a.session_id, "t": a.tenant_id, "k": a.session_id, "kk": a.session_key_kind or "vendor_session", "et": a.event_time},
    )


async def _insert(db, a: CandidateAlert) -> None:
    await _ensure_session(db, a)
    await db.execute(
        text(
            """
            INSERT INTO alerts (id, tenant_id, title, severity, status, event_time,
                                mitre_techniques, mitre_tactics, affected_users, affected_hosts,
                                affected_ips, affected_assets, connector_type, source_event_ids,
                                session_id, session_key_kind, originating_human)
            VALUES (:id, :t, :title, :sev, 'new', :et,
                    CAST(:m AS JSONB), CAST(:mt AS JSONB), CAST(:u AS JSONB), CAST(:h AS JSONB),
                    CAST(:i AS JSONB), CAST(:a AS JSONB), :c, CAST(:s AS JSONB),
                    CAST(:sid AS uuid), :skind, :human)
            """
        ),
        {
            "id": a.id,
            "t": a.tenant_id,
            "title": a.title,
            "sev": a.severity,
            "et": a.event_time,
            "m": json.dumps(list(a.mitre_techniques)),
            "mt": json.dumps(list(a.mitre_tactics)),
            "sid": a.session_id,
            "skind": a.session_key_kind,
            "human": a.originating_human,
            "u": json.dumps(list(a.affected_users)),
            "h": json.dumps(list(a.affected_hosts)),
            "i": json.dumps(list(a.affected_ips)),
            "a": json.dumps(list(a.affected_assets)),
            "c": a.connector_type,
            "s": json.dumps(list(a.source_event_ids)),
        },
    )


@pytest_asyncio.fixture
async def world():
    """Two scratch tenants. Yields ``(maker, tenant_a, tenant_b, insert)``."""
    engine = create_async_engine(_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    a, b = uuid.uuid4(), uuid.uuid4()
    async with maker() as db:
        for t in (a, b):
            await db.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
                {"i": t, "n": f"chain-{t.hex[:8]}", "s": f"chain-{t.hex[:8]}"},
            )
        await db.commit()

    async def insert(*alerts: CandidateAlert) -> None:
        async with maker() as db:
            for al in alerts:
                await _insert(db, al)
            await db.commit()

    yield maker, a, b, insert

    async with maker() as db:
        await db.execute(text("DELETE FROM alerts WHERE tenant_id IN (:a, :b)"), {"a": a, "b": b})
        await db.execute(text("DELETE FROM sessions WHERE tenant_id IN (:a, :b)"), {"a": a, "b": b})
        await db.execute(text("DELETE FROM tenants WHERE id IN (:a, :b)"), {"a": a, "b": b})
        await db.commit()
    await engine.dispose()


def _lockbit(tenant: uuid.UUID) -> list[CandidateAlert]:
    return [
        _alert(
            tenant, "phish", 0, severity="medium", mitre_techniques=("T1566.001",), affected_users=(USER,), affected_hosts=("WIN-USR-101",)
        ),
        _alert(tenant, "cred harvest", 5, mitre_techniques=("T1078",), affected_users=(USER,), affected_hosts=("WIN-USR-101",)),
        _alert(
            tenant,
            "cloud auth",
            120,
            mitre_techniques=("T1078.004",),
            affected_users=(USER,),
            affected_ips=(IP,),
            affected_assets=(BUCKET,),
        ),
        _alert(tenant, "s3 enum", 360, severity="medium", mitre_techniques=("T1580",), affected_ips=(IP,), affected_assets=(BUCKET,)),
        _alert(tenant, "exfil", 480, severity="critical", mitre_techniques=("T1567.002",), affected_assets=(BUCKET,)),
    ]


async def _chain(maker, tenant, seed_id, **kw):
    async with maker() as db:
        return await compute_attack_chain(
            seed_alert_id=seed_id,
            tenant_id=tenant,
            loader=PostgresAttackChainLoader(db),
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
            **kw,
        )


async def test_postgres_path_finds_the_multihop_chain_with_its_bridge(world) -> None:
    maker, a, _b, insert = world
    phish, harvest, cloud, enum, exfil = _lockbit(a)
    await insert(phish, harvest, cloud, enum, exfil)

    chain = await _chain(maker, a, phish.id)

    assert chain is not None
    by_id = {link.alert_id: link for link in chain.chain}
    assert set(by_id) == {harvest.id, cloud.id, enum.id, exfil.id}
    assert {k: v.distance for k, v in by_id.items()} == {harvest.id: 1, cloud.id: 1, enum.id: 2, exfil.id: 2}
    assert by_id[enum.id].via_alert_id == cloud.id
    assert by_id[exfil.id].via_alert_id == cloud.id
    assert [link.alert_id for link in chain.chain] == [harvest.id, cloud.id, enum.id, exfil.id]


async def test_another_tenants_alert_never_joins_the_chain(world) -> None:
    maker, a, b, insert = world
    phish, harvest, *_ = _lockbit(a)
    foreign = _alert(b, "same user, other tenant", 1, affected_users=(USER,))
    await insert(phish, harvest, foreign)

    chain = await _chain(maker, a, phish.id)

    assert chain is not None
    assert {link.alert_id for link in chain.chain} == {harvest.id}
    assert foreign.id not in {n["id"].removeprefix("alert:") for n in chain.entity_graph["nodes"]}
    # ...and a seed id that belongs to the other tenant is not loadable at all.
    assert await _chain(maker, a, foreign.id) is None


async def test_the_time_window_bounds_the_sweep(world) -> None:
    maker, a, _b, insert = world
    phish = _alert(a, "seed", 0, affected_users=(USER,))
    inside = _alert(a, "inside", 23 * 60, affected_users=(USER,))
    outside = _alert(a, "outside", 25 * 60, affected_users=(USER,))
    await insert(phish, inside, outside)

    chain = await _chain(maker, a, phish.id)

    assert chain is not None
    assert {link.alert_id for link in chain.chain} == {inside.id}


async def test_an_endpoint_entity_matches_hosts_and_ips_alike(world) -> None:
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, affected_hosts=("edge-01",), affected_ips=("198.51.100.7",))
    by_host = _alert(a, "by host", 1, affected_hosts=("edge-01",))
    by_ip = _alert(a, "by ip", 2, affected_ips=("198.51.100.7",))
    await insert(seed, by_host, by_ip)

    chain = await _chain(maker, a, seed.id)

    assert chain is not None
    assert {link.alert_id for link in chain.chain} == {by_host.id, by_ip.id}


@pytest.mark.parametrize("value", ["o'brien@acme.test", 'DOM\\"quoted"', "what?|is_this", "名前@例え.jp", "a" * 300])
async def test_entity_values_are_bound_not_interpolated(world, value: str) -> None:
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, affected_users=(value,))
    twin = _alert(a, "twin", 1, affected_users=(value,))
    await insert(seed, twin)

    chain = await _chain(maker, a, seed.id)

    assert chain is not None
    assert {link.alert_id for link in chain.chain} == {twin.id}


async def test_a_full_sweep_keeps_the_alerts_nearest_the_seed_and_says_it_truncated(world) -> None:
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, affected_users=(USER,))
    # Inserted farthest-first, so a LIMIT with no ORDER BY would return the
    # physically first rows — the ones furthest from the seed.
    others = [_alert(a, f"n{m}", m, affected_users=(USER,)) for m in (600, 500, 400, 300, 200, 100)]
    await insert(seed, *others)

    first = await _chain(maker, a, seed.id, sweep_limit=3)
    again = await _chain(maker, a, seed.id, sweep_limit=3)

    assert first is not None and again is not None
    nearest = {o.id for o in others if (o.event_time - T0) <= timedelta(minutes=300)}
    assert {link.alert_id for link in first.chain} == {o.id for o in others[3:]} == nearest
    assert first.truncated is True
    assert first.truncated_reasons == ["sweep_limit"]
    assert first.chain_signature == again.chain_signature


async def test_a_sweep_that_exactly_fits_its_limit_is_not_truncated_in_postgres(world) -> None:
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, affected_users=(USER,))
    others = [_alert(a, f"n{m}", m, affected_users=(USER,)) for m in (10, 20, 30)]
    await insert(seed, *others)

    chain = await _chain(maker, a, seed.id, sweep_limit=3)

    assert chain is not None
    assert chain.truncated is False
    assert len(chain.chain) == 3


async def test_stored_values_match_regardless_of_their_case(world) -> None:
    """Fusion writes ``affected_*`` verbatim, so two connectors name the same
    person ``JDoe@Acme.Test`` and ``jdoe@acme.test``."""
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, affected_users=("jdoe@acme.test",), affected_hosts=("win-usr-101",))
    other_user = _alert(a, "okta", 5, affected_users=("JDoe@Acme.Test",))
    other_host = _alert(a, "edr", 6, affected_hosts=("WIN-USR-101",))
    await insert(seed, other_user, other_host)

    chain = await _chain(maker, a, seed.id)

    assert chain is not None
    assert {link.alert_id for link in chain.chain} == {other_user.id, other_host.id}


async def test_a_row_with_a_malformed_entity_column_does_not_break_the_sweep(world) -> None:
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, affected_users=("jdoe@acme.test",))
    good = _alert(a, "good", 5, affected_users=("jdoe@acme.test",))
    await insert(seed, good)
    async with maker() as db:
        for bad in ('"just-a-string"', '{"not": "a list"}', "42", "null"):
            await db.execute(
                text(
                    "INSERT INTO alerts (id, tenant_id, title, severity, status, event_time, affected_users)"
                    " VALUES (:i, :t, 'malformed', 'low', 'new', :et, CAST(:v AS JSONB))"
                ),
                {"i": uuid.uuid4(), "t": a, "et": T0 + timedelta(minutes=1), "v": bad},
            )
        await db.commit()

    chain = await _chain(maker, a, seed.id)

    assert chain is not None
    assert {link.alert_id for link in chain.chain} == {good.id}


async def test_alerts_sharing_only_a_value_that_names_nothing_are_not_linked(world) -> None:
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, affected_hosts=("localhost",), affected_users=("-",), affected_ips=("127.0.0.1",))
    other = _alert(a, "other", 5, affected_hosts=("localhost",), affected_users=("-",), affected_ips=("127.0.0.1",))
    await insert(seed, other)

    chain = await _chain(maker, a, seed.id)

    assert chain is not None
    assert chain.chain == []


SESSION = "6f1b0e2a-9a3d-5c7e-8b4f-1d2c3e4f5a6b"
OTHER_SESSION = "7a2c1f3b-0b4e-4d8f-9c5a-2e3d4f5a6b7c"


async def test_alerts_of_one_session_are_linked_in_postgres(world) -> None:
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, session_id=SESSION, session_key_kind="vendor_session")
    same = _alert(a, "same session", 5, session_id=SESSION, session_key_kind="vendor_session")
    other = _alert(a, "another session", 6, session_id=OTHER_SESSION, session_key_kind="vendor_session")
    await insert(seed, same, other)

    chain = await _chain(maker, a, seed.id)

    assert chain is not None
    assert {link.alert_id for link in chain.chain} == {same.id}
    assert chain.chain[0].shared_entities == [{"kind": "Session", "value": SESSION}]


async def test_the_same_session_in_another_tenant_never_joins(world) -> None:
    maker, a, b, insert = world
    seed = _alert(a, "seed", 0, session_id=SESSION, session_key_kind="vendor_session")
    foreign = _alert(b, "other tenant", 5, session_id=SESSION, session_key_kind="vendor_session")
    await insert(seed, foreign)

    chain = await _chain(maker, a, seed.id)

    assert chain is not None
    assert chain.chain == []


async def test_a_resolved_human_matches_regardless_of_case_in_postgres(world) -> None:
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, originating_human="alice@example.com")
    other = _alert(a, "assumed role", 5, originating_human="Alice@Example.com")
    await insert(seed, other)

    chain = await _chain(maker, a, seed.id)

    assert chain is not None
    assert {link.alert_id for link in chain.chain} == {other.id}


async def test_a_weak_match_to_a_session_anchored_alert_is_refused_in_postgres(world) -> None:
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, session_id=SESSION, session_key_kind="vendor_session", affected_hosts=("h1",))
    same = _alert(a, "same session", 5, session_id=SESSION, session_key_kind="vendor_session")
    host_only = _alert(a, "host only", 6, affected_hosts=("h1",))
    await insert(seed, same, host_only)

    chain = await _chain(maker, a, seed.id)

    assert chain is not None
    assert {link.alert_id for link in chain.chain} == {same.id}
    assert chain.weak_links_refused == 1


async def test_a_stored_tactic_places_the_alert_on_the_kill_chain(world) -> None:
    maker, a, _b, insert = world
    seed = _alert(a, "seed", 0, affected_users=(USER,))
    other = _alert(a, "exfil", 5, affected_users=(USER,), mitre_tactics=("exfiltration",))
    await insert(seed, other)

    chain = await _chain(maker, a, seed.id)

    assert chain is not None
    assert (chain.chain[0].stage, chain.chain[0].tactic) == (12, "exfiltration")


@pytest.mark.parametrize("nat_hub", [False, True], ids=["fusion-noise", "nat-hub-noise"])
async def test_the_labelled_scenarios_are_recovered_through_the_real_sql(world, nat_hub: bool) -> None:
    """The same authored world the in-memory evaluation grades, but read back
    out of ``alerts`` by the production loader."""
    from _attack_chain_scenarios import labelled_world

    maker, a, _b, insert = world
    scenarios, noise = labelled_world(a, T0, nat_hub=nat_hub, session_of=lambda s: str(uuid.uuid5(uuid.NAMESPACE_URL, s)))
    await insert(*[x for alerts in scenarios.values() for x in alerts], *noise)

    for label, alerts in scenarios.items():
        chain = await _chain(maker, a, alerts[0].id)
        assert chain is not None
        found = {link.alert_id for link in chain.chain}
        assert found == {x.id for x in alerts[1:]}, f"{label}: {sorted(link.title for link in chain.chain)}"


async def test_a_derived_session_read_back_from_postgres_is_weaker_than_a_vendor_one(world) -> None:
    maker, a, _b, insert = world
    vendor = _alert(a, "vendor seed", 0, session_id=SESSION, session_key_kind="vendor_session")
    vendor_peer = _alert(a, "vendor peer", 5, session_id=SESSION, session_key_kind="vendor_session")
    derived = _alert(a, "derived seed", 0, session_id=OTHER_SESSION, session_key_kind="derived")
    derived_peer = _alert(a, "derived peer", 5, session_id=OTHER_SESSION, session_key_kind="derived")
    await insert(vendor, vendor_peer, derived, derived_peer)

    strong = await _chain(maker, a, vendor.id)
    weaker = await _chain(maker, a, derived.id)

    assert strong is not None and weaker is not None
    assert weaker.chain[0].shared_entities == [{"kind": "DerivedSession", "value": OTHER_SESSION}]
    assert weaker.chain[0].strength < strong.chain[0].strength
