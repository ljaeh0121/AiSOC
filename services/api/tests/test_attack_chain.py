"""Tests for the attack-chain timeline ranker (T3.3).

Anchored to the v8.0 acceptance fixture: a 5-alert LockBit-shaped chain
mirroring the seeded ``INC-RT-001`` showcase incident:

    1. Phishing email delivery        → host 'WIN-USR-101' / user 'jdoe'
    2. Credential harvesting          → user 'jdoe'
    3. Cloud auth anomaly             → user 'jdoe' (federated)
    4. S3 enumeration                 → asset 's3://acme-research'
    5. Data exfiltration              → asset 's3://acme-research'

The seed is alert #1 (phishing). Alerts 2–5 share entities transitively
(jdoe links 1↔2↔3, then alert 3 introduces the S3 asset, which links
4↔5 at depth 2). The test asserts:

  * the chain length is 4 (every non-seed alert reachable within
    depth ≤ 3 and the 24h window),
  * alert #2 (depth-1, t+5m, jdoe) ranks above alert #5 (depth-2,
    t+8h, asset only),
  * the ``shared_entities`` provenance for the depth-1 candidates is
    populated with the user identity,
  * ``chain_signature`` is deterministic and 32-char hex,
  * ``confidence`` is in (0, 1].
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta

import pytest
from app.services.attack_chain import (
    DEFAULT_WINDOW,
    CandidateAlert,
    _chain_signature,
    _distance_score,
    _risk_overlap,
    _temporal_score,
    compute_attack_chain,
    score_candidate,
)

# ---------------------------------------------------------------------------
# Fixture: the 5-alert LockBit chain
# ---------------------------------------------------------------------------

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000777")
SEED_ID = uuid.uuid4()
A2_ID = uuid.uuid4()
A3_ID = uuid.uuid4()
A4_ID = uuid.uuid4()
A5_ID = uuid.uuid4()

T0 = datetime(2026, 5, 14, 8, 0, 0)


def _build_lockbit_chain() -> list[CandidateAlert]:
    """5-alert fixture mirroring INC-RT-001."""
    return [
        CandidateAlert(
            id=SEED_ID,
            tenant_id=TENANT,
            title="Phishing email with malicious attachment delivered",
            severity="medium",
            event_time=T0,
            mitre_techniques=("T1566.001", "T1204.002"),
            affected_users=("jdoe@acme.test",),
            affected_hosts=("WIN-USR-101",),
            affected_ips=(),
            affected_assets=(),
            connector_type="email_security",
            source_event_ids=("evt-phish-001",),
        ),
        CandidateAlert(
            id=A2_ID,
            tenant_id=TENANT,
            title="Credential harvesting via fake O365 login portal",
            severity="high",
            event_time=T0 + timedelta(minutes=5),
            mitre_techniques=("T1566.002", "T1078"),
            affected_users=("jdoe@acme.test",),
            affected_hosts=("WIN-USR-101",),
            affected_ips=(),
            affected_assets=(),
            connector_type="email_security",
            source_event_ids=("evt-cred-002",),
        ),
        CandidateAlert(
            id=A3_ID,
            tenant_id=TENANT,
            title="Cloud auth anomaly: impossible-travel sign-in to AWS console",
            severity="high",
            event_time=T0 + timedelta(hours=2),
            mitre_techniques=("T1078.004",),
            affected_users=("jdoe@acme.test",),
            affected_hosts=(),
            affected_ips=("203.0.113.42",),
            affected_assets=("s3://acme-research",),
            connector_type="aws_cloudtrail",
            source_event_ids=("evt-auth-003",),
        ),
        CandidateAlert(
            id=A4_ID,
            tenant_id=TENANT,
            title="S3 bucket enumeration from unusual ASN",
            severity="medium",
            event_time=T0 + timedelta(hours=6),
            mitre_techniques=("T1580", "T1530"),
            affected_users=(),
            affected_hosts=(),
            affected_ips=("203.0.113.42",),
            affected_assets=("s3://acme-research",),
            connector_type="aws_cloudtrail",
            source_event_ids=("evt-enum-004",),
        ),
        CandidateAlert(
            id=A5_ID,
            tenant_id=TENANT,
            title="Large outbound data egress from S3 to unknown destination",
            severity="critical",
            event_time=T0 + timedelta(hours=8),
            mitre_techniques=("T1530", "T1567.002"),
            affected_users=(),
            affected_hosts=(),
            affected_ips=(),
            affected_assets=("s3://acme-research",),
            connector_type="aws_cloudtrail",
            source_event_ids=("evt-exfil-005",),
        ),
    ]


class _InMemoryLoader:
    """Test loader that walks the fixture as if it were Postgres."""

    def __init__(self, alerts: list[CandidateAlert]) -> None:
        self._by_id = {a.id: a for a in alerts}
        self._all = alerts

    async def load_seed(self, alert_id: uuid.UUID, tenant_id: uuid.UUID) -> CandidateAlert | None:
        row = self._by_id.get(alert_id)
        if row is None or row.tenant_id != tenant_id:
            return None
        return row

    async def load_candidates_for_entities(
        self,
        tenant_id: uuid.UUID,
        entities: Iterable[tuple[str, str]],
        start: datetime,
        end: datetime,
        exclude_ids: set[uuid.UUID],
        *,
        limit: int | None = None,
        anchor: datetime | None = None,
    ) -> list[CandidateAlert]:
        ents = set(entities)
        out: list[CandidateAlert] = []
        for row in self._all:
            if row.tenant_id != tenant_id:
                continue
            if row.id in exclude_ids:
                continue
            if not (start <= row.event_time <= end):
                continue
            if row.entities() & ents:
                out.append(row)
        if anchor is not None:
            out.sort(key=lambda r: (abs((r.event_time - anchor).total_seconds()), str(r.id)))
        # Contract: at most ``limit`` + 1 rows, the extra one only signals overflow.
        return out[: limit + 1] if limit is not None else out


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_distance_score_inverse_of_distance() -> None:
    assert _distance_score(1) == 1.0
    assert _distance_score(2) == 0.5
    assert pytest.approx(_distance_score(3), rel=1e-3) == 0.3333333


def test_distance_score_zero_distance_is_zero() -> None:
    assert _distance_score(0) == 0.0


def test_temporal_score_at_seed_is_one() -> None:
    score, dt = _temporal_score(T0, T0, timedelta(hours=24))
    assert score == 1.0
    assert dt == 0.0


def test_temporal_score_at_window_edge_is_zero() -> None:
    score, dt = _temporal_score(T0, T0 + timedelta(hours=24), timedelta(hours=24))
    assert score == 0.0
    assert dt == 86400.0


def test_temporal_score_clamps_below_zero() -> None:
    """Beyond the window, the score saturates at 0 — never goes negative."""
    score, _ = _temporal_score(T0, T0 + timedelta(hours=72), timedelta(hours=24))
    assert score == 0.0


def test_risk_overlap_identical_techniques_high_severity() -> None:
    a = _build_lockbit_chain()[2]  # cloud auth anomaly, high
    same = a
    assert _risk_overlap(a, same) == pytest.approx((1.0 + 0.8) / 2.0, rel=1e-3)


def test_risk_overlap_disjoint_techniques_low_severity() -> None:
    a = CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        title="x",
        severity="info",
        event_time=T0,
        mitre_techniques=("T0001",),
    )
    b = CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        title="y",
        severity="info",
        event_time=T0,
        mitre_techniques=("T9999",),
    )
    # Jaccard = 0, severity weight = min(1,1)/5 = 0.2 → mean = 0.1
    assert _risk_overlap(a, b) == pytest.approx(0.1, rel=1e-3)


def test_risk_overlap_no_techniques_anywhere() -> None:
    a = CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        title="x",
        severity="medium",
        event_time=T0,
    )
    b = CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        title="y",
        severity="medium",
        event_time=T0,
    )
    # Jaccard term = 0.0 (clean — neither has a technique tag),
    # severity term = 3/5 = 0.6 → mean = 0.3
    assert _risk_overlap(a, b) == pytest.approx(0.3, rel=1e-3)


# ---------------------------------------------------------------------------
# End-to-end ranking
# ---------------------------------------------------------------------------


def test_lockbit_chain_returns_four_links() -> None:
    """Seed is alert #1; alerts 2-5 are reachable inside the 24h window."""
    alerts = _build_lockbit_chain()
    loader = _InMemoryLoader(alerts)
    chain = asyncio.run(
        compute_attack_chain(
            seed_alert_id=SEED_ID,
            tenant_id=TENANT,
            loader=loader,
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
        )
    )
    assert chain is not None
    assert len(chain.chain) == 4
    assert {link.alert_id for link in chain.chain} == {A2_ID, A3_ID, A4_ID, A5_ID}


def test_lockbit_chain_reads_in_attack_stage_order_not_score_order() -> None:
    """The timeline is ordered by ATT&CK stage then time, not by score:
    credential harvest (initial access) -> cloud auth -> S3 enumeration
    (discovery) -> exfil (collection/exfiltration)."""
    alerts = _build_lockbit_chain()
    loader = _InMemoryLoader(alerts)
    chain = asyncio.run(
        compute_attack_chain(
            seed_alert_id=SEED_ID,
            tenant_id=TENANT,
            loader=loader,
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
        )
    )
    assert chain is not None
    ordering = [link.alert_id for link in chain.chain]
    assert ordering == [A2_ID, A3_ID, A4_ID, A5_ID]


def test_lockbit_chain_provenance_records_shared_user() -> None:
    """Depth-1 candidates that share the user identity surface that
    user in ``shared_entities``."""
    alerts = _build_lockbit_chain()
    loader = _InMemoryLoader(alerts)
    chain = asyncio.run(
        compute_attack_chain(
            seed_alert_id=SEED_ID,
            tenant_id=TENANT,
            loader=loader,
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
        )
    )
    assert chain is not None
    by_id = {link.alert_id: link for link in chain.chain}
    for cand_id in (A2_ID, A3_ID):
        ents = {(e["kind"], e["value"]) for e in by_id[cand_id].shared_entities}
        assert ("Identity", "jdoe@acme.test") in ents


def test_lockbit_chain_signature_is_deterministic_hex() -> None:
    """Two runs of the same seed + ordering produce the same signature.

    Important — the migration relies on this for upsert dedup.
    """
    alerts = _build_lockbit_chain()
    loader = _InMemoryLoader(alerts)
    runs = [
        asyncio.run(
            compute_attack_chain(
                seed_alert_id=SEED_ID,
                tenant_id=TENANT,
                loader=loader,
                window=DEFAULT_WINDOW,
                window_label="24h",
                now=T0,
            )
        )
        for _ in range(3)
    ]
    sigs = {r.chain_signature for r in runs if r is not None}
    assert len(sigs) == 1
    sig = next(iter(sigs))
    assert re.fullmatch(r"[0-9a-f]{32}", sig), sig


def test_lockbit_chain_confidence_is_in_unit_interval() -> None:
    alerts = _build_lockbit_chain()
    loader = _InMemoryLoader(alerts)
    chain = asyncio.run(
        compute_attack_chain(
            seed_alert_id=SEED_ID,
            tenant_id=TENANT,
            loader=loader,
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
        )
    )
    assert chain is not None
    assert 0.0 < chain.confidence <= 1.0


def test_lockbit_chain_entity_graph_includes_seed_and_assets() -> None:
    alerts = _build_lockbit_chain()
    loader = _InMemoryLoader(alerts)
    chain = asyncio.run(
        compute_attack_chain(
            seed_alert_id=SEED_ID,
            tenant_id=TENANT,
            loader=loader,
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
        )
    )
    assert chain is not None
    nodes = chain.entity_graph["nodes"]
    node_ids = {n["id"] for n in nodes}
    # Seed alert + the user it touches must be present.
    assert f"alert:{SEED_ID}" in node_ids
    assert "identity:jdoe@acme.test" in node_ids


def test_compute_returns_none_for_unknown_seed() -> None:
    loader = _InMemoryLoader(_build_lockbit_chain())
    chain = asyncio.run(
        compute_attack_chain(
            seed_alert_id=uuid.uuid4(),
            tenant_id=TENANT,
            loader=loader,
            window=DEFAULT_WINDOW,
            window_label="24h",
        )
    )
    assert chain is None


def test_chain_signature_changes_when_chain_changes() -> None:
    """Adding an alert with a different id flips the signature."""
    chain_a = _build_lockbit_chain()
    loader_a = _InMemoryLoader(chain_a)
    out_a = asyncio.run(
        compute_attack_chain(
            seed_alert_id=SEED_ID,
            tenant_id=TENANT,
            loader=loader_a,
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
        )
    )
    extra = CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        title="Lateral movement: psexec from cred-harvest host",
        severity="high",
        event_time=T0 + timedelta(minutes=30),
        mitre_techniques=("T1021.002",),
        affected_users=("jdoe@acme.test",),
        affected_hosts=("WIN-USR-101",),
    )
    loader_b = _InMemoryLoader([*chain_a, extra])
    out_b = asyncio.run(
        compute_attack_chain(
            seed_alert_id=SEED_ID,
            tenant_id=TENANT,
            loader=loader_b,
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
        )
    )
    assert out_a is not None
    assert out_b is not None
    assert out_a.chain_signature != out_b.chain_signature


def test_score_candidate_returns_dt_seconds_alongside_score() -> None:
    seed, cand = _build_lockbit_chain()[0:2]
    score, dt = score_candidate(seed, cand, distance=1, window=DEFAULT_WINDOW)
    assert dt == 300.0  # 5 minutes
    assert 0.0 < score <= 1.0


def test_chain_signature_helper_pure_seed_only_chain() -> None:
    """``_chain_signature`` is a pure function — verify the hex shape
    when the chain is empty (seed-only)."""
    sig = _chain_signature(SEED_ID, [])
    assert re.fullmatch(r"[0-9a-f]{32}", sig), sig


# ---------------------------------------------------------------------------
# Plan 4 — attack-chain precision
# ---------------------------------------------------------------------------


class _RecordingLoader(_InMemoryLoader):
    """In-memory loader that records every entity set it is asked about."""

    def __init__(self, alerts: list[CandidateAlert]) -> None:
        super().__init__(alerts)
        self.calls: list[set[tuple[str, str]]] = []

    async def load_candidates_for_entities(self, tenant_id, entities, *a, **k) -> list[CandidateAlert]:
        ents = set(entities)
        self.calls.append(ents)
        return await super().load_candidates_for_entities(tenant_id, ents, *a, **k)


def _run(alerts: list[CandidateAlert], loader: _InMemoryLoader | None = None, **kw):
    return asyncio.run(
        compute_attack_chain(
            seed_alert_id=SEED_ID,
            tenant_id=TENANT,
            loader=loader or _InMemoryLoader(alerts),
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
            **kw,
        )
    )


def test_an_entity_is_never_queried_twice() -> None:
    """Production truncates each sweep with a LIMIT, so an alert that shares
    an already-queried entity can surface at depth 2. Its entities must not
    send that entity back into the frontier."""
    seed = CandidateAlert(id=SEED_ID, tenant_id=TENANT, title="seed", severity="high", event_time=T0, affected_users=("jdoe",))
    a = CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        title="a",
        severity="high",
        event_time=T0 + timedelta(minutes=1),
        affected_users=("jdoe",),
        affected_hosts=("hostx",),
    )
    b = CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        title="b",
        severity="high",
        event_time=T0 + timedelta(minutes=2),
        affected_users=("jdoe",),
    )
    c = CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        title="c",
        severity="high",
        event_time=T0 + timedelta(minutes=3),
        affected_users=("jdoe",),
        affected_hosts=("hostx",),
    )
    loader = _RecordingLoader([seed, a, b, c])
    assert _run([], loader, sweep_limit=1) is not None
    queried = [e for call in loader.calls for e in call]
    assert len(queried) == len(set(queried)), queried


def test_lockbit_multihop_alerts_still_found_at_depth_two() -> None:
    chain = _run(_build_lockbit_chain())
    assert chain is not None
    by_id = {link.alert_id: link for link in chain.chain}
    assert by_id[A4_ID].distance == 2
    assert by_id[A5_ID].distance == 2


def test_chain_reads_in_attack_stage_order() -> None:
    chain = _run(_build_lockbit_chain())
    assert chain is not None
    # initial access -> initial access -> discovery -> collection/exfil
    assert [link.alert_id for link in chain.chain] == [A2_ID, A3_ID, A4_ID, A5_ID]


def _unmapped_alert(severity: str = "high") -> CandidateAlert:
    return CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        title="Untagged anomaly on the same user",
        severity=severity,
        event_time=T0 + timedelta(minutes=1),  # earliest of all candidates
        affected_users=("jdoe@acme.test",),
    )


def test_unmapped_mitre_alerts_sorted_last() -> None:
    unmapped = _unmapped_alert()
    chain = _run([*_build_lockbit_chain(), unmapped])
    assert chain is not None
    assert chain.chain[-1].alert_id == unmapped.id
    assert len(chain.chain) == 5  # kept, not dropped


def test_unknown_technique_ids_count_as_unmapped() -> None:
    odd = CandidateAlert(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        title="Tagged with a technique we have no tactic for",
        severity="high",
        event_time=T0 + timedelta(minutes=1),
        mitre_techniques=("T9999",),
        affected_users=("jdoe@acme.test",),
    )
    chain = _run([*_build_lockbit_chain(), odd])
    assert chain is not None
    assert chain.chain[-1].alert_id == odd.id


def test_truncation_keeps_highest_scoring_links_not_earliest_stage() -> None:
    """Stage order is a presentation order; the cap must still keep the best."""
    unmapped = _unmapped_alert()
    chain = _run([*_build_lockbit_chain(), unmapped], max_length=2)
    assert chain is not None
    assert len(chain.chain) == 2
    assert unmapped.id in {link.alert_id for link in chain.chain}  # highest score overall


def test_confidence_does_not_count_the_seed() -> None:
    """The seed is not a link in the chain; its implicit full strength must
    not be averaged in."""
    seed = _seed(affected_users=("jdoe@acme.test",))
    only = _mk(1, 5, affected_users=("jdoe@acme.test",))
    chain = _run([seed, only])
    assert chain is not None and len(chain.chain) == 1
    assert chain.confidence == pytest.approx(chain.chain[0].strength)
    assert chain.confidence < 1.0


def test_depth2_link_has_via_alert() -> None:
    chain = _run(_build_lockbit_chain())
    assert chain is not None
    by_id = {link.alert_id: link for link in chain.chain}
    assert by_id[A2_ID].via_alert_id is None
    assert by_id[A3_ID].via_alert_id is None
    assert by_id[A4_ID].via_alert_id == A3_ID
    assert by_id[A5_ID].via_alert_id == A3_ID
    # shared entities are with the intermediary, not the candidate's own set
    assert {(e["kind"], e["value"]) for e in by_id[A4_ID].shared_entities} == {
        ("Endpoint", "203.0.113.42"),
        ("Resource", "s3://acme-research"),
    }
    assert {(e["kind"], e["value"]) for e in by_id[A5_ID].shared_entities} == {("Resource", "s3://acme-research")}
    assert "via_alert_id" in by_id[A4_ID].to_dict()
    assert by_id[A4_ID].to_dict()["via_alert_id"] == str(A3_ID)


def test_entity_graph_links_intermediary_alert_to_pivot_entities() -> None:
    chain = _run(_build_lockbit_chain())
    assert chain is not None
    edges = {(e["source"], e["target"]) for e in chain.entity_graph["edges"]}
    assert (f"alert:{A3_ID}", "endpoint:203.0.113.42") in edges


def test_loader_exception_propagates() -> None:
    class _Broken(_InMemoryLoader):
        async def load_candidates_for_entities(self, *a, **k):
            raise RuntimeError("db down")

    with pytest.raises(RuntimeError, match="db down"):
        _run([], _Broken(_build_lockbit_chain()))


# ---------------------------------------------------------------------------
# Truncation is reported, never silent
# ---------------------------------------------------------------------------


def _same_user_alerts(n: int) -> list[CandidateAlert]:
    return [
        CandidateAlert(
            id=uuid.UUID(int=i + 1),
            tenant_id=TENANT,
            title=f"a{i}",
            severity="high",
            event_time=T0 + timedelta(minutes=10 * (i + 1)),
            affected_users=("jdoe@acme.test",),
        )
        for i in range(n)
    ]


def _seed_for(alerts: list[CandidateAlert]) -> CandidateAlert:
    return CandidateAlert(id=SEED_ID, tenant_id=TENANT, title="seed", severity="high", event_time=T0, affected_users=("jdoe@acme.test",))


def test_a_complete_chain_is_not_marked_truncated() -> None:
    chain = _run(_build_lockbit_chain())
    assert chain is not None
    assert chain.truncated is False
    assert chain.truncated_reasons == []
    assert chain.to_dict()["truncated"] is False


def test_a_sweep_that_hits_its_limit_says_so_and_keeps_the_closest_alerts() -> None:
    others = _same_user_alerts(5)
    chain = _run([_seed_for(others), *others], sweep_limit=3)
    assert chain is not None
    assert chain.truncated is True
    assert chain.truncated_reasons == ["sweep_limit"]
    # the three closest to the seed in time survive, not an arbitrary three
    assert {link.alert_id for link in chain.chain} == {o.id for o in others[:3]}
    assert chain.to_dict()["truncated_reasons"] == ["sweep_limit"]


def test_a_sweep_that_exactly_fits_its_limit_is_not_truncated() -> None:
    others = _same_user_alerts(3)
    chain = _run([_seed_for(others), *others], sweep_limit=3)
    assert chain is not None
    assert chain.truncated is False
    assert len(chain.chain) == 3


def test_which_alerts_survive_a_truncated_sweep_is_deterministic() -> None:
    tied = [
        CandidateAlert(
            id=uuid.UUID(int=100 - i),
            tenant_id=TENANT,
            title=f"t{i}",
            severity="high",
            event_time=T0 + timedelta(minutes=5),  # identical distance from the seed
            affected_users=("jdoe@acme.test",),
        )
        for i in range(4)
    ]
    runs = [_run([_seed_for(tied), *reversed(tied)] if k else [_seed_for(tied), *tied], sweep_limit=2) for k in (0, 1)]
    assert runs[0] is not None and runs[1] is not None
    assert runs[0].chain_signature == runs[1].chain_signature


def test_the_length_cap_is_reported_too() -> None:
    chain = _run(_build_lockbit_chain(), max_length=2)
    assert chain is not None
    assert chain.truncated is True
    assert chain.truncated_reasons == ["max_length"]


def test_both_reasons_can_apply_at_once() -> None:
    others = _same_user_alerts(6)
    chain = _run([_seed_for(others), *others], sweep_limit=4, max_length=2)
    assert chain is not None
    assert chain.truncated_reasons == ["sweep_limit", "max_length"]


# ---------------------------------------------------------------------------
# P1 — entity hygiene, evidence strength, stage fields
# ---------------------------------------------------------------------------

from app.services.attack_chain import (  # noqa: E402
    HUB_FANOUT,
    is_generic_account,
    normalize_entity,
)


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [
        ("Identity", "  JDoe@Acme.Test ", "jdoe@acme.test"),
        ("Identity", "CORP\\JDoe", "corp\\jdoe"),
        ("Endpoint", "WIN-USR-101.", "win-usr-101"),
        ("Endpoint", "::ffff:203.0.113.42", "203.0.113.42"),
        ("Endpoint", "2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("Endpoint", "[2001:db8::1]", "2001:db8::1"),
        ("Resource", "S3://Acme-Research/", "s3://acme-research"),
    ],
)
def test_entity_values_are_normalised(kind: str, raw: str, expected: str) -> None:
    assert normalize_entity(kind, raw) == expected


@pytest.mark.parametrize(
    ("kind", "raw"),
    [
        ("Identity", ""),
        ("Identity", "   "),
        ("Identity", "-"),
        ("Identity", "N/A"),
        ("Identity", "Unknown"),
        ("Identity", None),
        ("Endpoint", "localhost"),
        ("Endpoint", "127.0.0.1"),
        ("Endpoint", "::1"),
        ("Endpoint", "0.0.0.0"),
        ("Endpoint", "169.254.10.5"),
        ("Endpoint", "224.0.0.251"),
        ("Endpoint", "255.255.255.255"),
    ],
)
def test_values_that_identify_nothing_are_not_entities(kind: str, raw: object) -> None:
    assert normalize_entity(kind, raw) is None


@pytest.mark.parametrize(
    ("value", "generic"),
    [
        ("SYSTEM", True),
        ("NT AUTHORITY\\SYSTEM", True),
        ("CORP\\Administrator", True),
        ("root", True),
        ("admin@acme.test", True),
        ("jdoe@acme.test", False),
        ("rootkit-analyst", False),
    ],
)
def test_shared_accounts_are_recognised_as_generic(value: str, generic: bool) -> None:
    assert is_generic_account(value) is generic


def _mk(n: int, minutes: int, **kw) -> CandidateAlert:
    return CandidateAlert(
        id=uuid.UUID(int=n),
        tenant_id=TENANT,
        title=f"alert {n}",
        severity=kw.pop("severity", "high"),
        event_time=T0 + timedelta(minutes=minutes),
        **kw,
    )


def _seed(**kw) -> CandidateAlert:
    return CandidateAlert(id=SEED_ID, tenant_id=TENANT, title="seed", severity="high", event_time=T0, **kw)


def test_alerts_that_differ_only_in_case_are_linked() -> None:
    seed = _seed(affected_users=("JDoe@Acme.Test",))
    other = _mk(1, 5, affected_users=("jdoe@acme.test",))
    chain = _run([seed, other])
    assert chain is not None
    assert [link.alert_id for link in chain.chain] == [other.id]
    assert chain.chain[0].shared_entities == [{"kind": "Identity", "value": "jdoe@acme.test"}]


def test_a_generic_account_is_never_a_pivot() -> None:
    seed = _seed(affected_users=("NT AUTHORITY\\SYSTEM",), affected_hosts=("h1",))
    unrelated = _mk(1, 5, affected_users=("NT AUTHORITY\\SYSTEM",), affected_hosts=("h2",))
    related = _mk(2, 6, affected_hosts=("h1",))
    loader = _RecordingLoader([seed, unrelated, related])
    chain = _run([], loader)
    assert chain is not None
    assert [link.alert_id for link in chain.chain] == [related.id]
    assert ("Identity", "nt authority\\system") not in {e for call in loader.calls for e in call}
    assert chain.suppressed_pivots == [
        {"kind": "Identity", "value": "nt authority\\system", "reason": "generic_account", "alert_count": None}
    ]


def test_an_entity_reached_through_a_hub_is_not_expanded() -> None:
    """A shared egress IP that dozens of unrelated alerts touch must not drag
    them all into the chain just because one related alert also touched it."""
    seed = _seed(affected_hosts=("h1",))
    bridge = _mk(1, 5, affected_hosts=("h1",), affected_ips=("198.51.100.9",))
    noise = [_mk(100 + i, 10 + i, affected_ips=("198.51.100.9",)) for i in range(HUB_FANOUT + 5)]
    chain = _run([seed, bridge, *noise])
    assert chain is not None
    assert [link.alert_id for link in chain.chain] == [bridge.id]
    assert chain.suppressed_pivots == [
        {"kind": "Endpoint", "value": "198.51.100.9", "reason": "high_fanout", "alert_count": HUB_FANOUT + 5}
    ]


def test_a_busy_entity_on_the_seed_itself_is_still_followed() -> None:
    """The seed's own entities are the case's anchor: a compromised account
    legitimately has many alerts. Dense is weak evidence there, not excluded."""
    seed = _seed(affected_users=("jdoe@acme.test",))
    many = [_mk(i + 1, i + 1, affected_users=("jdoe@acme.test",)) for i in range(HUB_FANOUT + 5)]
    chain = _run([seed, *many])
    assert chain is not None
    assert len(chain.chain) == HUB_FANOUT + 5
    assert chain.suppressed_pivots == []


def test_link_strength_is_the_weight_of_what_was_shared() -> None:
    seed = _seed(affected_users=("jdoe@acme.test",), affected_hosts=("h1",), affected_ips=("203.0.113.5",))
    by_user = _mk(1, 5, affected_users=("jdoe@acme.test",))
    by_ip = _mk(2, 6, affected_ips=("203.0.113.5",))
    by_both = _mk(3, 7, affected_users=("jdoe@acme.test",), affected_hosts=("h1",))
    chain = _run([seed, by_user, by_ip, by_both])
    assert chain is not None
    s = {link.alert_id: link.strength for link in chain.chain}
    assert s[by_ip.id] < s[by_user.id] < s[by_both.id] <= 1.0
    assert all(0.0 < v <= 1.0 for v in s.values())


def test_a_link_through_a_busy_entity_is_weaker_than_one_through_a_rare_entity() -> None:
    def strength_with(extra: int) -> float:
        seed = _seed(affected_users=("jdoe@acme.test",))
        peers = [_mk(i + 1, i + 1, affected_users=("jdoe@acme.test",)) for i in range(1 + extra)]
        chain = _run([seed, *peers])
        assert chain is not None
        return next(link.strength for link in chain.chain if link.alert_id == peers[0].id)

    assert strength_with(8) < strength_with(0)


def test_a_two_hop_link_is_no_stronger_than_the_hop_that_reached_it() -> None:
    chain = _run(_build_lockbit_chain())
    assert chain is not None
    by_id = {link.alert_id: link for link in chain.chain}
    for deep in (A4_ID, A5_ID):
        assert by_id[deep].strength < by_id[by_id[deep].via_alert_id].strength


def test_chain_confidence_is_the_mean_link_strength_not_the_best_link() -> None:
    chain = _run(_build_lockbit_chain())
    assert chain is not None
    assert chain.confidence == pytest.approx(sum(link.strength for link in chain.chain) / len(chain.chain))


def test_a_chain_padded_with_weak_links_is_less_confident() -> None:
    seed = _seed(affected_users=("jdoe@acme.test",), affected_hosts=("h1",))
    strong = _mk(1, 5, affected_users=("jdoe@acme.test",), affected_hosts=("h1",))
    lone = _run([seed, strong])
    # weak links: reached only through an address one other alert shares
    pad_bridge = _mk(2, 6, affected_hosts=("h1",), affected_ips=("203.0.113.77",))
    pad = [_mk(20 + i, 20 + i, affected_ips=("203.0.113.77",)) for i in range(5)]
    padded = _run([seed, strong, pad_bridge, *pad])
    assert lone is not None and padded is not None
    assert padded.confidence < lone.confidence


def test_an_empty_chain_has_zero_confidence() -> None:
    chain = _run([_seed(affected_users=("jdoe@acme.test",))])
    assert chain is not None
    assert chain.chain == []
    assert chain.confidence == 0.0


def test_links_carry_their_stage_and_tactic() -> None:
    unmapped = _unmapped_alert()
    chain = _run([*_build_lockbit_chain(), unmapped])
    assert chain is not None
    by_id = {link.alert_id: link for link in chain.chain}
    assert (by_id[A2_ID].stage, by_id[A2_ID].tactic) == (2, "initial-access")
    assert (by_id[A4_ID].stage, by_id[A4_ID].tactic) == (8, "discovery")
    assert (by_id[unmapped.id].stage, by_id[unmapped.id].tactic) == (None, None)
    d = by_id[A5_ID].to_dict()
    assert {"stage", "tactic", "strength", "out_of_sequence"} <= d.keys()


def test_a_chain_whose_stage_order_contradicts_time_is_marked() -> None:
    seed = _seed(affected_users=("jdoe@acme.test",), mitre_techniques=("T1566",))
    exfil_first = _mk(1, 10, affected_users=("jdoe@acme.test",), mitre_techniques=("T1567",))
    discovery_later = _mk(2, 60, affected_users=("jdoe@acme.test",), mitre_techniques=("T1083",))
    chain = _run([seed, exfil_first, discovery_later])
    assert chain is not None
    assert [link.alert_id for link in chain.chain] == [discovery_later.id, exfil_first.id]  # stage order
    flags = {link.alert_id: link.out_of_sequence for link in chain.chain}
    assert flags == {discovery_later.id: False, exfil_first.id: True}


def test_a_chain_that_reads_forward_in_time_is_not_marked() -> None:
    chain = _run(_build_lockbit_chain())
    assert chain is not None
    assert not any(link.out_of_sequence for link in chain.chain)


# ---------------------------------------------------------------------------
# Contract with the console
# ---------------------------------------------------------------------------

import dataclasses  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402

CONTRACT_FIXTURE = Path(__file__).parent / "fixtures" / "attack_chain_response.json"
CASE_ID = uuid.UUID(int=0xCA5E)


def _contract_payload() -> dict:
    """The exact body ``GET /cases/{id}/attack-chain`` returns for the LockBit
    scenario, on fixed ids so the file is byte-stable."""
    fixed = {a.id: uuid.UUID(int=0x1000 + i) for i, a in enumerate(_build_lockbit_chain())}
    alerts = [dataclasses.replace(a, id=fixed[a.id]) for a in _build_lockbit_chain()]
    chain = asyncio.run(
        compute_attack_chain(
            seed_alert_id=fixed[SEED_ID],
            tenant_id=TENANT,
            loader=_InMemoryLoader(alerts),
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
        )
    )
    assert chain is not None
    payload = chain.to_dict()
    payload.pop("generated_at")  # a clock reading; the console falls back when absent
    payload["case_id"] = str(CASE_ID)
    return json.loads(json.dumps(payload, sort_keys=True))


def test_response_body_matches_the_fixture_the_console_is_tested_against() -> None:
    """``apps/web`` feeds this same file through ``casesApi.getAttackChain``.
    If the response changes shape this fails until the file is regenerated
    (``ATTACK_CHAIN_UPDATE_FIXTURE=1``), which in turn fails the console's
    test unless its mapper learned the change."""
    payload = _contract_payload()
    if os.environ.get("ATTACK_CHAIN_UPDATE_FIXTURE"):
        CONTRACT_FIXTURE.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    assert json.loads(CONTRACT_FIXTURE.read_text()) == payload


# ---------------------------------------------------------------------------
# Labelled scenarios: recall and precision
# ---------------------------------------------------------------------------

from _attack_chain_scenarios import labelled_world  # noqa: E402


def _labelled_world(*, nat_hub: bool):
    return labelled_world(TENANT, T0, nat_hub=nat_hub)


def measure_scenarios(*, nat_hub: bool) -> dict[str, dict[str, float]]:
    scenarios, noise = _labelled_world(nat_hub=nat_hub)
    everything = [a for alerts in scenarios.values() for a in alerts] + noise
    owner = {a.id: label for label, alerts in scenarios.items() for a in alerts}
    out: dict[str, dict[str, float]] = {}
    for label, alerts in scenarios.items():
        seed, expected = alerts[0], {a.id for a in alerts[1:]}
        chain = asyncio.run(
            compute_attack_chain(
                seed_alert_id=seed.id,
                tenant_id=TENANT,
                loader=_InMemoryLoader(everything),
                window=DEFAULT_WINDOW,
                window_label="24h",
            )
        )
        assert chain is not None
        found = {link.alert_id for link in chain.chain}
        right = found & expected
        out[label] = {
            "recall": len(right) / len(expected),
            # an empty chain asserts nothing, so it cannot be wrong
            "precision": len(right) / len(found) if found else 1.0,
            "foreign": float(len({owner.get(i, "noise") for i in found - expected} - {label})),
        }
        print(f"[eval] {label}: recall {out[label]['recall']:.0%}, precision {out[label]['precision']:.0%} ({len(found)} links)")
    return out


@pytest.mark.parametrize("nat_hub", [False, True], ids=["fusion-noise", "nat-hub-noise"])
def test_the_labelled_scenarios_are_recovered_whole_and_clean(nat_hub: bool) -> None:
    """Every scenario's alerts are found from its first alert, and nothing
    from another scenario or the noise comes with them.

    Authored scenarios (see the fixture's provenance): a regression bar for
    the link rules, not a claim about accuracy on real incidents."""
    result = measure_scenarios(nat_hub=nat_hub)
    assert {k: v["recall"] for k, v in result.items()} == dict.fromkeys(result, 1.0)
    assert {k: v["precision"] for k, v in result.items()} == dict.fromkeys(result, 1.0)


# ---------------------------------------------------------------------------
# Strong links: sessions and resolved humans
# ---------------------------------------------------------------------------


def test_alerts_from_one_session_are_linked_with_nothing_else_in_common() -> None:
    seed = _seed(session_id="sess-1", session_key_kind="vendor_session")
    other = _mk(1, 5, session_id="sess-1", session_key_kind="vendor_session")
    chain = _run([seed, other])
    assert chain is not None
    assert [link.alert_id for link in chain.chain] == [other.id]
    assert chain.chain[0].shared_entities == [{"kind": "Session", "value": "sess-1"}]


def test_alerts_behind_the_same_resolved_human_are_linked() -> None:
    seed = _seed(originating_human="Alice@Example.com")
    other = _mk(1, 5, originating_human="alice@example.com")
    chain = _run([seed, other])
    assert chain is not None
    assert chain.chain[0].shared_entities == [{"kind": "Human", "value": "alice@example.com"}]


def test_a_session_we_derived_is_weaker_than_one_the_vendor_named() -> None:
    def strength(kind: str) -> float:
        seed = _seed(session_id="s", session_key_kind=kind)
        other = _mk(1, 5, session_id="s", session_key_kind=kind)
        chain = _run([seed, other])
        assert chain is not None
        return chain.chain[0].strength

    assert strength("derived") < strength("vendor_session")


def test_a_session_outweighs_a_string_match() -> None:
    from app.services.attack_chain import _entity_weight

    session, human = _entity_weight("Session", "s"), _entity_weight("Human", "h")
    user, host = _entity_weight("Identity", "jdoe"), _entity_weight("Endpoint", "h1")
    address = _entity_weight("Endpoint", "203.0.113.5")
    assert session > human > user
    assert user == host
    assert host > address
    assert _entity_weight("DerivedSession", "s") < human  # we made that grouping ourselves
    assert _entity_weight("Identity", "system") < address  # a shared account says almost nothing


def test_a_weak_string_match_does_not_join_an_alert_anchored_on_a_session() -> None:
    """The story grouper's rule, found there by measurement: once an alert has
    an authenticated context behind it, a host or address string shared with
    some other alert is not allowed to pull that alert's neighbours in."""
    seed = _seed(session_id="s", affected_hosts=("h1",))
    same_session = _mk(1, 5, session_id="s")
    just_the_host = _mk(2, 6, affected_hosts=("h1",))
    chain = _run([seed, same_session, just_the_host])
    assert chain is not None
    assert [link.alert_id for link in chain.chain] == [same_session.id]
    assert chain.weak_links_refused == 1
    assert chain.to_dict()["weak_links_refused"] == 1


def test_a_weak_match_is_fine_when_the_seed_has_no_strong_context() -> None:
    seed = _seed(affected_hosts=("h1",))
    other = _mk(1, 5, affected_hosts=("h1",))
    chain = _run([seed, other])
    assert chain is not None
    assert [link.alert_id for link in chain.chain] == [other.id]
    assert chain.weak_links_refused == 0


def test_a_weak_match_that_also_shares_the_session_is_kept() -> None:
    seed = _seed(session_id="s", affected_hosts=("h1",))
    other = _mk(1, 5, session_id="s", affected_hosts=("h1",))
    chain = _run([seed, other])
    assert chain is not None
    assert [link.alert_id for link in chain.chain] == [other.id]
    assert chain.weak_links_refused == 0


def test_a_shared_address_cannot_weld_a_noise_alert_onto_a_session_anchored_hop() -> None:
    seed = _seed(session_id="s")
    bridge = _mk(1, 5, session_id="s", affected_ips=("203.0.113.5",))
    noise = _mk(2, 6, affected_ips=("203.0.113.5",))
    chain = _run([seed, bridge, noise])
    assert chain is not None
    assert [link.alert_id for link in chain.chain] == [bridge.id]
    assert chain.weak_links_refused == 1


def test_an_alert_refused_on_one_route_is_found_by_another() -> None:
    seed = _seed(session_id="s", affected_hosts=("h1",))
    bridge = _mk(1, 5, session_id="s", originating_human="alice@example.com")
    # Weak to the seed (a host), but shares the resolved human with the bridge.
    reached = _mk(2, 6, affected_hosts=("h1",), originating_human="alice@example.com")
    chain = _run([seed, bridge, reached])
    assert chain is not None
    by_id = {link.alert_id: link for link in chain.chain}
    assert reached.id in by_id
    assert by_id[reached.id].via_alert_id == bridge.id
    assert chain.weak_links_refused == 0  # refused on one route, found on another: not "refused"


@pytest.mark.parametrize(
    ("tactics", "techniques", "stage", "tactic"),
    [
        (("exfiltration",), (), 12, "exfiltration"),
        (("Initial Access",), (), 2, "initial-access"),
        (("privilege_escalation",), (), 5, "privilege-escalation"),
        (("stealth",), (), 6, "defense-evasion"),
        (("collection", "exfiltration"), (), 10, "collection"),
        ((), ("T1567",), 12, "exfiltration"),
        (("discovery",), ("T1567",), 8, "discovery"),  # the earliest of both sources
        (("not-a-tactic",), (), None, None),
    ],
)
def test_stage_comes_from_the_alerts_tactics_as_well_as_its_techniques(tactics, techniques, stage, tactic) -> None:
    seed = _seed(affected_users=("jdoe",))
    other = _mk(1, 5, affected_users=("jdoe",), mitre_tactics=tactics, mitre_techniques=techniques)
    chain = _run([seed, other])
    assert chain is not None
    assert (chain.chain[0].stage, chain.chain[0].tactic) == (stage, tactic)
