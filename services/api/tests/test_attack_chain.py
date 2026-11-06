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


def test_confidence_excludes_seed() -> None:
    unmapped = _unmapped_alert()
    chain = _run([*_build_lockbit_chain(), unmapped])
    assert chain is not None
    best = max(link.score for link in chain.chain)
    assert chain.confidence == pytest.approx(best)
    assert chain.chain[0].score < best  # best candidate is not first in stage order
    assert chain.confidence < 1.0  # the seed's implicit 1.0 never leaks in


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
