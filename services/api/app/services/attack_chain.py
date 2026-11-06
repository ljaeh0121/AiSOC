"""Attack-chain timeline ranker (T3.3 — v8.0 parallel team plan).

Given a *seed* alert, walk the security graph within a configurable
window and return a ranked, deduplicated timeline of every alert that
shares ≥ 1 entity with the seed (transitively up to depth 3). The output
is the data behind ``GET /v1/cases/{id}/attack-chain``.

Design
------

The graph writer (T1.1, ``services/ingest/internal/graph``) materialises
``:Identity / :Resource / :Endpoint`` nodes into Neo4j. We *could* run a
2–3-hop Cypher walk per seed alert, but the alert table itself already
denormalises the entity touch-set into JSONB columns
(``affected_users``, ``affected_hosts``, ``affected_ips``,
``affected_assets``) — exactly the same set the graph writer derives
the edges from. That denormalised view gives us:

* a single Postgres round trip for the candidate sweep (no Neo4j
  dependency in the test path),
* tenant scoping for free via existing RLS,
* a deterministic algorithm we can unit-test without spinning up Neo4j.

We treat the alerts table as a bipartite (alert ↔ entity) graph, then:

  1. Pull the seed's entity touch-set (``E_seed``).
  2. Sweep all alerts in the window whose ``affected_*`` lists intersect
     ``E_seed`` — these are the depth-1 candidates.
  3. For each candidate, repeat the sweep with *all* of that candidate's
     entities (depth 2, 3) to expand the neighbourhood. A cumulative
     ``seen_entities`` set guarantees no entity is queried twice, so the
     traversal terminates regardless of how dense the graph is.
  4. Score each candidate:

         score = w1 * (1 / graph_distance)
               + w2 * (1 - |Δt| / window)
               + w3 * risk_overlap

     where ``risk_overlap`` is the Jaccard similarity of MITRE techniques
     plus shared severity weighting (an explicitly-derived quantity, not
     a black box — see ``_risk_overlap``). The score decides which links
     survive the length cap.
  5. Present the survivors in ATT&CK stage order (earliest tactic of any of
     the alert's techniques, then event time); alerts with no placeable
     technique go last. Compute a stable ``chain_signature`` and a
     ``confidence`` (the best candidate score — the seed is not a candidate).

The algorithm is intentionally pure Python over a small list of
dictionaries so:

  * the test fixture is a hand-built list of ``CandidateAlert`` objects,
    no DB,
  * the public ``compute_attack_chain`` accepts an injected
    ``loader: AttackChainLoader`` so callers (the API endpoint) plug in
    Postgres while the test plugs in an in-memory loader.

Provenance
~~~~~~~~~~

The output is more than a ranked list — for each pair we also report
``shared_entities`` (the *exact* identities/resources/endpoints that
tied the two alerts together) and, for depth ≥ 2, ``via_alert_id`` — the
alert that bridged it in, with ``shared_entities`` taken against *that*
alert rather than the seed. This is what the UI's "pivot" affordance
needs to take an analyst back to the original detection / connector
event.
"""

from __future__ import annotations

import hashlib
import logging
import math
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: Default analyst-facing window. The endpoint accepts an override but
#: clamps to the same {1h, 6h, 24h, 72h, 7d} allowlist enforced here.
DEFAULT_WINDOW: timedelta = timedelta(hours=24)

#: Max BFS depth into the alert↔entity bipartite graph. The CEO/eng
#: review explicitly settled on 3: depth-2 captures most "phishing →
#: cred theft → cloud auth anomaly" chains, depth-3 catches the long
#: tail (S3 enumeration → exfil) without exploding the candidate set.
MAX_DEPTH: int = 3

#: Hard cap on candidates returned. Defends against pathological cases
#: (e.g. an alert whose affected_user is a service account that touches
#: thousands of resources). The chain-construction tradeoff is "we'd
#: rather show the top 50 ordered correctly than the top 5,000 with no
#: visual signal".
MAX_CHAIN_LENGTH: int = 50

#: Score weights. These are tuned for "graph distance dominates,
#: temporal proximity is the next strongest signal, risk overlap is a
#: tie-breaker that prevents two unrelated incidents on the same host
#: from outranking the actual chain." Re-tuning these moves analyst
#: behaviour, so they're documented constants rather than env knobs.
W_DISTANCE: float = 0.55
W_TEMPORAL: float = 0.30
W_RISK: float = 0.15

assert math.isclose(W_DISTANCE + W_TEMPORAL + W_RISK, 1.0)

#: ATT&CK tactics in kill-chain order. The chain is *presented* in this order
#: (then by time); the score only decides which links survive the length cap.
MITRE_TACTIC_ORDER: dict[str, int] = {
    "reconnaissance": 0,
    "resource-development": 1,
    "initial-access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege-escalation": 5,
    "defense-evasion": 6,
    "credential-access": 7,
    "discovery": 8,
    "lateral-movement": 9,
    "collection": 10,
    "command-and-control": 11,
    "exfiltration": 12,
    "impact": 13,
}

#: Stage given to an alert with no technique we can place. Such alerts stay in
#: the chain (they are linked by entities, not by MITRE) and sort to the end.
UNMAPPED_STAGE: int = 999

#: Top-level technique id -> index into ``MITRE_TACTIC_ORDER``. A technique that
#: serves several tactics takes the earliest one. Generated from the ATT&CK
#: Enterprise v20.1 STIX bundle (non-revoked, non-deprecated techniques);
#: v20's "Stealth" and "Defense Impairment" tactics, which replaced Defense
#: Evasion, are both placed at the Defense Evasion position. Sub-techniques
#: resolve through their parent. The API service does not ship the MITRE corpus
#: (it lives in the agents service), so the table is carried here.
_TECHNIQUE_STAGE: dict[str, int] = {
    "T1001": 11,
    "T1003": 7,
    "T1005": 10,
    "T1006": 6,
    "T1007": 8,
    "T1008": 11,
    "T1010": 8,
    "T1011": 12,
    "T1012": 8,
    "T1014": 6,
    "T1016": 8,
    "T1018": 8,
    "T1020": 12,
    "T1021": 9,
    "T1025": 10,
    "T1027": 6,
    "T1029": 12,
    "T1030": 12,
    "T1033": 8,
    "T1036": 6,
    "T1037": 4,
    "T1039": 10,
    "T1040": 7,
    "T1041": 12,
    "T1046": 8,
    "T1047": 3,
    "T1048": 12,
    "T1049": 8,
    "T1052": 12,
    "T1053": 3,
    "T1055": 5,
    "T1056": 7,
    "T1057": 8,
    "T1059": 3,
    "T1068": 5,
    "T1069": 8,
    "T1070": 6,
    "T1071": 11,
    "T1072": 3,
    "T1074": 10,
    "T1078": 2,
    "T1080": 9,
    "T1082": 8,
    "T1083": 8,
    "T1087": 8,
    "T1090": 11,
    "T1091": 2,
    "T1092": 11,
    "T1095": 11,
    "T1098": 4,
    "T1102": 11,
    "T1104": 11,
    "T1105": 11,
    "T1106": 3,
    "T1110": 7,
    "T1111": 7,
    "T1112": 4,
    "T1113": 10,
    "T1114": 10,
    "T1115": 10,
    "T1119": 10,
    "T1120": 8,
    "T1123": 10,
    "T1124": 8,
    "T1125": 10,
    "T1127": 3,
    "T1129": 3,
    "T1132": 11,
    "T1133": 2,
    "T1134": 5,
    "T1135": 8,
    "T1136": 4,
    "T1137": 4,
    "T1140": 6,
    "T1176": 4,
    "T1185": 10,
    "T1187": 7,
    "T1189": 2,
    "T1190": 2,
    "T1195": 2,
    "T1197": 3,
    "T1199": 2,
    "T1200": 2,
    "T1201": 8,
    "T1202": 6,
    "T1203": 3,
    "T1204": 3,
    "T1205": 4,
    "T1207": 6,
    "T1210": 9,
    "T1211": 6,
    "T1212": 7,
    "T1213": 10,
    "T1216": 6,
    "T1217": 8,
    "T1218": 6,
    "T1219": 11,
    "T1220": 6,
    "T1221": 6,
    "T1222": 6,
    "T1480": 6,
    "T1482": 8,
    "T1484": 5,
    "T1485": 13,
    "T1486": 13,
    "T1489": 13,
    "T1490": 13,
    "T1491": 13,
    "T1495": 13,
    "T1496": 13,
    "T1497": 6,
    "T1498": 13,
    "T1499": 13,
    "T1505": 4,
    "T1518": 8,
    "T1525": 4,
    "T1526": 8,
    "T1528": 7,
    "T1529": 13,
    "T1530": 10,
    "T1531": 13,
    "T1534": 9,
    "T1535": 6,
    "T1537": 12,
    "T1538": 8,
    "T1539": 7,
    "T1542": 4,
    "T1543": 4,
    "T1546": 4,
    "T1547": 4,
    "T1548": 5,
    "T1550": 9,
    "T1552": 7,
    "T1553": 6,
    "T1554": 4,
    "T1555": 7,
    "T1556": 4,
    "T1557": 7,
    "T1558": 7,
    "T1559": 3,
    "T1560": 10,
    "T1561": 13,
    "T1563": 9,
    "T1564": 6,
    "T1565": 13,
    "T1566": 2,
    "T1567": 12,
    "T1568": 11,
    "T1569": 3,
    "T1570": 9,
    "T1571": 11,
    "T1572": 11,
    "T1573": 11,
    "T1574": 3,
    "T1578": 6,
    "T1580": 8,
    "T1583": 1,
    "T1584": 1,
    "T1585": 1,
    "T1586": 1,
    "T1587": 1,
    "T1588": 1,
    "T1589": 0,
    "T1590": 0,
    "T1591": 0,
    "T1592": 0,
    "T1593": 0,
    "T1594": 0,
    "T1595": 0,
    "T1596": 0,
    "T1597": 0,
    "T1598": 0,
    "T1599": 6,
    "T1600": 6,
    "T1601": 6,
    "T1602": 10,
    "T1606": 7,
    "T1608": 1,
    "T1609": 3,
    "T1610": 3,
    "T1611": 5,
    "T1612": 6,
    "T1613": 8,
    "T1614": 8,
    "T1615": 8,
    "T1619": 8,
    "T1620": 6,
    "T1621": 7,
    "T1622": 6,
    "T1647": 6,
    "T1648": 3,
    "T1649": 7,
    "T1650": 1,
    "T1651": 3,
    "T1652": 8,
    "T1653": 4,
    "T1654": 8,
    "T1657": 13,
    "T1659": 2,
    "T1665": 11,
    "T1666": 6,
    "T1667": 13,
    "T1668": 4,
    "T1669": 2,
    "T1671": 4,
    "T1673": 8,
    "T1674": 3,
    "T1675": 3,
    "T1677": 3,
    "T1678": 6,
    "T1679": 6,
    "T1680": 8,
    "T1681": 0,
    "T1682": 0,
    "T1683": 1,
    "T1684": 6,
    "T1685": 6,
    "T1686": 6,
    "T1687": 6,
    "T1688": 6,
    "T1689": 6,
    "T1690": 6,
    "T1696": 6,
    "T1697": 7,
    "T1698": 3,
    "T1699": 3,
    "T1700": 12,
}


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CandidateAlert:
    """Loader-shaped alert row.

    The loader interface returns these — *not* SQLAlchemy ORM objects —
    so tests can build them directly without a DB.
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    severity: str
    event_time: datetime
    mitre_techniques: tuple[str, ...] = ()
    affected_users: tuple[str, ...] = ()
    affected_hosts: tuple[str, ...] = ()
    affected_ips: tuple[str, ...] = ()
    affected_assets: tuple[str, ...] = ()
    connector_type: str | None = None
    source_event_ids: tuple[str, ...] = ()

    def entities(self) -> set[tuple[str, str]]:
        """Return the set of (kind, value) entity tuples for this alert."""
        out: set[tuple[str, str]] = set()
        for v in self.affected_users:
            if v:
                out.add(("Identity", str(v)))
        for v in self.affected_hosts:
            if v:
                out.add(("Endpoint", str(v)))
        for v in self.affected_ips:
            if v:
                out.add(("Endpoint", str(v)))
        for v in self.affected_assets:
            if v:
                out.add(("Resource", str(v)))
        return out


@dataclass
class ChainLink:
    """One node in the ranked attack-chain timeline."""

    alert_id: uuid.UUID
    title: str
    severity: str
    event_time: datetime
    score: float
    distance: int
    dt_seconds: float
    shared_entities: list[dict[str, str]]
    mitre_techniques: list[str]
    connector_type: str | None
    source_event_ids: list[str]
    #: The alert that connected this one to the chain. ``None`` for depth-1
    #: links (they connect to the seed directly); otherwise a depth-(n-1)
    #: alert, and ``shared_entities`` are the entities shared with *it*.
    via_alert_id: uuid.UUID | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": str(self.alert_id),
            "title": self.title,
            "severity": self.severity,
            "event_time": self.event_time.isoformat(),
            "score": round(self.score, 4),
            "distance": self.distance,
            "dt_seconds": round(self.dt_seconds, 2),
            "shared_entities": self.shared_entities,
            "mitre_techniques": self.mitre_techniques,
            "connector_type": self.connector_type,
            "source_event_ids": self.source_event_ids,
            "via_alert_id": str(self.via_alert_id) if self.via_alert_id else None,
        }


@dataclass
class AttackChain:
    """Full ranked chain returned to the API layer."""

    seed_alert_id: uuid.UUID
    tenant_id: uuid.UUID
    window: str
    chain: list[ChainLink]
    entity_graph: dict[str, list[dict[str, Any]]]
    chain_signature: str
    confidence: float
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed_alert_id": str(self.seed_alert_id),
            "tenant_id": str(self.tenant_id),
            "window": self.window,
            "chain": [link.to_dict() for link in self.chain],
            "entity_graph": self.entity_graph,
            "chain_signature": self.chain_signature,
            "confidence": round(self.confidence, 4),
            "generated_at": self.generated_at.isoformat(),
        }


class AttackChainLoader(Protocol):
    """Pluggable data source.

    The endpoint plugs in a Postgres-backed loader; tests plug in an
    in-memory list. Both must return a ``CandidateAlert`` for every
    alert in the tenant whose ``event_time`` falls in
    ``[start, end]`` *and* whose entity touch-set intersects the seed
    set passed in.
    """

    async def load_seed(self, alert_id: uuid.UUID, tenant_id: uuid.UUID) -> CandidateAlert | None:
        # Protocol method body: ``pass`` rather than ``...`` so CodeQL
        # ``py/ineffectual-statement`` doesn't flag the ellipsis as a
        # discarded expression. Semantically identical for a Protocol
        # stub (both leave the implementation contract empty).
        pass

    async def load_candidates_for_entities(
        self,
        tenant_id: uuid.UUID,
        entities: Iterable[tuple[str, str]],
        start: datetime,
        end: datetime,
        exclude_ids: set[uuid.UUID],
    ) -> list[CandidateAlert]:
        # See ``load_seed`` — Protocol stubs use ``pass`` to silence
        # ``py/ineffectual-statement`` without changing semantics.
        pass


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _temporal_score(seed_time: datetime, candidate_time: datetime, window: timedelta) -> tuple[float, float]:
    """Return (score, |Δt| in seconds). Score is in [0, 1] — closer in
    time → higher score. ``|Δt|`` is exposed in the response so the UI
    can render the absolute time delta beside the chain link."""
    dt = abs((candidate_time - seed_time).total_seconds())
    win_s = window.total_seconds()
    if win_s <= 0:
        return (0.0, dt)
    return (max(0.0, 1.0 - (dt / win_s)), dt)


def _distance_score(distance: int) -> float:
    """``1 / distance`` — bounded so distance-1 is 1.0 and distance-3 is
    ~0.33. Distance-0 is the seed itself, which is excluded upstream."""
    if distance <= 0:
        return 0.0
    return 1.0 / float(distance)


_SEVERITY_RANK: dict[str, int] = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def _risk_overlap(seed: CandidateAlert, cand: CandidateAlert) -> float:
    """MITRE-Jaccard + severity-weighted overlap, ∈ [0, 1].

    * MITRE-Jaccard: ``|A∩B| / |A∪B|`` over technique IDs. Returns 0
      cleanly when neither side has any technique tags.
    * Severity weight: ``min(rank_a, rank_b) / 5`` — favours pairs
      where both alerts are in the high tier over a high+info pair
      that happens to share a single technique.

    The two terms are averaged so neither dominates.
    """
    a = set(seed.mitre_techniques or ())
    b = set(cand.mitre_techniques or ())
    if a or b:
        jaccard = len(a & b) / max(1, len(a | b))
    else:
        jaccard = 0.0
    sa = _SEVERITY_RANK.get((seed.severity or "info").lower(), 1)
    sc = _SEVERITY_RANK.get((cand.severity or "info").lower(), 1)
    sev_term = min(sa, sc) / 5.0
    return (jaccard + sev_term) / 2.0


def _stage_index(alert: CandidateAlert) -> int:
    """Earliest kill-chain stage any of the alert's techniques belongs to, or
    ``UNMAPPED_STAGE`` when none can be placed."""
    stages = []
    for tid in alert.mitre_techniques or ():
        stage = _TECHNIQUE_STAGE.get(str(tid).strip().upper().split(".")[0])
        if stage is not None:
            stages.append(stage)
    return min(stages) if stages else UNMAPPED_STAGE


def score_candidate(
    seed: CandidateAlert,
    cand: CandidateAlert,
    distance: int,
    window: timedelta,
) -> tuple[float, float]:
    """Return ``(score, dt_seconds)`` for a candidate alert.

    Score is the weighted sum from the doc-string above. ``dt_seconds``
    is returned alongside so the caller (which already has it) doesn't
    have to recompute.
    """
    temporal, dt_s = _temporal_score(seed.event_time, cand.event_time, window)
    distance_s = _distance_score(distance)
    risk = _risk_overlap(seed, cand)
    score = (W_DISTANCE * distance_s) + (W_TEMPORAL * temporal) + (W_RISK * risk)
    return (score, dt_s)


# ---------------------------------------------------------------------------
# Provenance helpers
# ---------------------------------------------------------------------------


def _chain_signature(seed_id: uuid.UUID, chain: list[ChainLink]) -> str:
    """Deterministic hash of the seed + ordered chain alert ids.

    Used by ``attack_chains.chain_signature`` to dedupe rewrites of the
    same chain across re-runs (e.g. when a new alert lands and we
    recompute). Stable across processes — never a Python ``hash()``.
    """
    parts = [str(seed_id)] + [str(link.alert_id) for link in chain]
    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def _entity_graph_payload(
    seed: CandidateAlert,
    chain: list[ChainLink],
    candidate_index: dict[uuid.UUID, CandidateAlert],
) -> dict[str, list[dict[str, Any]]]:
    """Build the right-column entity graph the UI renders side-by-side
    with the timeline. Lightweight node/edge JSON — no Neo4j required.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def _add_alert_node(alert: CandidateAlert) -> None:
        node_id = f"alert:{alert.id}"
        if node_id in nodes:
            return
        nodes[node_id] = {
            "id": node_id,
            "kind": "Alert",
            "label": alert.title,
            "severity": alert.severity,
            "event_time": alert.event_time.isoformat(),
        }

    def _add_entity_node(kind: str, value: str) -> None:
        node_id = f"{kind.lower()}:{value}"
        if node_id in nodes:
            return
        nodes[node_id] = {"id": node_id, "kind": kind, "label": value}

    _add_alert_node(seed)
    for kind, value in sorted(seed.entities()):
        _add_entity_node(kind, value)
        edges.append({"source": f"alert:{seed.id}", "target": f"{kind.lower()}:{value}", "kind": "TOUCHES"})

    for link in chain:
        cand = candidate_index.get(link.alert_id)
        if cand is None:
            continue
        _add_alert_node(cand)
        # The alert that bridged this one in touches the same shared
        # entities; draw that too so the pivot lands on the right alert.
        via = candidate_index.get(link.via_alert_id) if link.via_alert_id else None
        if via is not None:
            _add_alert_node(via)
        for ent in link.shared_entities:
            kind = ent["kind"]
            value = ent["value"]
            _add_entity_node(kind, value)
            for owner in (cand, via):
                if owner is None:
                    continue
                edge = {
                    "source": f"alert:{owner.id}",
                    "target": f"{kind.lower()}:{value}",
                    "kind": "TOUCHES",
                }
                if edge not in edges:
                    edges.append(edge)

    return {"nodes": list(nodes.values()), "edges": edges}


# ---------------------------------------------------------------------------
# Core algorithm
# ---------------------------------------------------------------------------


async def compute_attack_chain(
    seed_alert_id: uuid.UUID,
    tenant_id: uuid.UUID,
    loader: AttackChainLoader,
    *,
    window: timedelta = DEFAULT_WINDOW,
    window_label: str = "24h",
    max_depth: int = MAX_DEPTH,
    max_length: int = MAX_CHAIN_LENGTH,
    now: datetime | None = None,
) -> AttackChain | None:
    """Walk the alert↔entity graph from ``seed_alert_id`` and return a
    ranked timeline.

    Returns ``None`` if the seed alert can't be loaded — the API
    endpoint translates that into a 404.
    """
    seed = await loader.load_seed(seed_alert_id, tenant_id)
    if seed is None:
        return None

    anchor = now or seed.event_time
    start = anchor - window
    end = anchor + window  # symmetric: alerts in the future window count too

    # BFS over the bipartite (alert ↔ entity) graph. ``frontier`` holds the
    # entities to query at this depth; ``seen_entities`` is every entity
    # already queried, so one never goes back into the frontier. ``known``
    # holds alerts already placed, so none is re-enqueued at a worse distance.
    seed_entities = seed.entities()
    frontier: set[tuple[str, str]] = set(seed_entities)
    seen_entities: set[tuple[str, str]] = set()
    known: dict[uuid.UUID, tuple[CandidateAlert, int]] = {seed.id: (seed, 0)}
    candidate_index: dict[uuid.UUID, CandidateAlert] = {seed.id: seed}
    # alert id -> (via alert id, entities shared with it); depth-1 links are
    # tied to the seed itself and carry no intermediary.
    via_of: dict[uuid.UUID, tuple[uuid.UUID | None, set[tuple[str, str]]]] = {}
    by_depth: dict[int, list[CandidateAlert]] = {0: [seed]}

    for depth in range(1, max_depth + 1):
        frontier -= seen_entities
        if not frontier:
            break
        seen_entities |= frontier
        rows = await loader.load_candidates_for_entities(
            tenant_id=tenant_id,
            entities=frontier,
            start=start,
            end=end,
            exclude_ids=set(known.keys()),
        )
        next_frontier: set[tuple[str, str]] = set()
        for row in rows:
            if row.id in known:
                continue
            known[row.id] = (row, depth)
            candidate_index[row.id] = row
            by_depth.setdefault(depth, []).append(row)
            if depth == 1:
                via_of[row.id] = (None, row.entities() & seed_entities)
            else:
                # Bridged in by the earliest depth-(n-1) alert it shares an
                # entity with (id breaks ties) so the choice is deterministic.
                bridges = sorted(
                    (a for a in by_depth.get(depth - 1, []) if a.entities() & row.entities()),
                    key=lambda a: (a.event_time, str(a.id)),
                )
                bridge = bridges[0] if bridges else None
                via_of[row.id] = (
                    bridge.id if bridge else None,
                    (bridge.entities() & row.entities()) if bridge else set(),
                )
            # Expand with *all* of this row's entities so depth+1 can attach
            # alerts that share its entities rather than the seed's ("S3
            # enumeration -> exfil" via the cloud user).
            next_frontier |= row.entities()
        frontier = next_frontier - seen_entities

    # Score every non-seed candidate and assemble the chain.
    chain: list[ChainLink] = []
    for alert_id, (cand, distance) in known.items():
        if alert_id == seed.id:
            continue
        score, dt_s = score_candidate(seed, cand, distance, window)
        via_id, shared_set = via_of.get(alert_id, (None, set()))
        chain.append(
            ChainLink(
                alert_id=cand.id,
                title=cand.title,
                severity=cand.severity,
                event_time=cand.event_time,
                score=score,
                distance=distance,
                dt_seconds=dt_s,
                shared_entities=[{"kind": k, "value": v} for k, v in sorted(shared_set)],
                mitre_techniques=list(cand.mitre_techniques),
                connector_type=cand.connector_type,
                source_event_ids=list(cand.source_event_ids),
                via_alert_id=via_id,
            )
        )

    # The cap keeps the best-scoring links; only then is the survivor set put
    # into attack-stage order (stage, then time, then id for determinism) so
    # the timeline reads as an intrusion narrative.
    chain.sort(key=lambda link: (-link.score, link.event_time, str(link.alert_id)))
    chain = chain[:max_length]
    chain.sort(key=lambda link: (_stage_index(candidate_index[link.alert_id]), link.event_time, str(link.alert_id)))

    # Confidence: best candidate score (the seed is not in ``chain``). The
    # chain is stage-ordered, so it is the max, not the first element. Score
    # weights sum to 1 so no normalisation is needed; empty chain -> 0.
    confidence = max((link.score for link in chain), default=0.0)
    signature = _chain_signature(seed.id, chain)
    entity_graph = _entity_graph_payload(seed, chain, candidate_index)

    return AttackChain(
        seed_alert_id=seed.id,
        tenant_id=tenant_id,
        window=window_label,
        chain=chain,
        entity_graph=entity_graph,
        chain_signature=signature,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Postgres-backed loader (used by the API endpoint)
# ---------------------------------------------------------------------------


class PostgresAttackChainLoader:
    """Production loader. Selects directly off ``alerts`` using its
    JSONB entity columns. Tenant scoping is enforced by RLS on the
    session — we still pass ``tenant_id`` for index hits.
    """

    def __init__(self, db: Any) -> None:
        self._db = db

    async def load_seed(self, alert_id: uuid.UUID, tenant_id: uuid.UUID) -> CandidateAlert | None:
        from sqlalchemy import select  # local import keeps the module

        from app.models.alert import Alert  #     test-importable w/o DB

        result = await self._db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id))
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_candidate(row)

    async def load_candidates_for_entities(
        self,
        tenant_id: uuid.UUID,
        entities: Iterable[tuple[str, str]],
        start: datetime,
        end: datetime,
        exclude_ids: set[uuid.UUID],
    ) -> list[CandidateAlert]:
        from sqlalchemy import and_, or_, select, text

        from app.models.alert import Alert

        users: list[str] = []
        hosts: list[str] = []
        assets: list[str] = []
        for kind, value in entities:
            if kind == "Identity":
                users.append(value)
            elif kind == "Endpoint":
                hosts.append(value)
            elif kind == "Resource":
                assets.append(value)

        # JSONB overlap probes. Use the ``?|`` operator so an alert
        # matches if *any* element in the JSONB array intersects the
        # candidate list — single index lookup, no UNNEST.
        clauses = []
        if users:
            clauses.append(text("alerts.affected_users ?| :u").bindparams(u=users))
        if hosts:
            clauses.append(
                or_(
                    text("alerts.affected_hosts ?| :h").bindparams(h=hosts),
                    text("alerts.affected_ips ?| :h2").bindparams(h2=hosts),
                )
            )
        if assets:
            clauses.append(text("alerts.affected_assets ?| :a").bindparams(a=assets))

        if not clauses:
            return []

        stmt = (
            select(Alert)
            .where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.event_time >= start,
                    Alert.event_time <= end,
                    or_(*clauses),
                )
            )
            .limit(MAX_CHAIN_LENGTH * 2)
        )
        if exclude_ids:
            stmt = stmt.where(Alert.id.notin_(list(exclude_ids)))

        result = await self._db.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_candidate(row) for row in rows]


def _row_to_candidate(row: Any) -> CandidateAlert:
    return CandidateAlert(
        id=row.id,
        tenant_id=row.tenant_id,
        title=row.title,
        severity=row.severity or "info",
        event_time=row.event_time,
        mitre_techniques=tuple(row.mitre_techniques or ()),
        affected_users=tuple(row.affected_users or ()),
        affected_hosts=tuple(row.affected_hosts or ()),
        affected_ips=tuple(row.affected_ips or ()),
        affected_assets=tuple(row.affected_assets or ()),
        connector_type=row.connector_type,
        source_event_ids=tuple(row.source_event_ids or ()),
    )
