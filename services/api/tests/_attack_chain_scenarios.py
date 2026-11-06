"""The labelled attack-chain scenarios as alert rows, shared by the in-memory
and the PostgreSQL evaluations so both grade the same world.

The scenarios and noise come from ``fixtures/attack_chain_scenarios.json``
(see its provenance note): authored, not captured.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from app.services.attack_chain import CandidateAlert

SCENARIO_FIXTURE = Path(__file__).parent / "fixtures" / "attack_chain_scenarios.json"


def _alert(tenant: uuid.UUID, t0: datetime, n: int, row: dict, label: str, session_of: Callable[[str], str]) -> CandidateAlert:
    return CandidateAlert(
        id=uuid.UUID(int=0x5000 + n),
        tenant_id=tenant,
        title=f"{label}: {row['title']}",
        severity=row["severity"],
        event_time=t0 + timedelta(minutes=n),
        affected_users=(row["user"],) if row.get("user") else (),
        affected_hosts=(row["host"],) if row.get("host") else (),
        affected_ips=(row["src_ip"],) if row.get("src_ip") else (),
        mitre_tactics=tuple(row.get("tactics", ())),
        session_id=session_of(row["session"]) if row.get("session") else None,
        session_key_kind="vendor_session" if row.get("session") else None,
        originating_human=row.get("human"),
    )


def labelled_world(
    tenant: uuid.UUID,
    t0: datetime,
    *,
    nat_hub: bool,
    session_of: Callable[[str], str] = lambda s: s,
) -> tuple[dict[str, list[CandidateAlert]], list[CandidateAlert]]:
    """Scenario alerts and noise, interleaved as the story grouper's own
    measurement does, because a method that only works on a quiet queue works
    on no real queue."""
    spec = json.loads(SCENARIO_FIXTURE.read_text())
    scenarios: dict[str, list[CandidateAlert]] = {k: [] for k in spec["scenarios"]}
    noise: list[CandidateAlert] = []
    n = 0
    longest = max(len(v) for v in spec["scenarios"].values())
    for index in range(longest):
        for label, rows in spec["scenarios"].items():
            if index < len(rows):
                scenarios[label].append(_alert(tenant, t0, n, rows[index], label, session_of))
                n += 1
        if index < len(spec["noise"]):
            noise.append(_alert(tenant, t0, n, spec["noise"][index], "noise", session_of))
            n += 1
    if nat_hub:
        hub = spec["nat_hub_noise"]
        for i in range(hub["count"]):
            row = {"title": f"{hub['title']} {i}", "severity": "low", "src_ip": hub["src_ip"], "host": f"ws-{1000 + i}"}
            noise.append(_alert(tenant, t0, n, row, "noise", session_of))
            n += 1
    return scenarios, noise
