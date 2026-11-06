"""Attack-chain timeline endpoint (T3.3 — v8.0 parallel team).

Exposes the ranked timeline computed by
``services/api/app/services/attack_chain.py`` to the case-detail UI.

``GET /v1/cases/{case_id}/attack-chain?window=24h``
    Returns the alerts that share entities with the seed alert anchored
    to this case, in ATT&CK stage order, plus the side-by-side entity
    graph the right column renders. ``truncated`` / ``truncated_reasons``
    say when matching alerts were left out; a short chain with
    ``truncated`` set is not evidence that nothing else is related.
    Read-only: a request writes nothing.

The endpoint is tenant-scoped via the existing RLS dependency stack
(``AuthUser`` + ``DBSession``). The seed alert is resolved as the
*earliest* alert linked to the case so the timeline reads
chronologically — first → last — by default.
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select, text

from app.api.v1.deps import AuthUser, DBSession
from app.models.alert import Alert
from app.services.attack_chain import (
    AttackChain,
    PostgresAttackChainLoader,
    compute_attack_chain,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["cases"])


WindowLiteral = Literal["1h", "6h", "24h", "72h", "7d", "30d"]

_WINDOW_TO_TIMEDELTA: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "72h": timedelta(hours=72),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


@router.get("/{case_id}/attack-chain")
async def get_attack_chain(
    case_id: uuid.UUID,
    db: DBSession,
    user: AuthUser,
    window: WindowLiteral = Query(default="24h"),
) -> dict[str, Any]:
    """Return the ranked attack-chain timeline for the case's seed alert.

    The seed alert is the earliest ``alert.event_time`` linked to the
    case. If the case has no linked alerts the response is an empty
    chain — never a 500.
    """
    if window not in _WINDOW_TO_TIMEDELTA:
        # Belt + suspenders: FastAPI's Literal already rejects unknowns
        # but a future schema change could relax that — fail closed.
        raise HTTPException(status_code=400, detail=f"unknown window: {window}")

    # Read the case via raw SQL against ``aisoc_cases``: the live schema
    # stores cases there, while the ``Case`` ORM still points at the empty
    # legacy ``cases`` table — ``select(Case)`` 404'd every real case.
    case_row = (
        await db.execute(
            text("SELECT id, tenant_id, alert_ids FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=case_id, tenant_id=user.tenant_id
            )
        )
    ).fetchone()
    if case_row is None:
        raise HTTPException(status_code=404, detail="case_not_found")

    # Pick the seed alert: earliest event_time linked to the case. We
    # prefer ``case.alert_ids`` (denormalised) but fall back to a probe
    # on ``alerts.case_id`` if that list is empty so a freshly-linked
    # case still resolves.
    seed_alert_id: uuid.UUID | None = None
    raw_ids = case_row.alert_ids or []
    if raw_ids:
        candidate_ids = [uuid.UUID(str(a)) if not isinstance(a, uuid.UUID) else a for a in raw_ids]
        seed_row = (
            await db.execute(
                select(Alert)
                .where(
                    Alert.id.in_(candidate_ids),
                    Alert.tenant_id == user.tenant_id,
                )
                .order_by(Alert.event_time.asc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if seed_row is not None:
            seed_alert_id = seed_row.id

    if seed_alert_id is None:
        seed_row = (
            await db.execute(
                select(Alert)
                .where(
                    Alert.case_id == case_id,
                    Alert.tenant_id == user.tenant_id,
                )
                .order_by(Alert.event_time.asc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if seed_row is not None:
            seed_alert_id = seed_row.id

    if seed_alert_id is None:
        return {
            "case_id": str(case_id),
            "tenant_id": str(user.tenant_id),
            "window": window,
            "seed_alert_id": None,
            "chain": [],
            "entity_graph": {"nodes": [], "edges": []},
            "chain_signature": None,
            "confidence": 0.0,
            "truncated": False,
            "truncated_reasons": [],
            "reason": "case_has_no_linked_alerts",
        }

    loader = PostgresAttackChainLoader(db)
    try:
        chain: AttackChain | None = await compute_attack_chain(
            seed_alert_id=seed_alert_id,
            tenant_id=user.tenant_id,
            loader=loader,
            window=_WINDOW_TO_TIMEDELTA[window],
            window_label=window,
        )
    except Exception:
        # Fail closed: a database error must not read as "no related
        # alerts". The caller is told the chain could not be built.
        logger.exception("attack_chain computation failed case_id=%s", case_id)
        raise HTTPException(status_code=503, detail="attack_chain_unavailable") from None
    if chain is None:
        raise HTTPException(status_code=404, detail="seed_alert_not_found")

    # Nothing is persisted here. This route used to upsert every computed
    # chain into ``aisoc_attack_chains``, but nothing reads that table, and
    # its unique key includes ``chain_signature`` — a value only known after
    # the traversal — so it could never be looked up to skip the traversal. A
    # GET that writes an unreadable row per distinct chain is cost without a
    # consumer. A real cache needs a key knowable before computing (seed,
    # window) plus an invalidation rule, which is a schema decision.

    payload = chain.to_dict()
    payload["case_id"] = str(case_id)
    return payload
