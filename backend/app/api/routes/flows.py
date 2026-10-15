
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.evidence import Evidence
from app.models.network_flow import NetworkFlow
from app.schemas.network_flow import NetworkFlowResponse

router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/flows",
    tags=["network flows"],
)


@router.get("", response_model=list[NetworkFlowResponse])
async def list_network_flows(
    case_id: UUID,
    evidence_id: UUID,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    protocol: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """
    Return aggregated network flows for a specific evidence file.

    Supports:
    - Pagination using limit and offset
    - Optional protocol filtering
    """
    evidence = await db.get(Evidence, evidence_id)

    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(
            status_code=404,
            detail="Evidence not found in this case",
        )

    stmt = select(NetworkFlow).where(
        NetworkFlow.evidence_id == evidence_id
    )

    if protocol:
        stmt = stmt.where(
            NetworkFlow.protocol == protocol.upper()
        )

    stmt = (
        stmt.order_by(
            NetworkFlow.first_seen.asc().nulls_last(),
            NetworkFlow.id.asc(),
        )
        .offset(offset)
        .limit(limit)
    )

    result = await db.execute(stmt)
    return list(result.scalars().all())