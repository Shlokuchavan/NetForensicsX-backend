from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.evidence import Evidence
from app.models.network_host import NetworkHost
from app.schemas.network_host import NetworkHostResponse
from app.services.host_discovery import discover_hosts


router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/hosts",
    tags=["host discovery"],
)


@router.post(
    "/discover",
    response_model=list[NetworkHostResponse],
)
async def run_host_discovery(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    evidence = await db.get(
        Evidence,
        evidence_id,
    )

    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(
            status_code=404,
            detail="Evidence not found in this case",
        )

    return await discover_hosts(
        db,
        evidence_id,
    )


@router.get(
    "",
    response_model=list[NetworkHostResponse],
)
async def list_discovered_hosts(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    evidence = await db.get(
        Evidence,
        evidence_id,
    )

    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(
            status_code=404,
            detail="Evidence not found in this case",
        )

    result = await db.execute(
        select(NetworkHost)
        .where(
            NetworkHost.evidence_id == evidence_id
        )
        .order_by(
            NetworkHost.ip_address.asc()
        )
    )

    return list(result.scalars().all())