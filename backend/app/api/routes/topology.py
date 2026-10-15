from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.evidence import Evidence
from app.schemas.network_topology import NetworkTopologyResponse
from app.services.network_topology import build_network_topology


router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/topology",
    tags=["network topology"],
)


@router.get(
    "",
    response_model=NetworkTopologyResponse,
)
async def get_network_topology(
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

    return await build_network_topology(
        db,
        evidence_id,
    )