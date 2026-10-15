from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.evidence import Evidence
from app.models.ioc import IOC
from app.schemas.ioc import IOCAnalysisResponse, IOCRead
from app.services.ioc_extraction import extract_iocs


router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/iocs",
    tags=["iocs"],
)


async def validate_evidence(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession,
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


@router.post(
    "/analyze",
    response_model=IOCAnalysisResponse,
)
async def analyze_iocs(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    await validate_evidence(
        case_id,
        evidence_id,
        db,
    )

    created, updated = await extract_iocs(
        db,
        evidence_id,
    )

    result = await db.execute(
        select(IOC).where(
            IOC.evidence_id == evidence_id
        )
    )

    total = len(
        list(result.scalars().all())
    )

    return IOCAnalysisResponse(
        created=created,
        updated=updated,
        total=total,
    )


@router.get(
    "",
    response_model=list[IOCRead],
)
async def list_iocs(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
    ioc_type: str | None = None,
    search: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    await validate_evidence(
        case_id,
        evidence_id,
        db,
    )

    query = (
        select(IOC)
        .where(
            IOC.evidence_id == evidence_id
        )
        .order_by(
            IOC.occurrences.desc()
        )
        .limit(limit)
        .offset(offset)
    )

    if ioc_type:
        query = query.where(
            IOC.ioc_type == ioc_type
        )

    if search:
        query = query.where(
            IOC.value.ilike(
                f"%{search}%"
            )
        )

    result = await db.execute(query)

    return list(result.scalars().all())