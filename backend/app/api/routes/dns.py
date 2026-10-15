from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.dns_record import DNSRecord
from app.models.evidence import Evidence
from app.schemas.dns_record import DNSRecordRead
from app.services.dns_analysis import analyze_dns


router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/dns",
    tags=["dns"],
)


@router.post(
    "/analyze",
    response_model=list[DNSRecordRead],
)
async def analyze_dns_records(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    evidence = await db.get(Evidence, evidence_id)

    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(
            status_code=404,
            detail="Evidence not found in this case",
        )

    try:
        return await analyze_dns(
            db,
            evidence_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.get(
    "",
    response_model=list[DNSRecordRead],
)
async def get_dns_records(
    case_id: UUID,
    evidence_id: UUID,
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    db: AsyncSession = Depends(get_db),
):

    evidence = await db.get(Evidence, evidence_id)

    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(
            status_code=404,
            detail="Evidence not found in this case",
        )

    result = await db.execute(
        select(DNSRecord)
        .where(
            DNSRecord.evidence_id == evidence_id
        )
        .order_by(
            DNSRecord.timestamp.asc()
        )
        .offset(offset)
        .limit(limit)
    )

    return list(result.scalars().all())