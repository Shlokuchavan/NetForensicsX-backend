from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.evidence import Evidence
from app.models.http_transaction import HTTPTransaction
from app.schemas.http_transaction import HTTPTransactionRead
from app.services.http_analysis import analyze_http


router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/http",
    tags=["http"],
)


@router.post(
    "/analyze",
    response_model=list[HTTPTransactionRead],
)
async def analyze_http_transactions(
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

    try:
        return await analyze_http(
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
    response_model=list[HTTPTransactionRead],
)
async def get_http_transactions(
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
        select(HTTPTransaction)
        .where(
            HTTPTransaction.evidence_id == evidence_id
        )
        .order_by(
            HTTPTransaction.timestamp.asc()
        )
        .offset(offset)
        .limit(limit)
    )

    return list(result.scalars().all())