from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.evidence import Evidence
from app.models.timeline_event import TimelineEvent
from app.schemas.timeline import (
    TimelineAnalysisResponse,
    TimelineEventRead,
)
from app.services.timeline import build_timeline


router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/timeline",
    tags=["timeline"],
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
    "/build",
    response_model=TimelineAnalysisResponse,
)
async def create_timeline(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    await validate_evidence(
        case_id,
        evidence_id,
        db,
    )

    created, total = await build_timeline(
        db,
        evidence_id,
    )

    return TimelineAnalysisResponse(
        created=created,
        total=total,
    )


@router.get(
    "",
    response_model=list[TimelineEventRead],
)
async def get_timeline(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
    event_type: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    await validate_evidence(
        case_id,
        evidence_id,
        db,
    )

    query = (
        select(TimelineEvent)
        .where(
            TimelineEvent.evidence_id == evidence_id
        )
        .order_by(
            TimelineEvent.timestamp.asc()
        )
        .limit(limit)
        .offset(offset)
    )

    if event_type:
        query = query.where(
            TimelineEvent.event_type == event_type
        )

    if severity:
        query = query.where(
            TimelineEvent.severity == severity
        )

    if search:
        query = query.where(
            TimelineEvent.title.ilike(
                f"%{search}%"
            )
            | TimelineEvent.description.ilike(
                f"%{search}%"
            )
            | TimelineEvent.source_ip.ilike(
                f"%{search}%"
            )
            | TimelineEvent.destination_ip.ilike(
                f"%{search}%"
            )
        )

    result = await db.execute(query)

    return list(result.scalars().all())