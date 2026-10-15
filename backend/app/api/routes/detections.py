from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.detection import Detection
from app.models.evidence import Evidence
from app.schemas.detection import (
    DetectionAnalysisResponse,
    DetectionRead,
    DetectionSummary,
    DetectionUpdate,
)
from app.services.detection_engine import analyze_detections


router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/detections",
    tags=["detections"],
)


async def get_valid_evidence(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession,
) -> Evidence:
    evidence = await db.get(Evidence, evidence_id)

    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(
            status_code=404,
            detail="Evidence not found in this case",
        )

    return evidence


@router.post(
    "/analyze",
    response_model=DetectionAnalysisResponse,
)
async def analyze_detection_rules(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    await get_valid_evidence(
        case_id,
        evidence_id,
        db,
    )

    created, existing = await analyze_detections(
        db,
        evidence_id,
    )

    result = await db.execute(
        select(func.count())
        .select_from(Detection)
        .where(Detection.evidence_id == evidence_id)
    )

    total = result.scalar_one()

    return DetectionAnalysisResponse(
        created=created,
        existing=existing,
        total=total,
    )


@router.get(
    "",
    response_model=list[DetectionRead],
)
async def list_detections(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
    severity: str | None = None,
    detection_type: str | None = None,
    status: str | None = None,
    search: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    await get_valid_evidence(
        case_id,
        evidence_id,
        db,
    )

    query = (
        select(Detection)
        .where(
            Detection.evidence_id == evidence_id
        )
        .order_by(
            Detection.timestamp.asc().nullslast(),
            Detection.created_at.asc(),
        )
        .limit(limit)
        .offset(offset)
    )

    if severity:
        query = query.where(
            Detection.severity == severity
        )

    if detection_type:
        query = query.where(
            Detection.detection_type == detection_type
        )

    if status:
        query = query.where(
            Detection.status == status
        )

    if search:
        pattern = f"%{search}%"

        query = query.where(
            Detection.title.ilike(pattern)
            | Detection.description.ilike(pattern)
            | Detection.source_ip.ilike(pattern)
            | Detection.destination_ip.ilike(pattern)
        )

    result = await db.execute(query)

    return list(result.scalars().all())


@router.get(
    "/summary",
    response_model=DetectionSummary,
)
async def detection_summary(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    await get_valid_evidence(
        case_id,
        evidence_id,
        db,
    )

    result = await db.execute(
        select(Detection)
        .where(
            Detection.evidence_id == evidence_id
        )
    )

    rows = list(result.scalars().all())

    return DetectionSummary(
        total=len(rows),
        critical=sum(
            1 for row in rows
            if row.severity == "critical"
        ),
        high=sum(
            1 for row in rows
            if row.severity == "high"
        ),
        medium=sum(
            1 for row in rows
            if row.severity == "medium"
        ),
        low=sum(
            1 for row in rows
            if row.severity == "low"
        ),
        info=sum(
            1 for row in rows
            if row.severity == "info"
        ),
    )


@router.patch(
    "/{detection_id}",
    response_model=DetectionRead,
)
async def update_detection(
    case_id: UUID,
    evidence_id: UUID,
    detection_id: UUID,
    payload: DetectionUpdate,
    db: AsyncSession = Depends(get_db),
):
    await get_valid_evidence(
        case_id,
        evidence_id,
        db,
    )

    detection = await db.get(
        Detection,
        detection_id,
    )

    if (
        detection is None
        or detection.evidence_id != evidence_id
    ):
        raise HTTPException(
            status_code=404,
            detail="Detection not found",
        )

    if payload.status is not None:
        detection.status = payload.status

    if payload.severity is not None:
        detection.severity = payload.severity

    await db.commit()
    await db.refresh(detection)

    return detection