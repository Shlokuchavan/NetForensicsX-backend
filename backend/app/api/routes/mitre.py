from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.evidence import Evidence
from app.models.mitre_mapping import MitreMapping
from app.schemas.mitre import (
    MitreAnalysisResponse,
    MitreMappingRead,
)
from app.services.mitre import map_detections_to_mitre


router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/mitre",
    tags=["mitre"],
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
    response_model=MitreAnalysisResponse,
)
async def analyze_mitre(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    await validate_evidence(
        case_id,
        evidence_id,
        db,
    )

    created, total = await map_detections_to_mitre(
        db,
        evidence_id,
    )

    return MitreAnalysisResponse(
        created=created,
        total=total,
    )


@router.get(
    "",
    response_model=list[MitreMappingRead],
)
async def list_mitre_mappings(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
    technique_id: str | None = None,
    tactic: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    await validate_evidence(
        case_id,
        evidence_id,
        db,
    )

    query = (
        select(MitreMapping)
        .where(
            MitreMapping.evidence_id == evidence_id
        )
        .order_by(
            MitreMapping.confidence.desc()
        )
        .limit(limit)
        .offset(offset)
    )

    if technique_id:
        query = query.where(
            MitreMapping.technique_id == technique_id
        )

    if tactic:
        query = query.where(
            MitreMapping.tactic == tactic
        )

    result = await db.execute(query)

    return list(result.scalars().all())