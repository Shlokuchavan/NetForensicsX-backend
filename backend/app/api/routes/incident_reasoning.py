
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.evidence import Evidence
from app.services.incident_reasoning_service import build_incident_reasoning


router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/incident-reasoning",
    tags=["incident-reasoning"],
)


async def validate_evidence(
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


@router.post("/analyze")
async def analyze_incident(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    await validate_evidence(case_id, evidence_id, db)

    try:
        return await build_incident_reasoning(
            db=db,
            case_id=case_id,
            evidence_id=evidence_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Incident reasoning failed. Check backend logs for details.",
        ) from exc


@router.get("")
async def get_incident_reasoning(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    # Recompute from current evidence so this endpoint does not return
    # stale, separately persisted analysis.
    return await analyze_incident(
        case_id=case_id,
        evidence_id=evidence_id,
        db=db,
    )