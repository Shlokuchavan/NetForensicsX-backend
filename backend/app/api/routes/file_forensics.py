
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.evidence import Evidence
from app.services.file_forensics_service import analyze_file_forensics


router = APIRouter(
    prefix="/cases/{case_id}/evidence/{evidence_id}/file-forensics",
    tags=["file-forensics"],
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
async def run_file_forensics(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    await validate_evidence(case_id, evidence_id, db)

    try:
        return await analyze_file_forensics(
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
        # Do not expose filesystem paths, SQL details, or internal tracebacks.
        raise HTTPException(
            status_code=500,
            detail="File forensics failed. Check backend logs for details.",
        ) from exc


@router.get("")
async def get_file_forensics(
    case_id: UUID,
    evidence_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Re-run analysis on request. Results are computed from the current PCAP
    and HTTP transaction records; they are not persisted in a new table.
    """
    return await run_file_forensics(
        case_id=case_id,
        evidence_id=evidence_id,
        db=db,
    )