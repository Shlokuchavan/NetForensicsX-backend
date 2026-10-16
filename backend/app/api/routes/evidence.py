import uuid
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.evidence import UPLOAD_DIR, save_evidence_file

from app.db.session import get_db
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.pcap_analysis import PcapAnalysis
from app.schemas.evidence import EvidenceRead
from app.schemas.pcap_analysis import PcapAnalysisResponse
from app.services.evidence import save_evidence_file
from app.services.pcap_analysis import analyze_evidence


router = APIRouter(
    prefix="/cases/{case_id}/evidence",
    tags=["evidence"],
)


@router.post(
    "",
    response_model=EvidenceRead,
)
async def upload_evidence(
    case_id: uuid.UUID,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    case = await db.get(Case, case_id)

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found",
        )

    try:
        (
            stored_filename,
            sha256,
            file_size,
        ) = await save_evidence_file(file)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

        evidence = Evidence(
        case_id=case_id,
        original_filename=file.filename,
        stored_filename=stored_filename,
        file_path=str(UPLOAD_DIR / stored_filename),
        file_size=file_size,
        sha256=sha256,
        mime_type=file.content_type,
        evidence_type="pcap",
        status="uploaded",
    )

    db.add(evidence)

    await db.commit()
    await db.refresh(evidence)

    return evidence


@router.get(
    "",
    response_model=list[EvidenceRead],
)
async def list_evidence(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Evidence)
        .where(Evidence.case_id == case_id)
        .order_by(Evidence.created_at.desc())
    )

    return list(result.scalars().all())


@router.post(
    "/{evidence_id}/analyze",
    response_model=PcapAnalysisResponse,
)
async def analyze_pcap(
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
        return await analyze_evidence(
            db,
            evidence_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.get(
    "/{evidence_id}/analysis",
    response_model=PcapAnalysisResponse,
)
async def get_analysis(
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

    result = await db.execute(
        select(PcapAnalysis).where(
            PcapAnalysis.evidence_id == evidence_id
        )
    )

    analysis = result.scalar_one_or_none()

    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="PCAP has not been analyzed yet",
        )

    return analysis
