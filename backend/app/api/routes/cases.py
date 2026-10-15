import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.case import Case
from app.schemas.case import CaseCreate, CaseRead

router = APIRouter(prefix="/cases", tags=["cases"])


def make_case_number() -> str:
    return f"NF-{uuid.uuid4().hex[:8].upper()}"


@router.get("", response_model=list[CaseRead])
async def list_cases(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Case).order_by(Case.created_at.desc())
    )
    return list(result.scalars().all())



@router.post("", response_model=CaseRead, status_code=status.HTTP_201_CREATED)
async def create_case(payload: CaseCreate, db: AsyncSession = Depends(get_db)):
    case = Case(
        case_number=make_case_number(),
        name=payload.name,
        description=payload.description,
        severity=payload.severity,
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return case



@router.get("/{case_id}", response_model=CaseRead)
async def get_case(case_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case
