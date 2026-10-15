
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.case import Case
from app.models.case_activity import CaseActivity

router = APIRouter(prefix="/cases", tags=["Case Workflow"])

CaseStatus = Literal[
    "open",
    "in_progress",
    "under_review",
    "closed",
]


class StatusUpdate(BaseModel):
    status: CaseStatus
    actor: str = Field(default="analyst", min_length=1, max_length=120)
    note: str | None = Field(default=None, max_length=5000)


class ActivityCreate(BaseModel):
    actor: str = Field(default="analyst", min_length=1, max_length=120)
    action: str = Field(default="note_added", min_length=1, max_length=80)
    details: str = Field(min_length=1, max_length=10000)


def _activity_dict(item: CaseActivity) -> dict:
    return {
        "id": str(item.id),
        "case_id": str(item.case_id),
        "actor": item.actor,
        "action": item.action,
        "details": item.details,
        "metadata_json": item.metadata_json or {},
        "created_at": (
            item.created_at.isoformat()
            if item.created_at
            else None
        ),
    }


async def _get_case(db: AsyncSession, case_id: str) -> Case:
    result = await db.execute(
        select(Case).where(Case.id == case_id)
    )
    case = result.scalar_one_or_none()

    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    return case


async def _log_activity(
    db: AsyncSession,
    case_id: str,
    actor: str,
    action: str,
    details: str | None,
    metadata: dict | None = None,
) -> CaseActivity:
    activity = CaseActivity(
        case_id=case_id,
        actor=actor,
        action=action,
        details=details,
        metadata_json=metadata or {},
        created_at=datetime.now(timezone.utc),
    )
    db.add(activity)
    return activity


@router.get("/{case_id}/activity")
async def list_case_activity(
    case_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    await _get_case(db, case_id)

    result = await db.execute(
        select(CaseActivity)
        .where(CaseActivity.case_id == case_id)
        .order_by(CaseActivity.created_at.desc())
        .limit(limit)
    )
    items = result.scalars().all()

    return {
        "items": [_activity_dict(item) for item in items],
        "count": len(items),
    }


@router.post("/{case_id}/activity", status_code=201)
async def add_case_activity(
    case_id: str,
    payload: ActivityCreate,
    db: AsyncSession = Depends(get_db),
):
    await _get_case(db, case_id)

    activity = await _log_activity(
        db,
        case_id,
        payload.actor,
        payload.action,
        payload.details,
    )

    await db.commit()
    await db.refresh(activity)
    return _activity_dict(activity)


@router.patch("/{case_id}/status")
async def update_case_status(
    case_id: str,
    payload: StatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    case = await _get_case(db, case_id)

    previous_status = getattr(case, "status", None)
    case.status = payload.status

    await _log_activity(
        db,
        case_id,
        payload.actor,
        "status_changed",
        payload.note
        or f"Case status changed from {previous_status} to {payload.status}.",
        {
            "previous_status": previous_status,
            "new_status": payload.status,
        },
    )

    await db.commit()
    await db.refresh(case)

    return {
        "case_id": str(case.id),
        "status": case.status,
        "previous_status": previous_status,
        "message": "Case status updated",
    }