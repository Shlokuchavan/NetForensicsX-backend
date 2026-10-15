# backend/app/models/case_activity.py

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CaseActivity(Base):
    __tablename__ = "case_activities"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    
    case_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("cases.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    actor: Mapped[str] = mapped_column(
        String(120),
        default="analyst",
        nullable=False,
    )
    action: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
        index=True,
    )
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )