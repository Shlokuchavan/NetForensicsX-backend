from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    evidence_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    ioc_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    first_seen: Mapped[float | None] = mapped_column(
        nullable=True,
    )

    last_seen: Mapped[float | None] = mapped_column(
        nullable=True,
    )

    occurrences: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        default=0.5,
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(16),
        default="info",
        nullable=False,
    )

    metadata_json: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )