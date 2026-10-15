from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Detection(Base):
    __tablename__ = "detections"

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

    timestamp: Mapped[float | None] = mapped_column(
        nullable=True,
        index=True,
    )

    detection_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    destination_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    protocol: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        default=0.5,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(16),
        default="new",
        nullable=False,
        index=True,
    )

    fingerprint: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
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