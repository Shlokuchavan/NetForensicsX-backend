from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class HTTPTransaction(Base):
    __tablename__ = "http_transactions"

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
        nullable=True
    )

    source_ip: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    destination_ip: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    source_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    destination_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    method: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        index=True,
    )

    host: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        index=True,
    )

    uri: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    status_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )

    user_agent: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )