from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class NetworkHost(Base):
    __tablename__ = "network_hosts"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    evidence_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "evidence.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    ip_address: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    packets_sent: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    packets_received: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    bytes_sent: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    bytes_received: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    unique_destinations: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    unique_sources: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    first_seen: Mapped[float | None] = mapped_column(
        nullable=True,
    )

    last_seen: Mapped[float | None] = mapped_column(
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )