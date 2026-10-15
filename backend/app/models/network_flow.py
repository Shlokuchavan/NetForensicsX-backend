from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class NetworkFlow(Base):
    __tablename__ = "network_flows"

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

    protocol: Mapped[str] = mapped_column(
        String(16),
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

    packets: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    bytes: Mapped[int] = mapped_column(
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