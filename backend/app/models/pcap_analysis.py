from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PcapAnalysis(Base):
    __tablename__ = "pcap_analysis"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    evidence_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )

    packet_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    host_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    tcp_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    udp_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    icmp_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    dns_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    http_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    https_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    flow_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    capture_start: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    capture_end: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    duration: Mapped[float] = mapped_column(
        Float,
        default=0,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="completed",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )