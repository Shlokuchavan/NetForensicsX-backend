from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class PcapAnalysisResponse(BaseModel):

    model_config = ConfigDict(from_attributes=True)

    id: UUID

    evidence_id: UUID

    packet_count: int
    host_count: int

    tcp_count: int
    udp_count: int
    icmp_count: int

    dns_count: int
    http_count: int
    https_count: int

    flow_count: int

    capture_start: float | None
    capture_end: float | None

    duration: float

    status: str

    created_at: datetime