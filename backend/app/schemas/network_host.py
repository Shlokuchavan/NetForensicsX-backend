from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class NetworkHostResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: UUID
    evidence_id: UUID

    ip_address: str

    packets_sent: int
    packets_received: int

    bytes_sent: int
    bytes_received: int

    unique_destinations: int
    unique_sources: int

    first_seen: float | None
    last_seen: float | None

    created_at: datetime