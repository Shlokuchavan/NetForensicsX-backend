from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class NetworkFlowResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: UUID
    evidence_id: UUID

    source_ip: str
    destination_ip: str

    protocol: str

    source_port: int | None
    destination_port: int | None

    packets: int
    bytes: int

    first_seen: float | None
    last_seen: float | None

    created_at: datetime