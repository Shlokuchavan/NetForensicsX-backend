from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class TimelineEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: UUID

    timestamp: float
    event_type: str

    source_ip: str | None
    destination_ip: str | None

    title: str
    description: str

    severity: str

    reference_type: str | None
    reference_id: str | None

    metadata_json: dict
    created_at: datetime


class TimelineAnalysisResponse(BaseModel):
    created: int
    total: int