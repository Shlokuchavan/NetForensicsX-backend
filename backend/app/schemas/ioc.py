from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class IOCRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: UUID

    ioc_type: str
    value: str
    source: str

    first_seen: float | None
    last_seen: float | None

    occurrences: int
    confidence: float
    severity: str

    metadata_json: dict
    created_at: datetime


class IOCAnalysisResponse(BaseModel):
    created: int
    updated: int
    total: int