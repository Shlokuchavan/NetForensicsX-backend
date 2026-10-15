from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class DetectionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: UUID
    timestamp: float | None

    detection_type: str
    severity: str

    title: str
    description: str

    source_ip: str | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str | None

    confidence: float
    status: str

    fingerprint: str
    metadata_json: dict

    created_at: datetime


class DetectionUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None


class DetectionSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class DetectionAnalysisResponse(BaseModel):
    created: int
    existing: int
    total: int