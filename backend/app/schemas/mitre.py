from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class MitreMappingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: UUID
    detection_id: UUID | None

    technique_id: str
    technique_name: str
    tactic: str
    description: str

    confidence: float
    metadata_json: dict
    created_at: datetime


class MitreAnalysisResponse(BaseModel):
    created: int
    total: int