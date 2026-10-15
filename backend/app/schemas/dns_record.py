from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class DNSRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: UUID
    timestamp: float | None
    source_ip: str
    destination_ip: str
    query_name: str
    query_type: str | None
    response_code: int | None
    answers: str | None
    created_at: datetime