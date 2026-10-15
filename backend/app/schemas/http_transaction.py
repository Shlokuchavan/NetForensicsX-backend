from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class HTTPTransactionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: UUID
    timestamp: float | None

    source_ip: str
    destination_ip: str

    source_port: int | None
    destination_port: int | None

    method: str | None
    host: str | None
    uri: str | None
    status_code: int | None
    user_agent: str | None

    created_at: datetime