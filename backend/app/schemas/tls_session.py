from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class TLSSessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: UUID
    timestamp: float | None

    source_ip: str
    destination_ip: str

    source_port: int | None
    destination_port: int | None

    tls_version: str | None
    sni: str | None
    cipher: str | None
    handshake_type: str | None

    created_at: datetime