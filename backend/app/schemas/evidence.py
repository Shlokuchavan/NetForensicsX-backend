import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID

    original_filename: str
    stored_filename: str
    file_path: str

    file_size: int
    sha256: str

    mime_type: str | None
    evidence_type: str
    status: str

    created_at: datetime