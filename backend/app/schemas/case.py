
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


CaseSeverity = Literal["critical", "high", "medium", "low", "info", "unknown"]


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    severity: CaseSeverity = "medium"


class CaseRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_number: str
    name: str
    description: str | None
    status: str
    severity: str
    created_at: datetime
    updated_at: datetime
