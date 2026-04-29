from datetime import datetime

from pydantic import BaseModel


class ORMModel(BaseModel):
    model_config = {"from_attributes": True}


class TimestampedSchema(ORMModel):
    id: str
    created_at: datetime
    updated_at: datetime
