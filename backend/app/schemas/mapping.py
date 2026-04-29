from app.schemas.common import TimestampedSchema


class MappingReferenceRead(TimestampedSchema):
    case_id: str
    evidence_item_id: str | None
    masvs_refs: str | None
    maswe_refs: str | None
    mastg_refs: str | None
    status: str
    notes: str | None
