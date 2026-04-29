from app.schemas.common import TimestampedSchema


class EvidenceItemRead(TimestampedSchema):
    case_id: str
    artifact_id: str | None
    evidence_type: str
    source: str
    original_filename: str | None
    normalized_path: str
    hash_sha256: str | None
    mime_type: str | None
    size: int | None
    tags: str | None
    description: str | None
    sensitivity_level: str
    anonymized_flag: bool
    traceability_refs: str | None
    status: str
