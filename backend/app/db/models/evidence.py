from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin, UUIDMixin


class EvidenceItem(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "evidence_items"

    case_id: Mapped[str] = mapped_column(ForeignKey("audit_cases.id", ondelete="CASCADE"))
    artifact_id: Mapped[str | None] = mapped_column(ForeignKey("uploaded_artifacts.id", ondelete="SET NULL"))
    evidence_type: Mapped[str]
    source: Mapped[str]
    original_filename: Mapped[str | None]
    normalized_path: Mapped[str]
    hash_sha256: Mapped[str | None]
    mime_type: Mapped[str | None]
    size: Mapped[int | None]
    tags: Mapped[str | None]
    description: Mapped[str | None] = mapped_column(Text)
    sensitivity_level: Mapped[str] = mapped_column(default="internal")
    anonymized_flag: Mapped[bool] = mapped_column(default=False)
    traceability_refs: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(default="collected")

    audit_case = relationship("AuditCase", back_populates="evidence_items")
