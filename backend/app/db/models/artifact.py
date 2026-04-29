from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin, UUIDMixin


class UploadedArtifact(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "uploaded_artifacts"

    case_id: Mapped[str] = mapped_column(ForeignKey("audit_cases.id", ondelete="CASCADE"))
    artifact_type: Mapped[str]
    source: Mapped[str]
    original_filename: Mapped[str]
    stored_path: Mapped[str]
    mime_type: Mapped[str | None]
    file_size: Mapped[int]
    file_hash_sha256: Mapped[str]
    description: Mapped[str | None] = mapped_column(Text)
    anonymized: Mapped[bool] = mapped_column(default=False)

    audit_case = relationship("AuditCase", back_populates="artifacts")
