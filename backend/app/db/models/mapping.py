from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin, UUIDMixin


class MappingReference(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "mapping_references"

    case_id: Mapped[str] = mapped_column(ForeignKey("audit_cases.id", ondelete="CASCADE"))
    evidence_item_id: Mapped[str | None] = mapped_column(ForeignKey("evidence_items.id", ondelete="CASCADE"))
    masvs_refs: Mapped[str | None]
    maswe_refs: Mapped[str | None]
    mastg_refs: Mapped[str | None]
    status: Mapped[str] = mapped_column(default="mapped")
    notes: Mapped[str | None] = mapped_column(Text)

    audit_case = relationship("AuditCase", back_populates="mapping_references")
    evidence_item = relationship("EvidenceItem")
