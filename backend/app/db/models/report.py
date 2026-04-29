from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin, UUIDMixin


class GeneratedReport(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "generated_reports"

    case_id: Mapped[str] = mapped_column(ForeignKey("audit_cases.id", ondelete="CASCADE"))
    report_type: Mapped[str]
    output_path: Mapped[str]
    status: Mapped[str] = mapped_column(default="ready")

    audit_case = relationship("AuditCase", back_populates="reports")


class ExportBundle(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "export_bundles"

    case_id: Mapped[str] = mapped_column(ForeignKey("audit_cases.id", ondelete="CASCADE"))
    bundle_type: Mapped[str]
    output_path: Mapped[str]
    status: Mapped[str] = mapped_column(default="ready")

    audit_case = relationship("AuditCase", back_populates="exports")
