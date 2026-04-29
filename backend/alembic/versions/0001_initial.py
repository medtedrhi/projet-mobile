"""initial schema"""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_cases",
        sa.Column("app_name", sa.String(), nullable=False),
        sa.Column("package_name", sa.String(), nullable=True),
        sa.Column("version_name", sa.String(), nullable=True),
        sa.Column("version_code", sa.String(), nullable=True),
        sa.Column("auditor", sa.String(), nullable=False),
        sa.Column("audit_date", sa.String(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, columns in {
        "uploaded_artifacts": [
            sa.Column("case_id", sa.String(), nullable=False), sa.Column("artifact_type", sa.String(), nullable=False),
            sa.Column("source", sa.String(), nullable=False), sa.Column("original_filename", sa.String(), nullable=False),
            sa.Column("stored_path", sa.String(), nullable=False), sa.Column("mime_type", sa.String(), nullable=True),
            sa.Column("file_size", sa.Integer(), nullable=False), sa.Column("file_hash_sha256", sa.String(), nullable=False),
            sa.Column("description", sa.Text(), nullable=True), sa.Column("anonymized", sa.Boolean(), nullable=False),
        ],
        "evidence_items": [
            sa.Column("case_id", sa.String(), nullable=False), sa.Column("artifact_id", sa.String(), nullable=True),
            sa.Column("evidence_type", sa.String(), nullable=False), sa.Column("source", sa.String(), nullable=False),
            sa.Column("original_filename", sa.String(), nullable=True), sa.Column("normalized_path", sa.String(), nullable=False),
            sa.Column("hash_sha256", sa.String(), nullable=True), sa.Column("mime_type", sa.String(), nullable=True),
            sa.Column("size", sa.Integer(), nullable=True), sa.Column("tags", sa.String(), nullable=True),
            sa.Column("description", sa.Text(), nullable=True), sa.Column("sensitivity_level", sa.String(), nullable=False),
            sa.Column("anonymized_flag", sa.Boolean(), nullable=False), sa.Column("traceability_refs", sa.Text(), nullable=True),
            sa.Column("status", sa.String(), nullable=False),
        ],
        "mapping_references": [
            sa.Column("case_id", sa.String(), nullable=False), sa.Column("evidence_item_id", sa.String(), nullable=True),
            sa.Column("masvs_refs", sa.String(), nullable=True), sa.Column("maswe_refs", sa.String(), nullable=True),
            sa.Column("mastg_refs", sa.String(), nullable=True), sa.Column("status", sa.String(), nullable=False),
            sa.Column("notes", sa.Text(), nullable=True),
        ],
        "missing_evidence_issues": [
            sa.Column("case_id", sa.String(), nullable=False), sa.Column("rule_id", sa.String(), nullable=False),
            sa.Column("category", sa.String(), nullable=False), sa.Column("severity", sa.String(), nullable=False),
            sa.Column("title", sa.String(), nullable=False), sa.Column("rationale", sa.Text(), nullable=False),
            sa.Column("recommendation", sa.Text(), nullable=False), sa.Column("status", sa.String(), nullable=False),
        ],
        "generated_reports": [
            sa.Column("case_id", sa.String(), nullable=False), sa.Column("report_type", sa.String(), nullable=False),
            sa.Column("output_path", sa.String(), nullable=False), sa.Column("status", sa.String(), nullable=False),
        ],
        "export_bundles": [
            sa.Column("case_id", sa.String(), nullable=False), sa.Column("bundle_type", sa.String(), nullable=False),
            sa.Column("output_path", sa.String(), nullable=False), sa.Column("status", sa.String(), nullable=False),
        ],
    }.items():
        base_cols = columns + [
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.Column("id", sa.String(), nullable=False),
        ]
        if name == "uploaded_artifacts":
            constraints = [sa.ForeignKeyConstraint(["case_id"], ["audit_cases.id"], ondelete="CASCADE")]
        elif name == "evidence_items":
            constraints = [
                sa.ForeignKeyConstraint(["artifact_id"], ["uploaded_artifacts.id"], ondelete="SET NULL"),
                sa.ForeignKeyConstraint(["case_id"], ["audit_cases.id"], ondelete="CASCADE"),
            ]
        elif name == "mapping_references":
            constraints = [
                sa.ForeignKeyConstraint(["case_id"], ["audit_cases.id"], ondelete="CASCADE"),
                sa.ForeignKeyConstraint(["evidence_item_id"], ["evidence_items.id"], ondelete="CASCADE"),
            ]
        else:
            constraints = [sa.ForeignKeyConstraint(["case_id"], ["audit_cases.id"], ondelete="CASCADE")]
        op.create_table(name, *base_cols, *constraints, sa.PrimaryKeyConstraint("id"))


def downgrade() -> None:
    for name in ["export_bundles", "generated_reports", "missing_evidence_issues", "mapping_references", "evidence_items", "uploaded_artifacts", "audit_cases"]:
        op.drop_table(name)
