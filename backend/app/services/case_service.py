import json
from pathlib import Path
from typing import Any

from fastapi import UploadFile
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import ensure_within_root, safe_filename
from app.db.models.artifact import UploadedArtifact
from app.db.models.audit_case import AuditCase
from app.db.models.evidence import EvidenceItem
from app.db.models.issue import MissingEvidenceIssue
from app.db.models.mapping import MappingReference
from app.db.models.report import ExportBundle, GeneratedReport
from app.services.apk_parser import ApkParserService
from app.services.android_capture_service import AndroidCaptureService
from app.services.completeness_service import CompletenessService
from app.services.evidence_collector import EvidenceCollectorService
from app.services.evidence_index_service import EvidenceIndexService
from app.services.export_service import ExportService
from app.services.hash_service import HashService
from app.services.intelligence import ComplianceNarrativeGenerator, MappingReasoner, SummaryProvider
from app.services.log_sanitizer import LogSanitizer
from app.services.manifest_service import ManifestService
from app.services.mapping_service import MappingService
from app.services.metrics_service import MetricsService
from app.services.missing_evidence_service import MissingEvidenceService
from app.services.permissions_service import PermissionsService
from app.services.report_service import ReportService
from app.services.sbom_service import SBOMService
from app.services.tool_versions_service import ToolVersionsService
from app.services.traceability_table_service import TraceabilityTableService


class CaseService:
    def __init__(self):
        settings = get_settings()
        self.settings = settings
        self.hash_service = HashService()
        self.apk_parser = ApkParserService()
        self.android_capture = AndroidCaptureService(
            adb_executable=settings.adb_executable,
            timeout_seconds=settings.screenshot_capture_timeout_seconds,
            runtime_log_timeout_seconds=settings.runtime_log_capture_timeout_seconds,
            runtime_log_line_count=settings.runtime_log_capture_line_count,
        )
        self.completeness_service = CompletenessService()
        self.evidence_collector = EvidenceCollectorService()
        self.manifest_service = ManifestService()
        self.permissions_service = PermissionsService()
        self.sbom_service = SBOMService()
        self.mapping_service = MappingService(Path("app/mappings"))
        self.metrics_service = MetricsService()
        self.missing_evidence_service = MissingEvidenceService()
        self.log_sanitizer = LogSanitizer()
        self.evidence_index_service = EvidenceIndexService()
        self.export_service = ExportService()
        self.report_service = ReportService(Path("app/templates"))
        self.tool_versions_service = ToolVersionsService()
        self.traceability_table_service = TraceabilityTableService()
        self.summary_provider = SummaryProvider()
        self.mapping_reasoner = MappingReasoner()
        self.narrative_generator = ComplianceNarrativeGenerator()

    def create_case(self, db: Session, payload: dict) -> AuditCase:
        audit_case = AuditCase(**payload)
        db.add(audit_case)
        db.commit()
        db.refresh(audit_case)
        self.refresh_mappings_and_issues(db, audit_case.id)
        return audit_case

    def list_cases(self, db: Session) -> list[AuditCase]:
        return db.query(AuditCase).order_by(AuditCase.created_at.desc()).all()

    def get_case(self, db: Session, case_id: str) -> AuditCase | None:
        return db.query(AuditCase).filter(AuditCase.id == case_id).first()

    def list_connected_android_devices(self) -> list[dict[str, str | None]]:
        return self.android_capture.list_devices()

    def _artifact_directory(self, case_id: str) -> Path:
        path = self.settings.uploads_dir / case_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def upload_artifact(
        self,
        db: Session,
        case_id: str,
        file: UploadFile,
        artifact_type: str,
        source: str = "user-upload",
        description: str | None = None,
    ) -> UploadedArtifact:
        content = file.file.read()

        if len(content) > self.settings.max_upload_size_mb * 1024 * 1024:
            raise ValueError("Uploaded file exceeds configured size limit")

        anonymized = False
        if artifact_type == "log":
            sanitized = self.log_sanitizer.sanitize(content.decode("utf-8", errors="ignore"), self.settings.redact_ipv6)
            content = sanitized.encode("utf-8")
            anonymized = True

        return self._persist_artifact(
            db=db,
            case_id=case_id,
            artifact_type=artifact_type,
            source=source,
            original_filename=file.filename or "upload.bin",
            content=content,
            mime_type=file.content_type,
            description=description,
            anonymized=anonymized,
        )

    def capture_screenshot(
        self,
        db: Session,
        case_id: str,
        device_serial: str | None = None,
        source: str = "adb-capture",
        description: str | None = None,
    ) -> UploadedArtifact:
        image_bytes, metadata = self.android_capture.capture_screenshot(device_serial)
        capture_description = description or f"Automated UI screenshot captured via adb from {metadata['device_serial']}."
        return self._persist_artifact(
            db=db,
            case_id=case_id,
            artifact_type="screenshot",
            source=source,
            original_filename=metadata["filename"],
            content=image_bytes,
            mime_type=metadata["mime_type"],
            description=capture_description,
            anonymized=False,
        )

    def capture_runtime_logs(
        self,
        db: Session,
        case_id: str,
        device_serial: str | None = None,
        source: str = "adb-logcat",
        description: str | None = None,
        line_count: int | None = None,
    ) -> UploadedArtifact:
        log_bytes, metadata = self.android_capture.capture_runtime_logs(device_serial, line_count=line_count)
        sanitized = self.log_sanitizer.sanitize(log_bytes.decode("utf-8", errors="ignore"), self.settings.redact_ipv6).encode("utf-8")
        capture_description = description or (
            f"Sanitized runtime logs captured via adb logcat from {metadata['device_serial']} "
            f"({metadata['line_count']} lines requested)."
        )
        return self._persist_artifact(
            db=db,
            case_id=case_id,
            artifact_type="log",
            source=source,
            original_filename=metadata["filename"],
            content=sanitized,
            mime_type=metadata["mime_type"],
            description=capture_description,
            anonymized=True,
        )

    def _persist_artifact(
        self,
        db: Session,
        case_id: str,
        artifact_type: str,
        source: str,
        original_filename: str,
        content: bytes,
        mime_type: str | None,
        description: str | None,
        anonymized: bool,
    ) -> UploadedArtifact:
        audit_case = self.get_case(db, case_id)
        if audit_case is None:
            raise ValueError("Case not found")

        safe_name = safe_filename(original_filename)
        artifact_dir = self._artifact_directory(case_id)
        output_path = self._available_output_path(artifact_dir, safe_name)
        output_path.write_bytes(content)
        hashes = self.hash_service.hash_file(output_path)

        artifact = UploadedArtifact(
            case_id=case_id,
            artifact_type=artifact_type,
            source=source,
            original_filename=original_filename,
            stored_path=str(output_path),
            mime_type=mime_type,
            file_size=len(content),
            file_hash_sha256=hashes["sha256"],
            description=description,
            anonymized=anonymized,
        )
        db.add(artifact)
        db.commit()
        db.refresh(artifact)

        self._create_evidence_from_artifact(db, case_id, artifact, output_path, hashes)
        return artifact

    def _available_output_path(self, artifact_dir: Path, filename: str) -> Path:
        candidate = ensure_within_root(artifact_dir, artifact_dir / filename)
        if not candidate.exists():
            return candidate

        stem = Path(filename).stem
        suffix = Path(filename).suffix
        index = 1
        while True:
            alternate = ensure_within_root(artifact_dir, artifact_dir / f"{stem}_{index}{suffix}")
            if not alternate.exists():
                return alternate
            index += 1

    def _create_evidence_from_artifact(
        self,
        db: Session,
        case_id: str,
        artifact: UploadedArtifact,
        output_path: Path,
        hashes: dict[str, str],
    ) -> None:
        base_evidence = EvidenceItem(
            case_id=case_id,
            artifact_id=artifact.id,
            evidence_type=artifact.artifact_type,
            source=artifact.source,
            original_filename=artifact.original_filename,
            normalized_path=str(output_path),
            hash_sha256=hashes["sha256"],
            mime_type=artifact.mime_type,
            size=artifact.file_size,
            tags=artifact.artifact_type,
            description=artifact.description,
            sensitivity_level="restricted" if artifact.artifact_type == "log" else "internal",
            anonymized_flag=artifact.anonymized,
            traceability_refs="",
        )
        db.add(base_evidence)
        db.flush()

        if artifact.artifact_type == "apk":
            extracted = self.evidence_collector.collect_from_apk(output_path)
            for item in extracted:
                record_path = self.evidence_collector.write_payload(output_path.parent, item)
                evidence = EvidenceItem(
                    case_id=case_id,
                    artifact_id=artifact.id,
                    evidence_type=item["evidence_type"],
                    source="generated",
                    original_filename=record_path.name,
                    normalized_path=str(record_path),
                    hash_sha256=self.hash_service.hash_file(record_path)["sha256"],
                    mime_type=item["mime_type"],
                    size=record_path.stat().st_size,
                    tags=item["evidence_type"],
                    description=item["description"],
                    sensitivity_level="internal",
                    anonymized_flag=False,
                    traceability_refs=json.dumps(self.mapping_reasoner.infer_domains(item["evidence_type"])),
                )
                db.add(evidence)

        db.commit()
        self.refresh_mappings_and_issues(db, case_id)

    def refresh_mappings_and_issues(self, db: Session, case_id: str) -> None:
        db.query(MappingReference).filter(MappingReference.case_id == case_id).delete()
        db.query(MissingEvidenceIssue).filter(MissingEvidenceIssue.case_id == case_id).delete()
        db.commit()

        evidence_items = db.query(EvidenceItem).filter(EvidenceItem.case_id == case_id).all()
        available_types = {item.evidence_type for item in evidence_items}

        for item in evidence_items:
            refs = self.mapping_service.map_evidence_item(
                item,
                payload=self._read_evidence_payload(item),
                raw_text=self._read_mapping_text(item),
            )
            mapping = MappingReference(
                case_id=case_id,
                evidence_item_id=item.id,
                masvs_refs=",".join(refs["masvs"]),
                maswe_refs=",".join(refs["maswe"]),
                mastg_refs=",".join(refs["mastg"]),
                status=refs["status"],
                notes=refs["notes"],
            )
            db.add(mapping)

        for issue in self.missing_evidence_service.evaluate(available_types):
            # Persist only fields that exist on the MissingEvidenceIssue model.
            # Exclude internal rule fields such as `requires` and `require_mode`.
            persisted_issue = {key: value for key, value in issue.items() if key not in ("requires", "require_mode")}
            missing = MissingEvidenceIssue(case_id=case_id, **persisted_issue)
            db.add(missing)

        db.commit()

    def build_case_summary(self, audit_case: AuditCase) -> dict[str, Any]:
        artifacts = len(audit_case.artifacts)
        evidence_items = len(audit_case.evidence_items)
        missing = len(self._deduplicate_missing_issues(audit_case.missing_issues))
        score = round(max(0.0, 100 - (missing * 12.5)), 2)
        return {
            "total_artifacts": artifacts,
            "total_evidence_items": evidence_items,
            "total_mappings": len(audit_case.mapping_references),
            "total_missing_issues": missing,
            "completeness_score": score,
        }

    def build_case_insights(self, audit_case: AuditCase) -> dict[str, Any]:
        missing_issues = self._deduplicate_missing_issues(audit_case.missing_issues)
        report_context = self._report_context(audit_case)
        provider_enabled = self.summary_provider.reasoner.enabled
        missing_explanations = []
        for issue, narrative in zip(missing_issues, report_context["summary"]["missing_narratives"]):
            missing_explanations.append(
                {
                    "title": issue.title,
                    "why_it_matters": issue.rationale,
                    "next_step": issue.recommendation,
                    "narrative": narrative,
                }
            )
        return {
            "collection_summary": report_context["summary"]["collection_summary"],
            "missing_narratives": report_context["summary"]["missing_narratives"],
            "missing_explanations": missing_explanations,
            "provider_mode": "openrouter" if provider_enabled else "fallback",
            "provider_label": (
                f"OpenRouter: {self.summary_provider.reasoner.model}"
                if provider_enabled
                else "Fallback summary mode"
            ),
        }

    def generate_report(self, db: Session, case_id: str) -> GeneratedReport:
        self.refresh_mappings_and_issues(db, case_id)
        audit_case = self.get_case(db, case_id)
        if audit_case is None:
            raise ValueError("Case not found")

        report_context = self._report_context(audit_case)
        report_path = self.settings.reports_dir / f"{case_id}.html"
        self.report_service.render_html(report_context, report_path)

        report = GeneratedReport(case_id=case_id, report_type="html", output_path=str(report_path))
        db.add(report)
        db.commit()
        db.refresh(report)
        return report

    def export_case_bundle(self, db: Session, case_id: str) -> ExportBundle:
        self.refresh_mappings_and_issues(db, case_id)
        audit_case = self.get_case(db, case_id)
        if audit_case is None:
            raise ValueError("Case not found")

        case_export_dir = self.settings.exports_dir / case_id
        self.export_service.build_evidence_tree(case_export_dir)
        report_context = self._report_context(audit_case)
        self.export_service.write_case_metadata(case_export_dir, report_context)
        self.export_service.write_tool_versions(case_export_dir, self.tool_versions_service.collect())
        self._write_metrics(case_export_dir, audit_case.evidence_items, report_context)

        evidence_items = [self._serialize_evidence(item) for item in audit_case.evidence_items]
        evidence_lookup = {item.id: item for item in audit_case.evidence_items}
        traceability = [self._serialize_mapping(item, evidence_lookup) for item in audit_case.mapping_references]
        self.evidence_index_service.write_indexes(case_export_dir, evidence_items, traceability)
        self.traceability_table_service.write_csv(case_export_dir, traceability)
        self._copy_evidence_into_pack(case_export_dir, audit_case.evidence_items)
        self._write_pack_supporting_files(case_export_dir, report_context, traceability)
        self._write_anonymization_report(case_export_dir, audit_case.evidence_items)
        self.completeness_service.write_report(case_export_dir)

        reports_dir = case_export_dir / "10_reports"
        reports_dir.mkdir(exist_ok=True)
        report = self.generate_report(db, case_id)
        report_path = Path(report.output_path)
        if report_path.exists():
            (reports_dir / report_path.name).write_text(report_path.read_text(encoding="utf-8"), encoding="utf-8")

        hashes_path = case_export_dir / "11_hashes" / "hashes.json"
        hashes_payload = {
            item["id"]: item["hash_sha256"]
            for item in evidence_items
            if item.get("hash_sha256")
        }
        hashes_path.write_text(json.dumps(hashes_payload, indent=2), encoding="utf-8")
        zip_path = self.settings.exports_dir / f"{case_id}_evidence_pack.zip"
        self.export_service.zip_directory(case_export_dir, zip_path)

        bundle = ExportBundle(case_id=case_id, bundle_type="zip", output_path=str(zip_path))
        db.add(bundle)
        db.commit()
        db.refresh(bundle)
        return bundle

    def _copy_evidence_into_pack(self, case_export_dir: Path, evidence_items: list[EvidenceItem]) -> None:
        for item in evidence_items:
            source_path = Path(item.normalized_path)
            preferred_name = item.original_filename or source_path.name
            self.export_service.copy_evidence_file(case_export_dir, item.evidence_type, source_path, preferred_name)

    def _write_metrics(self, case_export_dir: Path, evidence_items: list[EvidenceItem], report_context: dict) -> None:
        metrics_dir = case_export_dir / "10_metrics"
        metrics_dir.mkdir(parents=True, exist_ok=True)
        completeness = report_context["summary"].get("completeness_score", 0)
        metrics = self.metrics_service.build(list(evidence_items), completeness)
        (metrics_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    def _write_anonymization_report(self, case_export_dir: Path, evidence_items: list[EvidenceItem]) -> None:
        log_text = []
        for item in evidence_items:
            if item.evidence_type != "log":
                continue
            path = Path(item.normalized_path)
            if not path.exists():
                continue
            try:
                log_text.append(path.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue

        report = self.log_sanitizer.anonymization_report("\n".join(log_text), self.settings.redact_ipv6)
        report_path = case_export_dir / "06_logs" / "anonymization_report.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    def _serialize_evidence(self, item: EvidenceItem) -> dict:
        return {
            "id": item.id,
            "evidence_type": item.evidence_type,
            "source": item.source,
            "original_filename": item.original_filename,
            "normalized_path": item.normalized_path,
            "hash_sha256": item.hash_sha256,
            "mime_type": item.mime_type,
            "size": item.size,
            "sensitivity_level": item.sensitivity_level,
            "status": item.status,
        }

    def _serialize_mapping(self, item: MappingReference, evidence_lookup: dict[str, EvidenceItem] | None = None) -> dict:
        evidence = None
        if evidence_lookup:
            evidence = evidence_lookup.get(item.evidence_item_id or "")
        return {
            "evidence_item_id": item.evidence_item_id,
            "evidence_type": evidence.evidence_type if evidence else None,
            "original_filename": evidence.original_filename if evidence else None,
            "masvs": item.masvs_refs.split(",") if item.masvs_refs else [],
            "maswe": item.maswe_refs.split(",") if item.maswe_refs else [],
            "mastg": item.mastg_refs.split(",") if item.mastg_refs else [],
            "status": item.status,
            "notes": item.notes,
        }

    def _write_pack_supporting_files(self, case_export_dir: Path, report_context: dict, traceability: list[dict]) -> None:
        mapping_path = case_export_dir / "09_mas_mapping" / "mapping.json"
        mapping_path.write_text(json.dumps(traceability, indent=2), encoding="utf-8")
        summary_path = case_export_dir / "10_reports" / "summary.txt"
        details = report_context["details"]
        lines = [
            f"App: {report_context['case'].app_name}",
            f"Package: {report_context['case'].package_name or 'Unknown'}",
            f"Evidence items: {report_context['summary']['total_evidence_items']}",
            f"Completeness score: {report_context['summary']['completeness_score']}%",
            "",
            "AI evidence summary:",
            report_context["summary"]["collection_summary"],
            "",
            "Collected evidence types:",
        ]
        for evidence_type, count in report_context["summary"]["artifact_type_counts"].items():
            lines.append(f"- {evidence_type}: {count}")
        lines.extend(
            [
                "",
                "Manifest summary:",
                f"- minSdk: {details['latest_manifest'].get('min_sdk', 'Unknown') if details['latest_manifest'] else 'Unknown'}",
                f"- targetSdk: {details['latest_manifest'].get('target_sdk', 'Unknown') if details['latest_manifest'] else 'Unknown'}",
                f"- summary: {details['latest_manifest'].get('summary', 'Not available') if details['latest_manifest'] else 'Not available'}",
                "",
                "Missing evidence:",
            ]
        )
        for issue in report_context["missing_issues"]:
            lines.append(f"- {issue.title}: {issue.recommendation}")
        summary_path.write_text("\n".join(lines), encoding="utf-8")

    def _report_context(self, audit_case: AuditCase) -> dict:
        summary = self.build_case_summary(audit_case)
        artifacts = list(audit_case.artifacts)
        evidence_items = list(audit_case.evidence_items)
        evidence_lookup = {item.id: item for item in evidence_items}
        summary["artifact_type_counts"] = self._artifact_type_counts(evidence_items)
        summary["deduplication"] = self._deduplicate_artifacts(artifacts)
        extracted_details = self._build_extracted_details(evidence_items)
        missing_issues = self._deduplicate_missing_issues(audit_case.missing_issues)
        summary["coverage"] = self.mapping_service.coverage_summary(
            [self._serialize_mapping(item, evidence_lookup) for item in audit_case.mapping_references]
        )
        summary["collection_summary"] = self.summary_provider.summarize_collection(
            self._build_summary_prompt_context(audit_case, summary, extracted_details)
        )
        summary["missing_narratives"] = [
            self.narrative_generator.explain_gap(
                issue.title,
                issue.recommendation,
                issue.rationale,
                context=self._build_gap_prompt_context(audit_case, summary, extracted_details, issue.title),
            )
            for issue in missing_issues
        ]
        return {
            "case": audit_case,
            "summary": summary,
            "artifacts": artifacts,
            "evidence_items": evidence_items,
            "mapping_references": audit_case.mapping_references,
            "missing_issues": missing_issues,
            "details": extracted_details,
        }

    def _build_summary_prompt_context(self, audit_case: AuditCase, summary: dict[str, Any], details: dict[str, Any]) -> dict[str, Any]:
        latest_sbom = details.get("latest_sbom") or {}
        latest_manifest = details.get("latest_manifest") or {}
        latest_permissions = details.get("latest_permissions") or {}
        latest_components = details.get("latest_components") or {}
        return {
            "app_name": audit_case.app_name,
            "package_name": audit_case.package_name,
            "audit_scope": audit_case.scope,
            "total_artifacts": summary["total_artifacts"],
            "total_evidence_items": summary["total_evidence_items"],
            "total_missing_issues": summary["total_missing_issues"],
            "completeness_score": summary["completeness_score"],
            "evidence_types": sorted(summary["artifact_type_counts"].keys()),
            "artifact_type_counts": summary["artifact_type_counts"],
            "coverage": summary["coverage"],
            "manifest": {
                "package_name": latest_manifest.get("package") or latest_manifest.get("package_name"),
                "min_sdk": latest_manifest.get("min_sdk"),
                "target_sdk": latest_manifest.get("target_sdk"),
            },
            "permissions": {
                "count": len(latest_permissions.get("permissions", [])),
                "sensitive_count": len(latest_permissions.get("sensitive_permissions", [])),
            },
            "components": {
                "exported_component_count": len(latest_components.get("exported_components", [])),
                "embedded_domain_count": len(latest_components.get("embedded_domains", [])),
                "cleartext_traffic_allowed": latest_components.get("cleartext_traffic_allowed"),
            },
            "sbom": {
                "status": latest_sbom.get("status"),
                "generator": latest_sbom.get("generator"),
                "component_count": len(latest_sbom.get("components", [])),
                "statistics": latest_sbom.get("statistics", {}),
            },
            "missing_titles": [issue.title for issue in audit_case.missing_issues],
        }

    def _build_gap_prompt_context(
        self,
        audit_case: AuditCase,
        summary: dict[str, Any],
        details: dict[str, Any],
        gap_title: str,
    ) -> dict[str, Any]:
        return {
            "app_name": audit_case.app_name,
            "package_name": audit_case.package_name,
            "gap_title": gap_title,
            "available_evidence_types": sorted(summary["artifact_type_counts"].keys()),
            "artifact_type_counts": summary["artifact_type_counts"],
            "completeness_score": summary["completeness_score"],
            "latest_manifest_present": bool(details.get("latest_manifest")),
            "latest_permissions_present": bool(details.get("latest_permissions")),
            "latest_sbom_present": bool(details.get("latest_sbom")),
            "screenshot_count": len(details.get("screenshots", [])),
            "log_count": len(details.get("logs", [])),
        }

    def _artifact_type_counts(self, evidence_items: list[EvidenceItem]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in evidence_items:
            counts[item.evidence_type] = counts.get(item.evidence_type, 0) + 1
        return dict(sorted(counts.items()))

    def _deduplicate_artifacts(self, artifacts: list[UploadedArtifact]) -> dict[str, Any]:
        unique_hashes: dict[str, UploadedArtifact] = {}
        duplicate_groups: dict[str, list[str]] = {}
        for artifact in artifacts:
            unique_hashes.setdefault(artifact.file_hash_sha256, artifact)
            duplicate_groups.setdefault(artifact.file_hash_sha256, []).append(artifact.original_filename)
        return {
            "total_artifacts": len(artifacts),
            "unique_artifacts": len(unique_hashes),
            "duplicate_hashes": {key: value for key, value in duplicate_groups.items() if len(value) > 1},
        }

    def _build_extracted_details(self, evidence_items: list[EvidenceItem]) -> dict[str, Any]:
        details: dict[str, Any] = {
            "hashes": [],
            "manifests": [],
            "permissions": [],
            "components": [],
            "sboms": [],
            "logs": [],
            "screenshots": [],
            "imports": [],
        }
        for item in evidence_items:
            payload = self._read_evidence_payload(item)
            if item.evidence_type == "apk_hash" and isinstance(payload, dict):
                details["hashes"].append(payload)
            elif item.evidence_type == "manifest_summary" and isinstance(payload, dict):
                details["manifests"].append(payload)
            elif item.evidence_type == "permissions" and isinstance(payload, dict):
                details["permissions"].append(payload)
            elif item.evidence_type == "components" and isinstance(payload, dict):
                details["components"].append(payload)
            elif item.evidence_type == "sbom" and isinstance(payload, dict):
                details["sboms"].append(payload)
            elif item.evidence_type == "log":
                details["logs"].append(self._read_text_excerpt(item))
            elif item.evidence_type == "screenshot":
                details["screenshots"].append({"filename": item.original_filename, "path": item.normalized_path})
            elif item.evidence_type in {"mobsf", "jadx"}:
                details["imports"].append({"type": item.evidence_type, "filename": item.original_filename, "payload": payload})

        details["latest_manifest"] = details["manifests"][-1] if details["manifests"] else {}
        details["latest_permissions"] = details["permissions"][-1] if details["permissions"] else {}
        details["latest_components"] = details["components"][-1] if details["components"] else {}
        details["latest_sbom"] = details["sboms"][-1] if details["sboms"] else {}
        details["latest_hashes"] = details["hashes"][-1] if details["hashes"] else {}
        details["raw_manifest_xml"] = self._latest_raw_manifest(evidence_items)
        return details

    def _read_evidence_payload(self, item: EvidenceItem) -> Any:
        path = Path(item.normalized_path)
        if not path.exists() or path.suffix.lower() != ".json":
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _read_text_excerpt(self, item: EvidenceItem) -> dict[str, Any]:
        path = Path(item.normalized_path)
        excerpt = ""
        if path.exists():
            try:
                excerpt = path.read_text(encoding="utf-8", errors="ignore")[:1000]
            except OSError:
                excerpt = ""
        return {"filename": item.original_filename, "path": item.normalized_path, "excerpt": excerpt}

    def _read_mapping_text(self, item: EvidenceItem) -> str:
        path = Path(item.normalized_path)
        if not path.exists():
            return ""
        if item.evidence_type not in {"manifest_xml", "log", "mobsf", "jadx"}:
            return ""
        try:
            return path.read_text(encoding="utf-8", errors="ignore")[:6000]
        except OSError:
            return ""

    def _latest_raw_manifest(self, evidence_items: list[EvidenceItem]) -> str:
        for item in reversed(evidence_items):
            if item.evidence_type == "manifest_xml":
                path = Path(item.normalized_path)
                if path.exists():
                    try:
                        return path.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        return ""
        return ""

    def _deduplicate_missing_issues(self, missing_issues: list[MissingEvidenceIssue]) -> list[MissingEvidenceIssue]:
        unique: dict[str, MissingEvidenceIssue] = {}
        for issue in missing_issues:
            unique.setdefault(issue.rule_id, issue)
        return list(unique.values())
