import json
import re
from datetime import date
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
from app.services.dynamic_analysis_service import DynamicAnalysisResult, DynamicAnalysisService
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
        self.dynamic_analysis_service = DynamicAnalysisService(self.android_capture, LogSanitizer())
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

    def create_case_with_apk(self, db: Session, payload: dict, file: UploadFile) -> AuditCase:
        app_name = (payload.get("app_name") or "").strip()
        if not app_name:
            app_name = Path(file.filename or "Android APK").stem.replace("_", " ").replace("-", " ") or "Android APK"
        payload["app_name"] = app_name
        audit_case = self.create_case(db, payload)
        self.upload_artifact(
            db=db,
            case_id=audit_case.id,
            file=file,
            artifact_type="apk",
            source="case-creation-upload",
            description="APK uploaded during audit case creation.",
        )
        refreshed = self.get_case(db, audit_case.id)
        if refreshed is None:
            raise ValueError("Case not found after APK upload.")
        return refreshed

    def list_cases(self, db: Session) -> list[AuditCase]:
        return db.query(AuditCase).order_by(AuditCase.created_at.desc()).all()

    def get_case(self, db: Session, case_id: str) -> AuditCase | None:
        return db.query(AuditCase).filter(AuditCase.id == case_id).first()

    def delete_case(self, db: Session, case_id: str) -> None:
        audit_case = self.get_case(db, case_id)
        if audit_case is None:
            raise ValueError("Case not found")
        db.delete(audit_case)
        db.commit()

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

    def run_dynamic_apk_analysis(
        self,
        db: Session,
        case_id: str,
        device_serial: str | None = None,
        source: str = "adb-dynamic-analysis",
        monkey_event_count: int | None = None,
        log_line_count: int | None = None,
    ) -> UploadedArtifact:
        audit_case = self.get_case(db, case_id)
        if audit_case is None:
            raise ValueError("Case not found")

        apk_artifact = self._latest_apk_artifact(audit_case)
        if apk_artifact is None:
            raise ValueError("Upload an APK before running dynamic analysis.")

        package_name = audit_case.package_name
        if not package_name:
            apk_metadata = self.apk_parser.parse(Path(apk_artifact.stored_path))
            package_name = apk_metadata.get("package_name")
        if not package_name:
            raise ValueError("Package name could not be resolved from the case or APK.")

        payload_bytes, metadata = self.android_capture.run_dynamic_apk_analysis(
            Path(apk_artifact.stored_path),
            package_name=package_name,
            device_serial=device_serial,
            monkey_event_count=monkey_event_count or self.settings.dynamic_analysis_monkey_event_count,
            log_line_count=log_line_count,
        )
        sanitized_payload = self.log_sanitizer.sanitize(payload_bytes.decode("utf-8", errors="ignore"), self.settings.redact_ipv6).encode(
            "utf-8"
        )
        description = (
            f"Mobixler-style dynamic APK analysis for {package_name} on {metadata['device_serial']}: "
            "install, launch, monkey exercise, logcat, screenshot, process, and runtime state capture."
        )
        return self._persist_artifact(
            db=db,
            case_id=case_id,
            artifact_type="mobixler_dynamic",
            source=source,
            original_filename=metadata["filename"],
            content=sanitized_payload,
            mime_type=metadata["mime_type"],
            description=description,
            anonymized=True,
        )

    def run_full_dynamic_analysis(
        self,
        db: Session,
        case_id: str,
        file: UploadFile | None = None,
        device_serial: str | None = None,
        monkey_event_count: int | None = None,
        log_line_count: int | None = None,
        wait_after_launch_seconds: int | None = None,
    ) -> dict[str, Any]:
        if not self.settings.dynamic_analysis_enabled:
            raise ValueError("Dynamic analysis is disabled. Set DYNAMIC_ANALYSIS_ENABLED=true to enable it.")

        audit_case = self.get_case(db, case_id)
        if audit_case is None:
            raise ValueError("Case not found")

        apk_artifact = None
        if file is not None:
            apk_artifact = self.upload_artifact(
                db=db,
                case_id=case_id,
                file=file,
                artifact_type="apk",
                source="ui-dynamic-upload",
                description="APK uploaded for one-click full dynamic analysis.",
            )
            audit_case = self.get_case(db, case_id)
        if apk_artifact is None and audit_case is not None:
            apk_artifact = self._latest_apk_artifact(audit_case)
        if apk_artifact is None:
            raise ValueError("APK file missing. Upload an APK or attach one to this request.")

        apk_path = Path(apk_artifact.stored_path)
        if not apk_path.exists():
            raise ValueError("APK file missing on disk. Re-upload the APK before running dynamic analysis.")

        apk_metadata = self.apk_parser.parse(apk_path)
        package_name = apk_metadata.get("package_name") or (audit_case.package_name if audit_case else None)
        if not package_name:
            raise ValueError("Package name not found. The APK parser could not identify the target package.")

        result = self.dynamic_analysis_service.run_full_dynamic_analysis(
            apk_path=apk_path,
            package_name=package_name,
            case_id=case_id,
            device_serial=device_serial,
            monkey_event_count=monkey_event_count or self.settings.dynamic_analysis_monkey_event_count,
            log_line_count=log_line_count or self.settings.dynamic_analysis_log_line_count,
            wait_after_launch_seconds=wait_after_launch_seconds
            if wait_after_launch_seconds is not None
            else self.settings.dynamic_analysis_wait_after_launch_seconds,
            apk_info=apk_metadata,
        )

        for artifact in result.artifacts:
            if artifact.path.exists() and artifact.path.is_file():
                self._persist_artifact(
                    db=db,
                    case_id=case_id,
                    artifact_type=artifact.evidence_type,
                    source="adb-dynamic-analysis",
                    original_filename=artifact.filename,
                    content=artifact.path.read_bytes(),
                    mime_type=artifact.mime_type,
                    description=artifact.description,
                    anonymized=artifact.anonymized,
                )

        report_error = None
        export_error = None
        report = None
        export = None
        if self.settings.dynamic_analysis_auto_export:
            try:
                report = self.generate_report(db, case_id)
            except ValueError as exc:
                report_error = f"Report generation failed: {exc}"
            try:
                export = self.export_case_bundle(db, case_id)
            except ValueError as exc:
                export_error = f"Export generation failed: {exc}"

        if report_error:
            result.errors.append(report_error)
        if export_error:
            result.errors.append(export_error)

        return self._dynamic_response_payload(result, report, export)

    def _dynamic_response_payload(
        self,
        result: DynamicAnalysisResult,
        report: GeneratedReport | None,
        export: ExportBundle | None,
    ) -> dict[str, Any]:
        export_download_url = f"/api/exports/{export.id}/download" if export else None
        return {
            "status": "completed" if result.install_ok and not any("Export generation failed" in e for e in result.errors) else "completed_with_errors",
            "package_name": result.target.get("package_name"),
            "device_serial": result.device.get("serial"),
            "install_ok": result.install_ok,
            "launch_ok": result.launch_ok,
            "monkey_ok": result.monkey_ok,
            "screenshots_captured": result.execution.get("screenshots_captured", 0),
            "log_file_generated": bool(result.execution.get("logs_captured")),
            "crash_detected": bool(result.runtime.get("crash_detected")),
            "anr_detected": bool(result.runtime.get("anr_detected")),
            "process_present": bool(result.runtime.get("process_present")),
            "ai_summary_generated": bool(export),
            "report_id": report.id if report else None,
            "export_id": export.id if export else None,
            "export_download_url": export_download_url,
            "summary": result.to_payload(),
            "errors": result.errors,
        }

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

    def _latest_apk_artifact(self, audit_case: AuditCase) -> UploadedArtifact | None:
        apk_artifacts = [artifact for artifact in audit_case.artifacts if artifact.artifact_type == "apk"]
        return max(apk_artifacts, key=lambda artifact: artifact.created_at) if apk_artifacts else None

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
            self._update_case_metadata_from_apk(db, case_id, output_path)
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

    def _update_case_metadata_from_apk(self, db: Session, case_id: str, apk_path: Path) -> None:
        audit_case = self.get_case(db, case_id)
        if audit_case is None:
            return
        try:
            metadata = self.apk_parser.parse(apk_path)
        except Exception:
            return

        package_name = metadata.get("package_name")
        version_name = metadata.get("version_name")
        version_code = metadata.get("version_code")
        if package_name:
            audit_case.package_name = str(package_name)
        if version_name:
            audit_case.version_name = str(version_name)
        if version_code:
            audit_case.version_code = str(version_code)
        if not audit_case.app_name and package_name:
            audit_case.app_name = str(package_name)
        db.add(audit_case)
        db.flush()

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
        self._write_anonymization_report(case_export_dir, audit_case.evidence_items)
        self.completeness_service.write_report(case_export_dir)
        self._write_pack_supporting_files(case_export_dir, report_context, traceability)

        reports_dir = case_export_dir / "10_reports"
        reports_dir.mkdir(exist_ok=True)
        report = self.generate_report(db, case_id)
        report_path = Path(report.output_path)
        if report_path.exists():
            (reports_dir / "report.html").write_text(report_path.read_text(encoding="utf-8"), encoding="utf-8")

        hashes_path = case_export_dir / "11_hashes" / "hashes.json"
        hashes_payload = {
            item["id"]: item["hash_sha256"]
            for item in evidence_items
            if item.get("hash_sha256")
        }
        hashes_path.write_text(json.dumps(hashes_payload, indent=2), encoding="utf-8")
        zip_path = self.settings.exports_dir / self._export_zip_filename(audit_case)
        self.export_service.zip_directory(case_export_dir, zip_path)

        bundle = ExportBundle(case_id=case_id, bundle_type="zip", output_path=str(zip_path))
        db.add(bundle)
        db.commit()
        db.refresh(bundle)
        return bundle

    def _export_zip_filename(self, audit_case: AuditCase) -> str:
        app_name = audit_case.app_name or audit_case.package_name or audit_case.id
        normalized_name = re.sub(r"[^A-Za-z0-9._ -]+", "", app_name).strip()
        normalized_name = re.sub(r"\s+", " ", normalized_name).strip(" ._-")
        if not normalized_name:
            normalized_name = "android-app"
        export_date = date.today().isoformat()
        return f"evidences collection from the {normalized_name} {export_date}.zip"

    def _copy_evidence_into_pack(self, case_export_dir: Path, evidence_items: list[EvidenceItem]) -> None:
        for item in evidence_items:
            source_path = Path(item.normalized_path)
            preferred_name = item.original_filename or source_path.name
            if item.evidence_type == "apk":
                preferred_name = "uploaded.apk"
            elif item.evidence_type == "mobixler_dynamic":
                preferred_name = "mobisef_dynamic.json"
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
        mapping_dir = case_export_dir / "09_mas_mapping"
        mapping_path = mapping_dir / "masvs_mapping.json"
        mapping_path.write_text(json.dumps(traceability, indent=2), encoding="utf-8")
        (mapping_dir / "mapping.json").write_text(json.dumps(traceability, indent=2), encoding="utf-8")
        maswe_mapping = [item for item in traceability if item.get("maswe")]
        mastg_mapping = [item for item in traceability if item.get("mastg")]
        if maswe_mapping:
            (mapping_dir / "maswe_mapping.json").write_text(json.dumps(maswe_mapping, indent=2), encoding="utf-8")
        if mastg_mapping:
            (mapping_dir / "mastg_mapping.json").write_text(json.dumps(mastg_mapping, indent=2), encoding="utf-8")
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
        ai_summary_path = case_export_dir / "10_reports" / "ai_summary.md"
        ai_summary_path.write_text(self._build_dynamic_ai_summary(report_context, case_export_dir), encoding="utf-8")

    def _build_dynamic_ai_summary(self, report_context: dict, case_export_dir: Path) -> str:
        dynamic_payload = self._latest_import_payload(report_context, "mobixler_dynamic") or {}
        missing_path = case_export_dir / "12_completeness" / "missing_evidence.json"
        missing_payload = {}
        if missing_path.exists():
            try:
                missing_payload = json.loads(missing_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                missing_payload = {}

        context = {
            "case": {
                "app_name": report_context["case"].app_name,
                "package_name": report_context["case"].package_name,
            },
            "dynamic": dynamic_payload,
            "evidence_types": report_context["summary"].get("artifact_type_counts", {}),
            "missing_evidence": missing_payload.get("missing", []),
        }
        llm_summary = self.summary_provider.reasoner.complete(
            system_prompt=(
                "Write a grounded defensive Android audit evidence summary in markdown. "
                "Use only the supplied evidence. Include these headings exactly: "
                "# AI Evidence Summary, ## Executive Summary, ## Dynamic Analysis Result, "
                "## Foreground Activity Validation, ## Evidence Collected, ## Important Gaps, ## Conclusion. "
                "Do not invent root causes."
            ),
            user_payload=context,
            max_tokens=700,
            purpose="dynamic-evidence-summary",
        )
        if llm_summary:
            return llm_summary

        dynamic_execution = dynamic_payload.get("execution", {}) if isinstance(dynamic_payload, dict) else {}
        runtime = dynamic_payload.get("runtime", {}) if isinstance(dynamic_payload, dict) else {}
        package_name = (
            dynamic_payload.get("target", {}).get("package_name")
            if isinstance(dynamic_payload.get("target"), dict)
            else report_context["case"].package_name
        ) or "the target APK"
        evidence_types = sorted(report_context["summary"].get("artifact_type_counts", {}).keys())
        tracking = runtime.get("activity_tracking", {}) if isinstance(runtime, dict) else {}
        final_activity = tracking.get("foreground_activity_final", {}) if isinstance(tracking, dict) else {}
        missing = missing_payload.get("missing", []) or []
        gaps = "\n".join(f"- {item}" for item in missing) if missing else "No missing evidence was detected by the completeness engine."
        return "\n".join(
            [
                "# AI Evidence Summary",
                "",
                "## Executive Summary",
                f"{package_name} was tested with the built-in defensive Android dynamic analysis workflow.",
                "",
                "## Dynamic Analysis Result",
                (
                    f"Install: {'ok' if dynamic_execution.get('install_ok') else 'failed or unavailable'}. "
                    f"Launch: {'ok' if dynamic_execution.get('launch_ok') else 'failed or unavailable'}. "
                    f"Screenshots captured: {dynamic_execution.get('screenshots_captured', 0)}. "
                    f"Logs captured: {'yes' if dynamic_execution.get('logs_captured') else 'no'}. "
                    f"Crash detected: {'yes' if runtime.get('crash_detected') else 'no'}. "
                    f"Process present: {'yes' if runtime.get('process_present') else 'no'}."
                ),
                "",
                "## Foreground Activity Validation",
                (
                    f"The app was foreground after launch: {'yes' if tracking.get('was_target_foreground_after_launch') else 'no'}. "
                    f"Monkey left the app: {'yes' if tracking.get('monkey_left_app') else 'no'}. "
                    f"The tool re-focused the app before final evidence: {'yes' if tracking.get('refocus_attempted_after_monkey') else 'no'}. "
                    f"Final foreground activity: {final_activity.get('component') or 'unknown'}."
                ),
                "",
                "## Evidence Collected",
                ", ".join(evidence_types) if evidence_types else "No evidence artifacts were listed.",
                "",
                "## Important Gaps",
                gaps,
                "",
                "## Conclusion",
                "The evidence pack is suitable for a defensive mobile audit when the listed evidence and gaps match the intended scope.",
            ]
        )

    def _latest_import_payload(self, report_context: dict, evidence_type: str) -> dict[str, Any] | None:
        imports = report_context.get("details", {}).get("imports", [])
        for item in reversed(imports):
            if item.get("type") == evidence_type and isinstance(item.get("payload"), dict):
                return item["payload"]
        return None

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
            elif item.evidence_type in {"mobsf", "mobixler", "mobixler_dynamic", "jadx"}:
                details["imports"].append({"type": item.evidence_type, "filename": item.original_filename, "payload": payload})

        details["latest_manifest"] = details["manifests"][-1] if details["manifests"] else {}
        details["latest_permissions"] = details["permissions"][-1] if details["permissions"] else {}
        details["latest_components"] = details["components"][-1] if details["components"] else {}
        details["latest_sbom"] = details["sboms"][-1] if details["sboms"] else {}
        details["latest_hashes"] = details["hashes"][-1] if details["hashes"] else {}
        details["raw_manifest_xml"] = self._latest_raw_manifest(evidence_items)
        latest_dynamic = self._latest_dynamic_import(details["imports"])
        details["dynamic_activity_tracking"] = (latest_dynamic.get("runtime") or {}).get("activity_tracking", {}) if latest_dynamic else {}
        details["dynamic_target"] = latest_dynamic.get("target", {}) if latest_dynamic else {}
        return details

    def _latest_dynamic_import(self, imports: list[dict[str, Any]]) -> dict[str, Any] | None:
        for item in reversed(imports):
            if item.get("type") == "mobixler_dynamic" and isinstance(item.get("payload"), dict):
                return item["payload"]
        return None

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
        if item.evidence_type not in {"manifest_xml", "log", "mobsf", "mobixler", "mobixler_dynamic", "jadx"}:
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
