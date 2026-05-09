import json
import shutil
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


class ExportService:
    FOLDER_MAP = {
        "apk": "01_apk",
        "apk_hash": "11_hashes",
        "manifest_summary": "02_manifest",
        "manifest_xml": "02_manifest",
        "permissions": "03_permissions",
        "components": "04_components",
        "config_network_security_config": "04_configs",
        "config_strings": "04_configs",
        "config_build_config": "04_configs",
        "config_firebase_config": "04_configs",
        "config_app_config_summary": "04_configs",
        "config_config_status": "04_configs",
        "sbom": "05_sbom",
        "log": "06_logs",
        "screenshot": "07_screenshots",
        "mobsf": "08_findings_import",
        "mobixler": "08_findings_import",
        "mobixler_dynamic": "08_findings_import",
        "runtime_state": "08_findings_import",
        "crash_summary": "08_findings_import",
        "dynamic_run_summary": "00_case_metadata",
        "jadx": "08_findings_import",
    }

    def build_evidence_tree(self, base_dir: Path) -> list[Path]:
        folders = [
            "00_case_metadata",
            "01_apk",
            "02_manifest",
            "03_permissions",
            "04_components",
            "04_configs",
            "05_sbom",
            "06_logs",
            "07_screenshots",
            "08_findings_import",
            "09_mas_mapping",
            "10_metrics",
            "10_reports",
            "11_hashes",
            "12_completeness",
        ]
        created = []
        for folder in folders:
            path = base_dir / folder
            path.mkdir(parents=True, exist_ok=True)
            created.append(path)
        return created

    def write_case_metadata(self, base_dir: Path, payload: dict) -> Path:
        path = base_dir / "00_case_metadata" / "case_metadata.json"
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    def write_tool_versions(self, base_dir: Path, payload: dict) -> Path:
        path = base_dir / "00_case_metadata" / "tool_versions.json"
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    def copy_evidence_file(self, base_dir: Path, evidence_type: str, source_path: Path, preferred_name: str | None = None) -> Path | None:
        if not source_path.exists() or not source_path.is_file():
            return None
        folder = self.FOLDER_MAP.get(evidence_type, "08_findings_import")
        destination_dir = base_dir / folder
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination_name = preferred_name or source_path.name
        destination_path = destination_dir / destination_name
        if source_path.resolve() != destination_path.resolve():
            shutil.copy2(source_path, destination_path)
        return destination_path

    def zip_directory(self, source_dir: Path, zip_path: Path) -> Path:
        with ZipFile(zip_path, "w", ZIP_DEFLATED) as archive:
            for file_path in source_dir.rglob("*"):
                if file_path.is_file():
                    archive.write(file_path, arcname=Path("audit-evidence") / file_path.relative_to(source_dir))
        return zip_path
