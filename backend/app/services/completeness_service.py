from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree


class CompletenessService:
    """Verify required evidence files in an exported audit pack."""

    REQUIRED_CHECKS = (
        "apk_hash",
        "manifest_extract",
        "permissions_list",
        "sbom",
        "screenshots",
        "logs_anonymized",
        "tool_versions",
        "metrics",
        "masvs_mapping",
    )

    def build_report(self, export_dir: Path) -> dict:
        required_evidence = {
            "apk_hash": self._present(export_dir / "11_hashes" / "apk_hash.json"),
            "manifest_extract": self._manifest_status(export_dir),
            "permissions_list": self._present(export_dir / "03_permissions" / "permissions.json"),
            "sbom": self._present(export_dir / "05_sbom" / "sbom.json"),
            "screenshots": self._screenshots_status(export_dir),
            "logs_anonymized": self._logs_status(export_dir),
            "tool_versions": self._present(export_dir / "00_case_metadata" / "tool_versions.json"),
            "metrics": self._present(export_dir / "10_metrics" / "metrics.json"),
            "masvs_mapping": self._present(export_dir / "09_mas_mapping" / "mapping.json"),
        }
        missing = [name for name, status in required_evidence.items() if status != "present"]
        warnings = self._warnings(export_dir, required_evidence)
        present_count = sum(1 for status in required_evidence.values() if status == "present")

        return {
            "required_evidence": required_evidence,
            "missing": missing,
            "warnings": warnings,
            "completeness_percent": round((present_count / len(self.REQUIRED_CHECKS)) * 100),
        }

    def write_report(self, export_dir: Path) -> Path:
        output_dir = export_dir / "12_completeness"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "missing_evidence_report.json"
        output_path.write_text(json.dumps(self.build_report(export_dir), indent=2), encoding="utf-8")
        return output_path

    def _present(self, path: Path) -> str:
        return "present" if path.exists() and path.is_file() and path.stat().st_size > 0 else "missing"

    def _manifest_status(self, export_dir: Path) -> str:
        summary_path = export_dir / "02_manifest" / "manifest_summary.json"
        manifest_path = export_dir / "02_manifest" / "AndroidManifest.xml"
        if self._present(summary_path) != "present" or self._present(manifest_path) != "present":
            return "missing"
        if not self._valid_manifest_xml(manifest_path):
            return "broken"
        return "present"

    def _valid_manifest_xml(self, manifest_path: Path) -> bool:
        try:
            root = ElementTree.fromstring(manifest_path.read_text(encoding="utf-8"))
        except (ElementTree.ParseError, OSError, UnicodeDecodeError):
            return False
        return root.tag == "manifest" and bool(root.attrib.get("package"))

    def _screenshots_status(self, export_dir: Path) -> str:
        screenshots = list((export_dir / "07_screenshots").glob("*"))
        return "present" if any(path.is_file() and path.stat().st_size > 0 for path in screenshots) else "missing"

    def _logs_status(self, export_dir: Path) -> str:
        logs_dir = export_dir / "06_logs"
        has_log = any(path.is_file() and path.suffix.lower() == ".log" and path.stat().st_size > 0 for path in logs_dir.glob("*"))
        report_path = logs_dir / "anonymization_report.json"
        if not has_log or self._present(report_path) != "present":
            return "missing"
        try:
            report = json.loads(report_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return "broken"
        return "present" if report.get("status") == "passed" else "broken"

    def _warnings(self, export_dir: Path, required_evidence: dict[str, str]) -> list[str]:
        warnings = []
        screenshot_count = sum(1 for path in (export_dir / "07_screenshots").glob("*") if path.is_file())
        if screenshot_count == 1:
            warnings.append("Only one screenshot found")
        if required_evidence.get("manifest_extract") == "broken":
            warnings.append("Manifest XML is broken and must be re-extracted")
        elif required_evidence.get("manifest_extract") == "present":
            warnings.append("Manifest XML validated")
        return warnings
