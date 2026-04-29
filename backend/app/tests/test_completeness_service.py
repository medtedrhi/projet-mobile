import json
from pathlib import Path

from app.services.completeness_service import CompletenessService


def _write_required_pack(export_dir: Path, manifest_xml: str = '<manifest package="com.example.app" />') -> None:
    files = {
        "11_hashes/apk_hash.json": "{}",
        "02_manifest/manifest_summary.json": "{}",
        "02_manifest/AndroidManifest.xml": manifest_xml,
        "03_permissions/permissions.json": "{}",
        "05_sbom/sbom.json": "{}",
        "06_logs/runtime.log": "sanitized",
        "06_logs/anonymization_report.json": json.dumps({"status": "passed"}),
        "07_screenshots/screen.png": "png",
        "00_case_metadata/tool_versions.json": "{}",
        "10_metrics/metrics.json": "{}",
        "09_mas_mapping/mapping.json": "[]",
    }
    for relative_path, content in files.items():
        path = export_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_completeness_report_is_full_when_required_files_are_present(tmp_path: Path):
    _write_required_pack(tmp_path)

    report = CompletenessService().build_report(tmp_path)

    assert report["required_evidence"]["manifest_extract"] == "present"
    assert report["missing"] == []
    assert report["completeness_percent"] == 100
    assert "Only one screenshot found" in report["warnings"]


def test_completeness_report_is_not_full_when_manifest_is_broken(tmp_path: Path):
    _write_required_pack(tmp_path, manifest_xml="<Element manifest at 0x123>")

    report = CompletenessService().build_report(tmp_path)

    assert report["required_evidence"]["manifest_extract"] == "broken"
    assert "manifest_extract" in report["missing"]
    assert report["completeness_percent"] < 100
