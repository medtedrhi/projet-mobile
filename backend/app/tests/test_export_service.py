from pathlib import Path

from app.services.export_service import ExportService


def test_manifest_xml_exports_into_manifest_folder(tmp_path: Path):
    source_path = tmp_path / "AndroidManifest.xml"
    source_path.write_text("<manifest package='com.example.app' />", encoding="utf-8")

    export_dir = tmp_path / "audit-evidence"
    service = ExportService()
    service.build_evidence_tree(export_dir)

    destination = service.copy_evidence_file(
        export_dir,
        "manifest_xml",
        source_path,
        preferred_name="AndroidManifest.xml",
    )

    assert destination is not None
    assert destination == export_dir / "02_manifest" / "AndroidManifest.xml"
    assert destination.exists()
    assert destination.read_text(encoding="utf-8") == "<manifest package='com.example.app' />"


def test_config_evidence_exports_into_configs_folder(tmp_path: Path):
    source_path = tmp_path / "config_status.json"
    source_path.write_text('{"firebase_config":"not_found"}', encoding="utf-8")

    export_dir = tmp_path / "audit-evidence"
    service = ExportService()
    service.build_evidence_tree(export_dir)

    destination = service.copy_evidence_file(
        export_dir,
        "config_config_status",
        source_path,
        preferred_name="config_status.json",
    )

    assert destination == export_dir / "04_configs" / "config_status.json"
    assert destination.exists()
