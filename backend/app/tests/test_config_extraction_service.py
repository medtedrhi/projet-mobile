from pathlib import Path
from zipfile import ZipFile

from app.services.config_extraction_service import ConfigExtractionService


def test_config_status_records_missing_files(tmp_path: Path):
    apk_path = tmp_path / "empty.apk"
    with ZipFile(apk_path, "w"):
        pass

    items = ConfigExtractionService().extract(apk_path, {"package_name": "com.example.app"})
    by_name = {item["filename"]: item for item in items}

    assert by_name["config_status.json"]["payload"]["network_security_config"] == "not_found"
    assert by_name["config_status.json"]["payload"]["firebase_config"] == "not_found"
    assert by_name["config_status.json"]["payload"]["hardcoded_secrets"] == "not_detected"
    assert by_name["config_status.json"]["payload"]["cleartext_traffic"] == "checked"
    assert by_name["build_config.json"]["payload"]["package"] == "com.example.app"
    assert by_name["app_config_summary.json"]["payload"]["status"]["network_security_config"] == "not_found"


def test_config_extractor_decodes_plain_network_config(tmp_path: Path):
    apk_path = tmp_path / "app.apk"
    with ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "res/xml/network_security_config.xml",
            '<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>',
        )

    items = ConfigExtractionService().extract(apk_path, {})
    by_name = {item["filename"]: item for item in items}

    assert "network-security-config" in by_name["network_security_config.xml"]["payload"]
    assert by_name["config_status.json"]["payload"]["network_security_config"].startswith("extracted:")
