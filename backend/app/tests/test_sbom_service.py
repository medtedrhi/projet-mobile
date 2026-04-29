from pathlib import Path
from zipfile import ZipFile

from app.services.sbom_service import SBOMService


def test_generate_builds_archive_derived_sbom(tmp_path: Path):
    apk_path = tmp_path / "demo.apk"
    with ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest package='com.example.demo' />")
        archive.writestr("classes.dex", b"dex-1")
        archive.writestr("classes2.dex", b"dex-2")
        archive.writestr("lib/arm64-v8a/libcrypto.so", b"native-lib")
        archive.writestr("res/layout/activity_main.xml", "<LinearLayout />")

    metadata = {
        "package_name": "com.example.demo",
        "version_name": "1.2.3",
        "version_code": "123",
        "min_sdk": "24",
        "target_sdk": "34",
        "libraries": ["com.squareup.okio:okio:3.9.0"],
    }

    sbom = SBOMService().generate(metadata, apk_path)

    assert sbom["status"] == "generated"
    assert sbom["generator"] == "local-apk-sbom"
    assert sbom["format"] == "local-apk-sbom-v1"
    assert sbom["subject"]["name"] == "com.example.demo"
    assert sbom["source_artifact"]["filename"] == "demo.apk"
    assert sbom["statistics"]["declared_library_count"] == 1
    assert sbom["statistics"]["native_library_count"] == 1
    assert sbom["statistics"]["dex_unit_count"] == 2
    assert sbom["statistics"]["file_count"] == 5
    assert any(component["type"] == "application" for component in sbom["components"])
    assert any(component["type"] == "library" and component["name"] == "com.squareup.okio:okio" for component in sbom["components"])
    assert any(component["type"] == "native-library" and component["name"] == "libcrypto" for component in sbom["components"])
    assert any(component["properties"].get("role") == "manifest" for component in sbom["components"])
    assert any(relationship["type"] == "depends_on" for relationship in sbom["relationships"])
    assert any(relationship["type"] == "contains" for relationship in sbom["relationships"])


def test_generate_without_archive_still_returns_metadata_inventory():
    metadata = {
        "package_name": "com.example.partial",
        "version_name": "2.0.0",
        "libraries": ["androidx.core:core-ktx:1.13.1"],
    }

    sbom = SBOMService().generate(metadata, None)

    assert sbom["status"] == "partial"
    assert sbom["generator"] == "local-apk-sbom"
    assert sbom["statistics"]["declared_library_count"] == 1
    assert any(component["type"] == "application" for component in sbom["components"])
    assert any(component["type"] == "library" for component in sbom["components"])
