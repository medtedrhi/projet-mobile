from xml.etree import ElementTree

from app.services.apk_parser import ANDROID_NS, ApkParserService
from app.services.manifest_service import ManifestService


def test_manifest_xml_serializes_element_tree():
    manifest = ElementTree.Element("manifest", {"package": "com.example.getudiant"})
    ElementTree.SubElement(manifest, "uses-permission", {f"{{{ANDROID_NS}}}name": "android.permission.INTERNET"})

    xml_text = ApkParserService()._to_xml_text(manifest)

    assert xml_text.startswith('<manifest xmlns:android="http://schemas.android.com/apk/res/android"')
    assert 'package="com.example.getudiant"' in xml_text
    assert 'android:name="android.permission.INTERNET"' in xml_text
    assert "<Element manifest at" not in xml_text


def test_manifest_summary_uses_requested_schema():
    summary = ManifestService().summarize(
        {
            "package_name": "com.example.getudiant",
            "version_name": "1.0",
            "version_code": "1",
            "min_sdk": "24",
            "target_sdk": "36",
            "activities": ["com.example.getudiant.AddEtudiant"],
            "services": [],
            "receivers": [],
            "providers": [],
            "exported_components": ["activity:com.example.getudiant.AddEtudiant"],
        }
    )

    assert summary["package"] == "com.example.getudiant"
    assert summary["activities"] == ["com.example.getudiant.AddEtudiant"]
    assert summary["exported_components"] == ["activity:com.example.getudiant.AddEtudiant"]
