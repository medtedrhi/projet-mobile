from pathlib import Path
from types import SimpleNamespace

from app.services.mapping_service import MappingService


def test_permissions_mapping_uses_payload_details():
    service = MappingService(Path("app/mappings"))
    evidence_item = SimpleNamespace(
        evidence_type="permissions",
        tags="permissions",
        original_filename="permissions.json",
        description="Permission inventory",
        anonymized_flag=False,
    )

    result = service.map_evidence_item(
        evidence_item,
        payload={
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.CAMERA",
            ],
            "sensitive_permissions": ["android.permission.CAMERA"],
        },
    )

    assert result["status"] == "mapped"
    assert "MASVS-PLATFORM-1" in result["masvs"]
    assert "MASVS-PRIVACY-1" in result["masvs"]
    assert "MASWE-0001" in result["maswe"]
    assert "MASTG-TEST-0027" in result["mastg"]
    assert "sensitive-permissions-present" in result["matched_signals"]
    assert "android.permission.CAMERA" in result["notes"]


def test_screenshot_mapping_uses_auth_context_in_description():
    service = MappingService(Path("app/mappings"))
    evidence_item = SimpleNamespace(
        evidence_type="screenshot",
        tags="screenshot",
        original_filename="login_screen.png",
        description="Automatic UI screenshot of login screen with username and password prompt.",
        anonymized_flag=False,
    )

    result = service.map_evidence_item(evidence_item)

    assert result["status"] == "mapped"
    assert "MASVS-AUTH-1" in result["masvs"]
    assert "MASWE-0102" in result["maswe"]
    assert "MASTG-KNOW-0019" in result["mastg"]
    assert "screenshot-auth-context" in result["matched_signals"]
    assert "authentication-related screen" in result["notes"]


def test_manifest_xml_mapping_detects_network_markers():
    service = MappingService(Path("app/mappings"))
    evidence_item = SimpleNamespace(
        evidence_type="manifest_xml",
        tags="manifest_xml",
        original_filename="AndroidManifest.xml",
        description="Raw extracted manifest",
        anonymized_flag=False,
    )

    result = service.map_evidence_item(
        evidence_item,
        raw_text="""
        <manifest package="com.example.app">
          <application
            android:usesCleartextTraffic="true"
            android:networkSecurityConfig="@xml/network_security_config">
            <activity android:exported="true" />
          </application>
        </manifest>
        """,
    )

    assert result["status"] == "mapped"
    assert "MASVS-PLATFORM-1" in result["masvs"]
    assert "MASVS-NETWORK-1" in result["masvs"]
    assert "MASWE-0058" in result["maswe"]
    assert "MASWE-0050" in result["maswe"]
    assert "MASTG-TEST-0286" in result["mastg"]
    assert "manifest-network-markers" in result["matched_signals"]
    assert "cleartext traffic enabled" in result["notes"]
