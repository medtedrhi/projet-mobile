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


def test_mobixler_dynamic_mapping_uses_runtime_signals():
    service = MappingService(Path("app/mappings"))
    evidence_item = SimpleNamespace(
        evidence_type="mobixler_dynamic",
        tags="mobixler_dynamic",
        original_filename="mobixler_dynamic.json",
        description="Mobixler dynamic analysis export",
        anonymized_flag=False,
    )

    result = service.map_evidence_item(
        evidence_item,
        payload={
            "findings": [
                {
                    "severity": "medium",
                    "title": "Cleartext HTTP request observed after login",
                    "evidence": "Session token sent in request to http://example.test/profile",
                },
                {
                    "severity": "low",
                    "title": "SQLite database stores personal account data",
                    "evidence": "email and phone values observed in local database",
                },
            ]
        },
    )

    assert result["status"] == "mapped"
    assert "MASVS-RESILIENCE-1" in result["masvs"]
    assert "MASVS-NETWORK-1" in result["masvs"]
    assert "MASVS-AUTH-1" in result["masvs"]
    assert "MASVS-PRIVACY-1" in result["masvs"]
    assert "MASWE-0050" in result["maswe"]
    assert "MASWE-0007" in result["maswe"]
    assert "MASTG-TEST-0001" in result["mastg"]
    assert "MASTG-TEST-0286" in result["mastg"]
    assert "mobixler-dynamic-import-present" in result["matched_signals"]
    assert "mobixler-network-signals" in result["matched_signals"]
    assert "mobixler-auth-signals" in result["matched_signals"]
    assert "mobixler-privacy-storage-signals" in result["matched_signals"]
    assert "runtime findings" in result["notes"]
