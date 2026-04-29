from pathlib import Path

from app.services.tool_versions_service import ToolVersionsService


def test_tool_versions_schema(monkeypatch):
    service = ToolVersionsService()
    monkeypatch.setattr(service, "_run", lambda command: "not_found")
    monkeypatch.setattr(service, "_android_sdk_root", lambda: None)

    versions = service.collect()

    assert set(versions) == {
        "java_version",
        "gradle_version",
        "android_sdk_version",
        "adb_version",
        "python_version",
        "apktool_version",
        "jadx_version",
        "device_model",
        "android_version",
        "analysis_date",
    }
    assert versions["gradle_version"] == "not_found"
    assert versions["android_sdk_version"] == "not_found"
    assert versions["device_model"] == "not_found"


def test_android_sdk_version_uses_highest_platform(monkeypatch, tmp_path: Path):
    (tmp_path / "platforms" / "android-34").mkdir(parents=True)
    (tmp_path / "platforms" / "android-36").mkdir(parents=True)

    service = ToolVersionsService()
    monkeypatch.setattr(service, "_android_sdk_root", lambda: tmp_path)

    assert service._android_sdk_version() == "android-36"
