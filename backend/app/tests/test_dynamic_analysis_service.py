from __future__ import annotations

from types import SimpleNamespace
from zipfile import ZipFile

from app.services.dynamic_analysis_service import (
    DynamicAnalysisService,
    best_top_activity_excerpt,
    detect_crash_anr,
    is_target_foreground,
    parse_foreground_activity,
)
from app.services.export_service import ExportService
from app.services.case_service import CaseService


PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x00IEND\xaeB`\x82"


class FakeAndroidCapture:
    def __init__(self, devices=None, fail_install=False, foreground_outputs=None):
        self.devices = devices if devices is not None else [{"serial": "emulator-5554", "state": "device", "model": "Pixel"}]
        self.fail_install = fail_install
        self.foreground_outputs = list(
            foreground_outputs
            if foreground_outputs is not None
            else ["mResumedActivity: ActivityRecord{123 u0 com.demo/.MainActivity t45}"] * 10
        )

    def list_devices(self):
        return self.devices

    def _device_args(self, device_serial):
        return ["-s", device_serial]

    def _run(self, args, text=True, timeout_seconds=None):
        joined = " ".join(args)
        if "install -r -t" in joined:
            if self.fail_install:
                raise ValueError("adb command failed: INSTALL_FAILED_INVALID_APK")
            return SimpleNamespace(stdout="Success")
        if "exec-out screencap -p" in joined:
            return SimpleNamespace(stdout=PNG)
        if "logcat -d" in joined:
            return SimpleNamespace(stdout="I Demo: running\nE AndroidRuntime: FATAL EXCEPTION: main\njava.lang.RuntimeException: boom")
        if "dumpsys activity activities" in joined:
            output = self.foreground_outputs.pop(0) if self.foreground_outputs else "mResumedActivity: ActivityRecord{123 u0 com.demo/.MainActivity t45}"
            return SimpleNamespace(stdout=output)
        if "dumpsys window windows" in joined:
            return SimpleNamespace(stdout="mCurrentFocus=Window{abc u0 com.demo/com.demo.MainActivity}")
        if "dumpsys activity top" in joined:
            return SimpleNamespace(stdout="ACTIVITY com.demo/.MainActivity")
        if "dumpsys meminfo" in joined:
            return SimpleNamespace(stdout="Applications Memory Usage")
        if "ps -A" in joined:
            return SimpleNamespace(stdout="u0_a123 com.demo")
        if "cat /proc/net/tcp" in joined:
            return SimpleNamespace(stdout="sl local_address rem_address")
        if "ro.product.model" in joined:
            return SimpleNamespace(stdout="Pixel_8")
        if "ro.build.version.release" in joined:
            return SimpleNamespace(stdout="14")
        if "ro.build.version.sdk" in joined:
            return SimpleNamespace(stdout="34")
        return SimpleNamespace(stdout="OK")


def test_crash_detection_parser_flags_crash_and_anr():
    result = detect_crash_anr("FATAL EXCEPTION\nApplication Not Responding: com.demo\nsignal 11")

    assert result["crash_detected"] is True
    assert result["anr_detected"] is True
    assert result["excerpts"]


def test_parse_mresumed_activity():
    info = parse_foreground_activity(
        "mResumedActivity: ActivityRecord{123 u0 com.example.jnidemo/.MainActivity t45}",
        "dumpsys activity activities",
        "com.example.jnidemo",
    )

    assert info["package"] == "com.example.jnidemo"
    assert info["component"] == "com.example.jnidemo/.MainActivity"
    assert info["is_target_package"] is True


def test_parse_top_resumed_activity():
    info = parse_foreground_activity(
        "topResumedActivity=ActivityRecord{123 u0 com.example.jnidemo/.MainActivity t45}",
        "dumpsys activity activities",
        "com.example.jnidemo",
    )

    assert info["component"] == "com.example.jnidemo/.MainActivity"


def test_parse_current_focus():
    info = parse_foreground_activity(
        "mCurrentFocus=Window{abc u0 com.google.android.apps.nexuslauncher/com.google.android.apps.nexuslauncher.NexusLauncherActivity}",
        "dumpsys window windows",
        "com.example.jnidemo",
    )

    assert info["package"] == "com.google.android.apps.nexuslauncher"
    assert info["is_target_package"] is False


def test_detecting_target_package_from_component():
    assert is_target_foreground(
        {"package": None, "component": "com.example.jnidemo/com.example.jnidemo.MainActivity", "raw_excerpt": ""},
        "com.example.jnidemo",
    )


def test_dynamic_analysis_result_collects_artifacts(tmp_path):
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"apk")
    service = DynamicAnalysisService(android_capture=FakeAndroidCapture())
    service.settings.uploads_dir = tmp_path

    result = service.run_full_dynamic_analysis(
        apk_path=apk,
        package_name="com.demo",
        case_id="case-1",
        monkey_event_count=3,
        log_line_count=50,
        wait_after_launch_seconds=0,
    )

    assert result.install_ok is True
    assert result.launch_ok is True
    assert result.execution["screenshots_captured"] == 3
    assert result.runtime["process_present"] is True
    assert result.runtime["crash_detected"] is True
    assert result.runtime["activity_tracking"]["was_target_foreground_after_launch"] is True
    assert {artifact.filename for artifact in result.artifacts} >= {
        "001_after_launch.png",
        "002_after_monkey.png",
        "003_final_state.png",
        "runtime_logcat_sanitized.log",
        "mobisef_dynamic.json",
        "runtime_state.json",
        "crash_summary.json",
    }


def test_monkey_left_app_and_final_refocus_success(tmp_path):
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"apk")
    launcher = "mCurrentFocus=Window{abc u0 com.google.android.apps.nexuslauncher/com.google.android.apps.nexuslauncher.NexusLauncherActivity}"
    target = "mResumedActivity: ActivityRecord{123 u0 com.demo/.MainActivity t45}"
    service = DynamicAnalysisService(android_capture=FakeAndroidCapture(foreground_outputs=[target, target, launcher, target]))
    service.settings.uploads_dir = tmp_path

    result = service.run_full_dynamic_analysis(apk, "com.demo", "case-1", monkey_event_count=3, wait_after_launch_seconds=0)
    tracking = result.runtime["activity_tracking"]

    assert tracking["monkey_left_app"] is True
    assert tracking["refocus_attempted_after_monkey"] is True
    assert tracking["was_target_foreground_final"] is True
    assert tracking["refocus_success"] is True


def test_top_activity_excerpt_prefers_target_launch_over_launcher_final():
    target = {"raw_excerpt": "target launch activity", "is_target_package": True}
    launcher = {"raw_excerpt": "launcher final activity", "is_target_package": False}

    assert best_top_activity_excerpt(
        {
            "target_activity_after_launch": target,
            "foreground_activity_final": launcher,
            "foreground_activity_after_monkey": launcher,
        }
    ) == "target launch activity"


def test_dynamic_analysis_returns_no_device_error(tmp_path):
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"apk")
    service = DynamicAnalysisService(android_capture=FakeAndroidCapture(devices=[]))
    service.settings.uploads_dir = tmp_path

    result = service.run_full_dynamic_analysis(apk, "com.demo", "case-1", wait_after_launch_seconds=0)

    assert result.install_ok is False
    assert "No Android emulator/device connected" in result.errors[0]


def test_dynamic_analysis_install_failure_stops_run(tmp_path):
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"apk")
    service = DynamicAnalysisService(android_capture=FakeAndroidCapture(fail_install=True))
    service.settings.uploads_dir = tmp_path

    result = service.run_full_dynamic_analysis(apk, "com.demo", "case-1", wait_after_launch_seconds=0)

    assert result.install_ok is False
    assert any("APK install failed" in error for error in result.errors)
    assert not any(artifact.filename == "001_after_launch.png" for artifact in result.artifacts)


def test_export_zip_uses_audit_evidence_root(tmp_path):
    export_dir = tmp_path / "case-export"
    service = ExportService()
    service.build_evidence_tree(export_dir)
    (export_dir / "08_findings_import" / "mobisef_dynamic.json").write_text("{}", encoding="utf-8")

    zip_path = tmp_path / "pack.zip"
    service.zip_directory(export_dir, zip_path)

    with ZipFile(zip_path) as archive:
        assert "audit-evidence/08_findings_import/mobisef_dynamic.json" in archive.namelist()


def test_ai_fallback_summary_generation(tmp_path, monkeypatch):
    service = CaseService()
    monkeypatch.setattr(service.summary_provider.reasoner, "complete", lambda **kwargs: None)
    case = SimpleNamespace(app_name="Demo", package_name="com.demo")
    context = {
        "case": case,
        "summary": {"artifact_type_counts": {"apk": 1, "screenshot": 3, "log": 4}},
        "details": {
            "imports": [
                {
                    "type": "mobixler_dynamic",
                    "payload": {
                        "target": {"package_name": "com.demo"},
                        "execution": {"install_ok": True, "launch_ok": True, "screenshots_captured": 3, "logs_captured": True},
                        "runtime": {"crash_detected": False, "process_present": True},
                    },
                }
            ]
        },
    }

    summary = service._build_dynamic_ai_summary(context, tmp_path)

    assert "# AI Evidence Summary" in summary
    assert "Install: ok" in summary
    assert "Screenshots captured: 3" in summary
