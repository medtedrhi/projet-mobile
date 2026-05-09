from types import SimpleNamespace

import pytest

from app.services.android_capture_service import AndroidCaptureService


def test_capture_runtime_logs_returns_text_payload(monkeypatch):
    service = AndroidCaptureService(runtime_log_line_count=250)

    monkeypatch.setattr(service, "_default_device_serial", lambda: "emulator-5554")
    monkeypatch.setattr(
        service,
        "_run",
        lambda args, text=True, timeout_seconds=None: SimpleNamespace(stdout="04-22 12:00:00.000 I Demo: hello world\n"),
    )

    payload, metadata = service.capture_runtime_logs()

    assert payload.decode("utf-8") == "04-22 12:00:00.000 I Demo: hello world"
    assert metadata["device_serial"] == "emulator-5554"
    assert metadata["filename"] == "runtime_log_emulator-5554.log"
    assert metadata["mime_type"] == "text/plain"
    assert metadata["line_count"] == "250"


def test_capture_runtime_logs_rejects_empty_payload(monkeypatch):
    service = AndroidCaptureService()

    monkeypatch.setattr(service, "_default_device_serial", lambda: "emulator-5554")
    monkeypatch.setattr(
        service,
        "_run",
        lambda args, text=True, timeout_seconds=None: SimpleNamespace(stdout="   "),
    )

    with pytest.raises(ValueError, match="returned no runtime logs"):
        service.capture_runtime_logs()


def test_run_dynamic_apk_analysis_collects_runtime_payload(tmp_path, monkeypatch):
    service = AndroidCaptureService(runtime_log_line_count=250)
    apk_path = tmp_path / "demo.apk"
    apk_path.write_bytes(b"apk")

    monkeypatch.setattr(service, "_default_device_serial", lambda: "emulator-5554")

    def fake_run(args, text=True, timeout_seconds=None):
        joined = " ".join(args)
        if "exec-out screencap -p" in joined:
            return SimpleNamespace(stdout=b"\x89PNG\r\n\x1a\nmockpng")
        if "logcat -d" in joined:
            return SimpleNamespace(stdout="I Demo: login token sent to http://example.test/profile sqlite database\n")
        if "dumpsys package" in joined:
            return SimpleNamespace(stdout="Package [com.demo.app]")
        if "dumpsys activity top" in joined:
            return SimpleNamespace(stdout="ACTIVITY com.demo.app/.MainActivity")
        if "dumpsys meminfo" in joined:
            return SimpleNamespace(stdout="Applications Memory Usage")
        if "ps -A" in joined:
            return SimpleNamespace(stdout="u0_a123 com.demo.app")
        if "cat /proc/net/tcp" in joined:
            return SimpleNamespace(stdout="sl local_address rem_address")
        if "getprop ro.product.model" in joined:
            return SimpleNamespace(stdout="Pixel_8")
        if "getprop ro.build.version.release" in joined:
            return SimpleNamespace(stdout="14")
        if "getprop ro.build.version.sdk" in joined:
            return SimpleNamespace(stdout="34")
        return SimpleNamespace(stdout="OK")

    monkeypatch.setattr(service, "_run", fake_run)

    payload, metadata = service.run_dynamic_apk_analysis(apk_path, "com.demo.app")
    text = payload.decode("utf-8")

    assert metadata["filename"] == "mobixler_dynamic_emulator-5554.json"
    assert metadata["mime_type"] == "application/json"
    assert '"package_name": "com.demo.app"' in text
    assert "network-runtime-signals" in text
    assert "auth-session-runtime-signals" in text
    assert "privacy-storage-runtime-signals" in text
