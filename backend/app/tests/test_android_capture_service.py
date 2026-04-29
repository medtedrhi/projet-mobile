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
