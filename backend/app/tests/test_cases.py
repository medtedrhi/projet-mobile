from io import BytesIO


def test_create_case(client):
    response = client.post(
        "/api/cases",
        json={
            "app_name": "Demo App",
            "package_name": "com.demo.app",
            "version_name": "1.0.0",
            "version_code": "100",
            "auditor": "QA Analyst",
            "audit_date": "2026-04-06",
            "scope": "MASVS baseline review",
            "notes": "Seed case",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["app_name"] == "Demo App"


def test_upload_log_sanitizes(client):
    case_resp = client.post(
        "/api/cases",
        json={
            "app_name": "Log App",
            "package_name": "com.demo.log",
            "version_name": "1.0.0",
            "version_code": "1",
            "auditor": "QA Analyst",
            "audit_date": "2026-04-06",
            "scope": "Runtime evidence",
            "notes": None,
        },
    )
    case_id = case_resp.json()["id"]
    upload_resp = client.post(
        f"/api/cases/{case_id}/upload",
        data={"artifact_type": "log", "source": "runtime"},
        files={"file": ("runtime.log", BytesIO(b"user=test@example.com token=Bearer secretsecretsecret123"), "text/plain")},
    )
    assert upload_resp.status_code == 200
    evidence_resp = client.get(f"/api/cases/{case_id}/evidence")
    assert evidence_resp.status_code == 200
    assert any(item["evidence_type"] == "log" for item in evidence_resp.json())


def test_list_android_devices(client, monkeypatch):
    monkeypatch.setattr(
        "app.api.routes.uploads.case_service.list_connected_android_devices",
        lambda: [
            {
                "serial": "emulator-5554",
                "state": "device",
                "model": "Pixel_8",
                "product": "sdk_gphone64",
                "device": "emu64",
                "transport_id": "1",
            }
        ],
    )

    response = client.get("/api/android-devices")
    assert response.status_code == 200
    payload = response.json()
    assert payload[0]["serial"] == "emulator-5554"
    assert payload[0]["state"] == "device"


def test_capture_screenshot_creates_screenshot_evidence(client, monkeypatch):
    from app.api.routes import uploads as uploads_routes

    case_resp = client.post(
        "/api/cases",
        json={
            "app_name": "Capture App",
            "package_name": "com.demo.capture",
            "version_name": "1.0.0",
            "version_code": "1",
            "auditor": "QA Analyst",
            "audit_date": "2026-04-06",
            "scope": "UI screenshot evidence",
            "notes": None,
        },
    )
    case_id = case_resp.json()["id"]

    def fake_capture_screenshot(db, case_id, device_serial=None, source="adb-capture", description=None):
        return uploads_routes.case_service._persist_artifact(
            db=db,
            case_id=case_id,
            artifact_type="screenshot",
            source=source,
            original_filename="auto_screenshot_emulator-5554.png",
            content=b"\x89PNG\r\n\x1a\nmockpng",
            mime_type="image/png",
            description=description or "Automated UI screenshot captured via adb from emulator-5554.",
            anonymized=False,
        )

    monkeypatch.setattr("app.api.routes.uploads.case_service.capture_screenshot", fake_capture_screenshot)

    response = client.post(
        f"/api/cases/{case_id}/capture-screenshot?device_serial=emulator-5554",
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["artifact_type"] == "screenshot"
    assert payload["mime_type"] == "image/png"

    evidence_resp = client.get(f"/api/cases/{case_id}/evidence")
    assert evidence_resp.status_code == 200
    assert any(item["evidence_type"] == "screenshot" for item in evidence_resp.json())


def test_run_dynamic_analysis_creates_mobixler_dynamic_evidence(client, monkeypatch):
    from app.api.routes import uploads as uploads_routes

    case_resp = client.post(
        "/api/cases",
        json={
            "app_name": "Dynamic App",
            "package_name": "com.demo.dynamic",
            "version_name": "1.0.0",
            "version_code": "1",
            "auditor": "QA Analyst",
            "audit_date": "2026-04-06",
            "scope": "Dynamic APK analysis",
            "notes": None,
        },
    )
    case_id = case_resp.json()["id"]

    def fake_run_dynamic_apk_analysis(
        db,
        case_id,
        device_serial=None,
        source="adb-dynamic-analysis",
        monkey_event_count=None,
        log_line_count=None,
    ):
        return uploads_routes.case_service._persist_artifact(
            db=db,
            case_id=case_id,
            artifact_type="mobixler_dynamic",
            source=source,
            original_filename="mobixler_dynamic_emulator-5554.json",
            content=b'{"findings":[{"title":"Cleartext http request after login"}]}',
            mime_type="application/json",
            description="Mobixler-style dynamic APK analysis for com.demo.dynamic.",
            anonymized=True,
        )

    monkeypatch.setattr("app.api.routes.uploads.case_service.run_dynamic_apk_analysis", fake_run_dynamic_apk_analysis)

    response = client.post(
        f"/api/cases/{case_id}/run-dynamic-analysis?device_serial=emulator-5554&monkey_event_count=20",
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["artifact_type"] == "mobixler_dynamic"
    assert payload["mime_type"] == "application/json"

    evidence_resp = client.get(f"/api/cases/{case_id}/evidence")
    assert evidence_resp.status_code == 200
    assert any(item["evidence_type"] == "mobixler_dynamic" for item in evidence_resp.json())
