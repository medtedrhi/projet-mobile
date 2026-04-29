import json
from pathlib import Path
from types import SimpleNamespace

from app.services.metrics_service import MetricsService


def test_metrics_service_builds_expected_counts(tmp_path: Path):
    manifest_path = tmp_path / "manifest_summary.json"
    manifest_path.write_text(
        json.dumps(
            {
                "activities": ["MainActivity", "SettingsActivity"],
                "services": ["SyncService"],
                "receivers": [],
                "providers": ["InitProvider"],
                "exported_components": ["activity:MainActivity"],
            }
        ),
        encoding="utf-8",
    )
    permissions_path = tmp_path / "permissions.json"
    permissions_path.write_text(
        json.dumps({"permissions": ["android.permission.INTERNET", "android.permission.CAMERA"], "sensitive_permissions": []}),
        encoding="utf-8",
    )
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(json.dumps({"components": [{"name": "app"}, {"name": "classes.dex"}]}), encoding="utf-8")
    log_path = tmp_path / "runtime.log"
    log_path.write_text("one\ntwo\n", encoding="utf-8")

    items = [
        SimpleNamespace(evidence_type="apk", normalized_path=str(tmp_path / "app.apk"), size=1048576, anonymized_flag=False),
        SimpleNamespace(evidence_type="manifest_summary", normalized_path=str(manifest_path), size=manifest_path.stat().st_size, anonymized_flag=False),
        SimpleNamespace(evidence_type="permissions", normalized_path=str(permissions_path), size=permissions_path.stat().st_size, anonymized_flag=False),
        SimpleNamespace(evidence_type="sbom", normalized_path=str(sbom_path), size=sbom_path.stat().st_size, anonymized_flag=False),
        SimpleNamespace(evidence_type="screenshot", normalized_path=str(tmp_path / "screen.png"), size=10, anonymized_flag=False),
        SimpleNamespace(evidence_type="log", normalized_path=str(log_path), size=log_path.stat().st_size, anonymized_flag=True),
    ]

    metrics = MetricsService().build(items, 87.5)

    assert metrics["apk_size_mb"] == 1.0
    assert metrics["permissions_count"] == 2
    assert metrics["dangerous_permissions_count"] == 1
    assert metrics["activities_count"] == 2
    assert metrics["services_count"] == 1
    assert metrics["providers_count"] == 1
    assert metrics["exported_components_count"] == 1
    assert metrics["sbom_components_count"] == 2
    assert metrics["screenshots_count"] == 1
    assert metrics["logs_lines_count"] == 2
    assert metrics["anonymized_logs"] is True
    assert metrics["evidence_completeness_percent"] == 87.5
