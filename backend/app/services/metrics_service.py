from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.db.models.evidence import EvidenceItem


class MetricsService:
    """Build compact numeric audit metrics from collected evidence."""

    DANGEROUS_PERMISSIONS = {
        "android.permission.ACCEPT_HANDOVER",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_MEDIA_LOCATION",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.BLUETOOTH_ADVERTISE",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BODY_SENSORS",
        "android.permission.CALL_PHONE",
        "android.permission.CAMERA",
        "android.permission.GET_ACCOUNTS",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_CALENDAR",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECORD_AUDIO",
        "android.permission.SEND_SMS",
        "android.permission.USE_SIP",
        "android.permission.WRITE_CALENDAR",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.WRITE_CONTACTS",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    }

    def build(self, evidence_items: list[EvidenceItem], completeness_percent: float) -> dict[str, Any]:
        payloads = {item.evidence_type: self._read_json(item) for item in evidence_items}
        manifest = payloads.get("manifest_summary") or {}
        permissions = payloads.get("permissions") or {}
        sbom = payloads.get("sbom") or {}

        apk_item = self._first_item(evidence_items, "apk")
        permission_list = permissions.get("permissions") or []
        sensitive_permissions = permissions.get("sensitive_permissions") or []
        dangerous_permissions_count = len(
            set(sensitive_permissions) | {permission for permission in permission_list if permission in self.DANGEROUS_PERMISSIONS}
        )

        return {
            "apk_size_mb": self._apk_size_mb(apk_item),
            "permissions_count": len(permission_list),
            "dangerous_permissions_count": dangerous_permissions_count,
            "activities_count": len(manifest.get("activities") or []),
            "services_count": len(manifest.get("services") or []),
            "receivers_count": len(manifest.get("receivers") or []),
            "providers_count": len(manifest.get("providers") or []),
            "exported_components_count": len(manifest.get("exported_components") or []),
            "sbom_components_count": len(sbom.get("components") or []),
            "screenshots_count": sum(1 for item in evidence_items if item.evidence_type == "screenshot"),
            "logs_lines_count": self._logs_lines_count(evidence_items),
            "anonymized_logs": any(item.evidence_type == "log" and bool(item.anonymized_flag) for item in evidence_items),
            "evidence_completeness_percent": round(float(completeness_percent), 2),
        }

    def _first_item(self, evidence_items: list[EvidenceItem], evidence_type: str) -> EvidenceItem | None:
        for item in evidence_items:
            if item.evidence_type == evidence_type:
                return item
        return None

    def _apk_size_mb(self, item: EvidenceItem | None) -> float:
        if item is None:
            return 0.0
        size = item.size
        path = Path(item.normalized_path)
        if not size and path.exists():
            size = path.stat().st_size
        return round((size or 0) / (1024 * 1024), 2)

    def _logs_lines_count(self, evidence_items: list[EvidenceItem]) -> int:
        count = 0
        for item in evidence_items:
            if item.evidence_type != "log":
                continue
            path = Path(item.normalized_path)
            if not path.exists():
                continue
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as handle:
                    count += sum(1 for _line in handle)
            except OSError:
                continue
        return count

    def _read_json(self, item: EvidenceItem) -> Any:
        path = Path(item.normalized_path)
        if not path.exists() or path.suffix.lower() != ".json":
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
