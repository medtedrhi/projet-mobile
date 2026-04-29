class PermissionsService:
    def extract(self, apk_metadata: dict) -> dict:
        permissions = apk_metadata.get("permissions", [])
        risk_markers = []
        for item in permissions:
            if any(keyword in item for keyword in ["SMS", "READ_CONTACTS", "CAMERA", "RECORD_AUDIO"]):
                risk_markers.append(item)
        return {"permissions": permissions, "sensitive_permissions": risk_markers}
