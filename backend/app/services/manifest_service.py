class ManifestService:
    def summarize(self, apk_metadata: dict) -> dict:
        return {
            "package": apk_metadata.get("package_name"),
            "version_name": apk_metadata.get("version_name"),
            "version_code": apk_metadata.get("version_code"),
            "min_sdk": apk_metadata.get("min_sdk"),
            "target_sdk": apk_metadata.get("target_sdk"),
            "activities": apk_metadata.get("activities", []),
            "services": apk_metadata.get("services", []),
            "receivers": apk_metadata.get("receivers", []),
            "providers": apk_metadata.get("providers", []),
            "exported_components": apk_metadata.get("exported_components", []),
            "summary": apk_metadata.get("manifest_summary"),
        }
