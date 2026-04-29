import json
from pathlib import Path

from app.services.apk_parser import ApkParserService
from app.services.config_extraction_service import ConfigExtractionService
from app.services.hash_service import HashService
from app.services.manifest_service import ManifestService
from app.services.permissions_service import PermissionsService
from app.services.sbom_service import SBOMService


class EvidenceCollectorService:
    """Collect raw and normalized evidence artifacts from an uploaded APK."""

    def __init__(self):
        self.hash_service = HashService()
        self.apk_parser = ApkParserService()
        self.config_extraction_service = ConfigExtractionService()
        self.manifest_service = ManifestService()
        self.permissions_service = PermissionsService()
        self.sbom_service = SBOMService()

    def collect_from_apk(self, apk_path: Path) -> list[dict]:
        hashes = self.hash_service.hash_file(apk_path)
        apk_metadata = self.apk_parser.parse(apk_path)
        manifest_summary = self.manifest_service.summarize(apk_metadata)
        permissions = self.permissions_service.extract(apk_metadata)
        components = {
            "exported_components": apk_metadata.get("exported_components", []),
            "embedded_domains": apk_metadata.get("embedded_domains", []),
            "network_security_config": apk_metadata.get("network_security_config"),
            "cleartext_traffic_allowed": apk_metadata.get("cleartext_traffic_allowed"),
        }
        sbom = self.sbom_service.generate(apk_metadata, apk_path)
        manifest_xml = apk_metadata.get("manifest_xml") or "<manifest />"
        config_items = self.config_extraction_service.extract(apk_path, apk_metadata)

        items = [
            {
                "evidence_type": "apk_hash",
                "payload": hashes,
                "filename": "apk_hash.json",
                "mime_type": "application/json",
                "description": "APK integrity hashes",
            },
            {
                "evidence_type": "manifest_summary",
                "payload": manifest_summary,
                "filename": "manifest_summary.json",
                "mime_type": "application/json",
                "description": "Normalized AndroidManifest summary",
            },
            {
                "evidence_type": "manifest_xml",
                "payload": manifest_xml,
                "filename": "AndroidManifest.xml",
                "mime_type": "application/xml",
                "description": "Raw extracted Android manifest XML",
            },
            {
                "evidence_type": "permissions",
                "payload": permissions,
                "filename": "permissions.json",
                "mime_type": "application/json",
                "description": "Permission inventory and sensitive permission hints",
            },
            {
                "evidence_type": "components",
                "payload": components,
                "filename": "components.json",
                "mime_type": "application/json",
                "description": "Exported component and endpoint summary",
            },
            {
                "evidence_type": "sbom",
                "payload": sbom,
                "filename": "sbom.json",
                "mime_type": "application/json",
                "description": "Dependency and component inventory",
            },
        ]
        items.extend(config_items)
        return items

    def write_payload(self, base_dir: Path, item: dict) -> Path:
        output_path = base_dir / item["filename"]
        payload = item["payload"]
        if item["mime_type"] == "application/json":
            output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        else:
            output_path.write_text(str(payload), encoding="utf-8")
        return output_path
