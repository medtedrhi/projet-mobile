from __future__ import annotations

import csv
from pathlib import Path


class TraceabilityTableService:
    """Write a human-readable MASVS/MASTG traceability table."""

    FILE_BY_TYPE = {
        "apk": "01_apk",
        "apk_hash": "11_hashes/apk_hash.json",
        "manifest_summary": "02_manifest/manifest_summary.json",
        "manifest_xml": "02_manifest/AndroidManifest.xml",
        "permissions": "03_permissions/permissions.json",
        "components": "04_components/components.json",
        "sbom": "05_sbom/sbom.json",
        "screenshot": "07_screenshots",
        "log": "06_logs",
    }

    DESCRIPTION_BY_TYPE = {
        "apk": "Uploaded APK artifact",
        "apk_hash": "APK hash proof",
        "manifest_summary": "Manifest metadata summary",
        "manifest_xml": "Manifest extraction",
        "permissions": "Permissions analysis",
        "components": "Component exposure analysis",
        "sbom": "SBOM dependencies",
        "screenshot": "Screenshot evidence",
        "log": "Anonymized runtime logs",
    }

    def write_csv(self, export_dir: Path, traceability: list[dict]) -> Path:
        output_dir = export_dir / "09_mas_mapping"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "masvs_mastg_traceability.csv"

        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["Evidence ID", "File", "Description", "MASVS", "MASTG", "Status"],
            )
            writer.writeheader()
            for index, item in enumerate(traceability, start=1):
                writer.writerow(
                    {
                        "Evidence ID": f"EVD-{index:03d}",
                        "File": self._file_for(item),
                        "Description": self.DESCRIPTION_BY_TYPE.get(item.get("evidence_type"), item.get("original_filename") or "Evidence item"),
                        "MASVS": "; ".join(item.get("masvs") or []),
                        "MASTG": "; ".join(item.get("mastg") or []),
                        "Status": self._status_label(item.get("status")),
                    }
                )
        return output_path

    def _file_for(self, item: dict) -> str:
        evidence_type = item.get("evidence_type")
        mapped = self.FILE_BY_TYPE.get(evidence_type)
        if mapped and "/" in mapped:
            return mapped
        if mapped:
            filename = item.get("original_filename")
            return f"{mapped}/{filename}" if filename else mapped
        return item.get("original_filename") or ""

    def _status_label(self, status: str | None) -> str:
        if status == "mapped":
            return "OK"
        if status == "partially_mapped":
            return "PARTIAL"
        return "UNMAPPED"
