import csv
import json
from pathlib import Path


class EvidenceIndexService:
    """Write machine-readable evidence index artifacts for the export pack."""

    def write_indexes(self, export_dir: Path, evidence_items: list[dict], traceability: list[dict]) -> dict:
        export_dir.mkdir(parents=True, exist_ok=True)
        json_path = export_dir / "evidence_index.json"
        csv_path = export_dir / "evidence_index.csv"
        traceability_path = export_dir / "evidence_traceability.json"

        json_path.write_text(json.dumps(evidence_items, indent=2), encoding="utf-8")
        traceability_path.write_text(json.dumps(traceability, indent=2), encoding="utf-8")

        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "id",
                    "evidence_type",
                    "source",
                    "original_filename",
                    "normalized_path",
                    "hash_sha256",
                    "mime_type",
                    "size",
                    "sensitivity_level",
                    "status",
                ],
            )
            writer.writeheader()
            writer.writerows(evidence_items)

        return {
            "evidence_index_json": str(json_path),
            "evidence_index_csv": str(csv_path),
            "evidence_traceability_json": str(traceability_path),
        }
