import csv
from pathlib import Path

from app.services.traceability_table_service import TraceabilityTableService


def test_traceability_table_writes_clear_csv(tmp_path: Path):
    traceability = [
        {
            "evidence_type": "apk_hash",
            "original_filename": "apk_hash.json",
            "masvs": ["MASVS-RESILIENCE-1"],
            "mastg": ["MASTG-KNOW-0011"],
            "status": "mapped",
        },
        {
            "evidence_type": "manifest_xml",
            "original_filename": "AndroidManifest.xml",
            "masvs": ["MASVS-PLATFORM-1"],
            "mastg": ["MASTG-TEST-0026"],
            "status": "mapped",
        },
    ]

    output = TraceabilityTableService().write_csv(tmp_path, traceability)

    with output.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert rows[0]["Evidence ID"] == "EVD-001"
    assert rows[0]["File"] == "11_hashes/apk_hash.json"
    assert rows[0]["Description"] == "APK hash proof"
    assert rows[0]["MASVS"] == "MASVS-RESILIENCE-1"
    assert rows[0]["MASTG"] == "MASTG-KNOW-0011"
    assert rows[0]["Status"] == "OK"
    assert rows[1]["File"] == "02_manifest/AndroidManifest.xml"
