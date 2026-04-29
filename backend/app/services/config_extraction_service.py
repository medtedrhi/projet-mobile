from __future__ import annotations

import json
import re
from pathlib import Path
from zipfile import ZipFile

try:
    from androguard.core.apk import APK
    from androguard.core.axml import AXMLPrinter
except Exception:  # pragma: no cover
    APK = None
    AXMLPrinter = None


class ConfigExtractionService:
    """Extract APK configuration evidence into reviewable files."""

    NETWORK_CONFIG_CANDIDATES = (
        "res/xml/network_security_config.xml",
        "res/xml/network_security_config_debug.xml",
        "res/xml/network_security_config_release.xml",
    )
    FIREBASE_CANDIDATES = (
        "google-services.json",
        "res/raw/google_services.json",
        "assets/google-services.json",
        "assets/google_services.json",
    )
    SECRET_PATTERNS = (
        re.compile(r"(?i)(api[_-]?key|secret|token|client[_-]?secret|private[_-]?key)\s*[:=]\s*[\"']?[^\"'\s<>{}]{12,}"),
        re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    )

    def extract(self, apk_path: Path, apk_metadata: dict) -> list[dict]:
        files: dict[str, tuple[object, str]] = {}
        status = {
            "network_security_config": "not_found",
            "strings": "not_found",
            "build_config": "extracted",
            "firebase_config": "not_found",
            "hardcoded_secrets": "not_detected",
            "cleartext_traffic": "checked",
        }

        if apk_path.exists():
            files.update(self._extract_archive_configs(apk_path, status))
            strings_xml = self._extract_strings(apk_path, apk_metadata.get("package_name"))
            if strings_xml:
                files["strings.xml"] = (strings_xml, "application/xml")
                status["strings"] = "extracted"

        build_config = self._build_config(apk_metadata)
        files["build_config.json"] = (build_config, "application/json")

        firebase_config = self._firebase_from_strings(files.get("strings.xml", ("", ""))[0])
        if firebase_config:
            files["firebase_config.json"] = (firebase_config, "application/json")
            status["firebase_config"] = "extracted_from_strings"

        scanned_text = "\n".join(self._text_for_scan(content) for content, _mime in files.values())
        if self._detect_secrets(scanned_text):
            status["hardcoded_secrets"] = "detected"

        app_config_summary = {
            "package": apk_metadata.get("package_name"),
            "version_name": apk_metadata.get("version_name"),
            "version_code": apk_metadata.get("version_code"),
            "min_sdk": apk_metadata.get("min_sdk"),
            "target_sdk": apk_metadata.get("target_sdk"),
            "network_security_config": apk_metadata.get("network_security_config"),
            "cleartext_traffic_allowed": apk_metadata.get("cleartext_traffic_allowed"),
            "exported_components_count": len(apk_metadata.get("exported_components", [])),
            "status": status,
        }
        files["app_config_summary.json"] = (app_config_summary, "application/json")
        files["config_status.json"] = (status, "application/json")

        return [
            {
                "evidence_type": f"config_{Path(filename).stem}",
                "payload": content,
                "filename": filename,
                "mime_type": mime_type,
                "description": "Extracted APK configuration evidence",
            }
            for filename, (content, mime_type) in files.items()
        ]

    def _extract_archive_configs(self, apk_path: Path, status: dict[str, str]) -> dict[str, tuple[object, str]]:
        files: dict[str, tuple[object, str]] = {}
        with ZipFile(apk_path) as archive:
            names = set(archive.namelist())
            for candidate in self.NETWORK_CONFIG_CANDIDATES:
                if candidate in names:
                    files["network_security_config.xml"] = (
                        self._decode_xml(archive.read(candidate)),
                        "application/xml",
                    )
                    status["network_security_config"] = f"extracted:{candidate}"
                    break

            for candidate in self.FIREBASE_CANDIDATES:
                if candidate in names:
                    firebase_text = archive.read(candidate).decode("utf-8", errors="ignore")
                    files["firebase_config.json"] = (self._parse_json(firebase_text), "application/json")
                    status["firebase_config"] = f"extracted:{candidate}"
                    break
        return files

    def _extract_strings(self, apk_path: Path, package_name: str | None) -> str:
        if APK is None:
            return ""
        try:
            apk = APK(str(apk_path))
            resources = apk.get_android_resources()
            package = package_name or apk.get_package()
            strings = resources.get_string_resources(package)
        except Exception:
            return ""
        if isinstance(strings, bytes):
            return strings.decode("utf-8", errors="ignore")
        return str(strings) if strings else ""

    def _decode_xml(self, data: bytes) -> str:
        if data.lstrip().startswith(b"<"):
            return data.decode("utf-8", errors="ignore")
        if AXMLPrinter is None:
            return data.decode("utf-8", errors="ignore")
        try:
            return AXMLPrinter(data).get_xml().decode("utf-8", errors="ignore")
        except Exception:
            return data.decode("utf-8", errors="ignore")

    def _build_config(self, apk_metadata: dict) -> dict:
        return {
            "package": apk_metadata.get("package_name"),
            "version_name": apk_metadata.get("version_name"),
            "version_code": apk_metadata.get("version_code"),
            "min_sdk": apk_metadata.get("min_sdk"),
            "target_sdk": apk_metadata.get("target_sdk"),
            "debuggable": self._as_bool(apk_metadata.get("debuggable")),
            "allow_backup": self._as_bool(apk_metadata.get("allow_backup")),
            "uses_cleartext_traffic": self._as_bool(apk_metadata.get("cleartext_traffic_allowed")),
        }

    def _firebase_from_strings(self, strings_xml: str) -> dict:
        if not isinstance(strings_xml, str):
            return {}
        firebase_keys = (
            "google_app_id",
            "google_api_key",
            "firebase_database_url",
            "gcm_defaultSenderId",
            "google_storage_bucket",
            "project_id",
        )
        found: dict[str, str] = {}
        for key in firebase_keys:
            match = re.search(rf'<string\s+name="{re.escape(key)}"\s*>(.*?)</string>', strings_xml, re.DOTALL)
            if match:
                found[key] = match.group(1).strip()
        return found

    def _detect_secrets(self, text: str) -> bool:
        return any(pattern.search(text) for pattern in self.SECRET_PATTERNS)

    def _parse_json(self, text: str) -> object:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}

    def _text_for_scan(self, content: object) -> str:
        if isinstance(content, str):
            return content
        return json.dumps(content, sort_keys=True)

    def _as_bool(self, value: object) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        return str(value).lower() == "true"
