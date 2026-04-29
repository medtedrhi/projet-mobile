from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree
from zipfile import ZipFile

try:
    from androguard.core.apk import APK
except Exception:  # pragma: no cover
    APK = None

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class ApkParserService:
    """Parse APK metadata using androguard when available, with a defensive fallback."""

    def parse(self, apk_path: Path) -> dict:
        metadata = {
            "package_name": None,
            "version_name": None,
            "version_code": None,
            "min_sdk": None,
            "target_sdk": None,
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "permissions": [],
            "exported_components": [],
            "embedded_domains": [],
            "libraries": [],
            "manifest_xml": None,
            "network_security_config": None,
            "cleartext_traffic_allowed": None,
            "debuggable": None,
            "allow_backup": None,
            "manifest_summary": "Manifest parsing unavailable.",
        }

        if APK is not None:
            apk = APK(str(apk_path))
            manifest_xml = apk.get_android_manifest_xml()
            manifest_xml_text = self._to_xml_text(manifest_xml)
            application = self._find_application(manifest_xml)
            network_security_config = None
            cleartext_traffic_allowed = None
            if application is not None and hasattr(application, "get"):
                network_security_config = application.get(f"{{{ANDROID_NS}}}networkSecurityConfig")
                cleartext_traffic_allowed = application.get(f"{{{ANDROID_NS}}}usesCleartextTraffic")
                debuggable = application.get(f"{{{ANDROID_NS}}}debuggable")
                allow_backup = application.get(f"{{{ANDROID_NS}}}allowBackup")
            else:
                debuggable = None
                allow_backup = None
            metadata.update(
                {
                    "package_name": apk.get_package(),
                    "version_name": apk.get_androidversion_name(),
                    "version_code": apk.get_androidversion_code(),
                    "min_sdk": apk.get_min_sdk_version(),
                    "target_sdk": apk.get_target_sdk_version(),
                    "permissions": sorted(set(apk.get_permissions())),
                    "libraries": sorted(set(apk.get_libraries() or [])),
                    "manifest_xml": manifest_xml_text,
                    "network_security_config": network_security_config,
                    "cleartext_traffic_allowed": cleartext_traffic_allowed,
                    "debuggable": debuggable,
                    "allow_backup": allow_backup,
                    "manifest_summary": (
                        f"Package {apk.get_package()} targets SDK {apk.get_target_sdk_version()} "
                        f"and declares {len(apk.get_permissions())} permissions."
                    ),
                }
            )
            components = self._extract_manifest_components(manifest_xml, apk.get_package())
            metadata.update(
                {
                    "activities": components["activities"] or sorted(set(apk.get_activities() or [])),
                    "services": components["services"] or sorted(set(apk.get_services() or [])),
                    "receivers": components["receivers"] or sorted(set(apk.get_receivers() or [])),
                    "providers": components["providers"] or sorted(set(apk.get_providers() or [])),
                    "exported_components": components["exported_components"],
                }
            )
            metadata["embedded_domains"] = sorted(set(self._extract_domains(manifest_xml_text)))
            return metadata

        with ZipFile(apk_path) as archive:
            names = archive.namelist()
            metadata["embedded_domains"] = sorted(
                {entry for entry in names if entry.endswith((".so", ".dex", ".xml"))}
            )[:20]
            metadata["manifest_summary"] = "Fallback APK inspection succeeded; rich manifest fields unavailable."
        return metadata

    def _to_xml_text(self, manifest_xml: object) -> str:
        if manifest_xml is None:
            return ""
        try:
            from lxml import etree

            if isinstance(manifest_xml, etree._Element):
                return etree.tostring(
                    manifest_xml,
                    encoding="unicode",
                    pretty_print=True,
                    xml_declaration=False,
                ).strip()
        except Exception:
            pass
        if isinstance(manifest_xml, ElementTree.Element):
            ElementTree.register_namespace("android", ANDROID_NS)
            return ElementTree.tostring(manifest_xml, encoding="unicode", short_empty_elements=True)
        if hasattr(manifest_xml, "toprettyxml"):
            return manifest_xml.toprettyxml()
        if hasattr(manifest_xml, "decode"):
            try:
                return manifest_xml.decode("utf-8", errors="ignore")
            except TypeError:
                return str(manifest_xml)
        return str(manifest_xml)

    def _extract_domains(self, manifest_xml_text: str) -> list[str]:
        if not manifest_xml_text:
            return []
        pattern = re.compile(r"(?:https?://)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
        return sorted(set(match.group(1) for match in pattern.finditer(manifest_xml_text)))

    def _extract_manifest_components(self, manifest_xml: object, package_name: str | None) -> dict[str, list[str]]:
        components = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "exported_components": [],
        }
        if manifest_xml is None or not hasattr(manifest_xml, "iter"):
            return components

        component_tags = {
            "activity": "activities",
            "activity-alias": "activities",
            "service": "services",
            "receiver": "receivers",
            "provider": "providers",
        }
        for element in manifest_xml.iter():
            tag = self._local_name(getattr(element, "tag", ""))
            target = component_tags.get(tag)
            if target is None:
                continue

            name = self._component_name(element, package_name)
            if not name:
                continue
            components[target].append(name)

            if self._is_exported(element):
                components["exported_components"].append(f"{tag}:{name}")

        return {key: sorted(set(value)) for key, value in components.items()}

    def _find_application(self, manifest_xml: object) -> object | None:
        if manifest_xml is None or not hasattr(manifest_xml, "iter"):
            return None
        for element in manifest_xml.iter():
            if self._local_name(getattr(element, "tag", "")) == "application":
                return element
        return None

    def _component_name(self, element: object, package_name: str | None) -> str | None:
        if not hasattr(element, "get"):
            return None
        raw_name = element.get(f"{{{ANDROID_NS}}}name") or element.get("android:name") or element.get("name")
        if not raw_name:
            return None
        if raw_name.startswith(".") and package_name:
            return f"{package_name}{raw_name}"
        if "." not in raw_name and package_name:
            return f"{package_name}.{raw_name}"
        return raw_name

    def _is_exported(self, element: object) -> bool:
        if not hasattr(element, "get"):
            return False
        exported = element.get(f"{{{ANDROID_NS}}}exported") or element.get("android:exported")
        if exported is not None:
            return exported.lower() == "true"
        if hasattr(element, "find"):
            try:
                return element.find("intent-filter") is not None
            except SyntaxError:
                return False
        return False

    def _local_name(self, tag: object) -> str:
        tag_text = str(tag)
        if "}" in tag_text:
            return tag_text.rsplit("}", 1)[1]
        return tag_text
