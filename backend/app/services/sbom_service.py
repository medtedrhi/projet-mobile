from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
from zipfile import ZipFile


class SBOMService:
    """Generate a local APK-derived software inventory for audit evidence packs."""

    NATIVE_LIB_RE = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")
    DEX_RE = re.compile(r"^classes(\d*)\.dex$")

    def generate(self, apk_metadata: dict, apk_path: Path | None = None) -> dict:
        inventory = self._empty_inventory(apk_metadata, apk_path)
        components = inventory["components"]
        relationships = inventory["relationships"]

        application_ref = self._add_application_component(components, apk_metadata, apk_path)
        declared_refs = self._add_declared_libraries(components, relationships, application_ref, apk_metadata)

        if apk_path and apk_path.exists():
            archive_details = self._scan_archive(apk_path, application_ref, declared_refs)
            components.extend(archive_details["components"])
            relationships.extend(archive_details["relationships"])
            inventory["statistics"] = archive_details["statistics"]
            inventory["source_artifact"] = archive_details["source_artifact"]
            inventory["status"] = "generated"
            inventory["note"] = "SBOM inventory generated from APK metadata and archive contents."
        else:
            inventory["status"] = "partial"
            inventory["note"] = "SBOM inventory generated from APK metadata only because the APK archive was unavailable."

        inventory["statistics"]["component_count"] = len(components)
        inventory["statistics"]["relationship_count"] = len(relationships)
        return inventory

    def _empty_inventory(self, apk_metadata: dict, apk_path: Path | None) -> dict:
        package_name = apk_metadata.get("package_name") or (apk_path.stem if apk_path else "unknown-app")
        version = apk_metadata.get("version_name") or apk_metadata.get("version_code")
        return {
            "status": "partial",
            "generator": "local-apk-sbom",
            "format": "local-apk-sbom-v1",
            "subject": {
                "name": package_name,
                "version": version,
                "type": "application",
            },
            "source_artifact": None,
            "components": [],
            "relationships": [],
            "statistics": {
                "declared_library_count": 0,
                "native_library_count": 0,
                "dex_unit_count": 0,
                "top_level_directory_count": 0,
                "file_count": 0,
                "component_count": 0,
                "relationship_count": 0,
            },
            "note": "",
        }

    def _add_application_component(self, components: list[dict], apk_metadata: dict, apk_path: Path | None) -> str:
        package_name = apk_metadata.get("package_name") or (apk_path.stem if apk_path else "unknown-app")
        version = apk_metadata.get("version_name") or apk_metadata.get("version_code")
        component_ref = self._component_ref("application", package_name)
        components.append(
            {
                "bom_ref": component_ref,
                "type": "application",
                "name": package_name,
                "version": version,
                "properties": {
                    "package_name": apk_metadata.get("package_name"),
                    "version_code": apk_metadata.get("version_code"),
                    "min_sdk": apk_metadata.get("min_sdk"),
                    "target_sdk": apk_metadata.get("target_sdk"),
                },
            }
        )
        return component_ref

    def _add_declared_libraries(
        self,
        components: list[dict],
        relationships: list[dict],
        application_ref: str,
        apk_metadata: dict,
    ) -> set[str]:
        refs: set[str] = set()
        for library in sorted(set(apk_metadata.get("libraries", []))):
            name, version = self._split_library_version(library)
            component_ref = self._component_ref("declared-library", library)
            components.append(
                {
                    "bom_ref": component_ref,
                    "type": "library",
                    "name": name,
                    "version": version,
                    "evidence_source": "apk-metadata",
                    "properties": {"declared_identifier": library},
                }
            )
            relationships.append({"from": application_ref, "to": component_ref, "type": "depends_on"})
            refs.add(name)
        return refs

    def _scan_archive(self, apk_path: Path, application_ref: str, declared_refs: set[str]) -> dict:
        components: list[dict] = []
        relationships: list[dict] = []
        top_level_dirs: set[str] = set()
        native_count = 0
        dex_count = 0
        file_count = 0

        with ZipFile(apk_path) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            file_count = len(infos)
            source_artifact = {
                "filename": apk_path.name,
                "size": apk_path.stat().st_size,
                "sha256": self._hash_file(apk_path),
            }

            for info in infos:
                top_level = info.filename.split("/", 1)[0]
                top_level_dirs.add(top_level)

                native_match = self.NATIVE_LIB_RE.match(info.filename)
                if native_match:
                    abi, filename = native_match.groups()
                    native_name = filename.removesuffix(".so")
                    component_ref = self._component_ref("native-library", f"{abi}:{native_name}")
                    components.append(
                        {
                            "bom_ref": component_ref,
                            "type": "native-library",
                            "name": native_name,
                            "version": None,
                            "evidence_source": "apk-archive",
                            "properties": {
                                "path": info.filename,
                                "abi": abi,
                                "size": info.file_size,
                            },
                        }
                    )
                    relationships.append({"from": application_ref, "to": component_ref, "type": "contains"})
                    native_count += 1
                    continue

                dex_match = self.DEX_RE.match(info.filename)
                if dex_match:
                    dex_index = dex_match.group(1) or "1"
                    component_ref = self._component_ref("dex-unit", f"classes{dex_index}")
                    components.append(
                        {
                            "bom_ref": component_ref,
                            "type": "file",
                            "name": info.filename,
                            "version": None,
                            "evidence_source": "apk-archive",
                            "properties": {
                                "path": info.filename,
                                "role": "dex-unit",
                                "size": info.file_size,
                            },
                        }
                    )
                    relationships.append({"from": application_ref, "to": component_ref, "type": "contains"})
                    dex_count += 1
                    continue

                if info.filename == "AndroidManifest.xml":
                    component_ref = self._component_ref("manifest", info.filename)
                    components.append(
                        {
                            "bom_ref": component_ref,
                            "type": "file",
                            "name": info.filename,
                            "version": None,
                            "evidence_source": "apk-archive",
                            "properties": {
                                "path": info.filename,
                                "role": "manifest",
                                "size": info.file_size,
                            },
                        }
                    )
                    relationships.append({"from": application_ref, "to": component_ref, "type": "contains"})

        return {
            "components": self._deduplicate_components(components),
            "relationships": self._deduplicate_relationships(relationships),
            "statistics": {
                "declared_library_count": len(declared_refs),
                "native_library_count": native_count,
                "dex_unit_count": dex_count,
                "top_level_directory_count": len(top_level_dirs),
                "file_count": file_count,
            },
            "source_artifact": source_artifact,
        }

    def _deduplicate_components(self, components: list[dict]) -> list[dict]:
        unique: dict[str, dict] = {}
        for component in components:
            unique.setdefault(component["bom_ref"], component)
        return list(unique.values())

    def _deduplicate_relationships(self, relationships: list[dict]) -> list[dict]:
        seen: set[tuple[str, str, str]] = set()
        unique: list[dict] = []
        for relationship in relationships:
            key = (relationship["from"], relationship["to"], relationship["type"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(relationship)
        return unique

    def _hash_file(self, path: Path) -> str:
        digest = sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _component_ref(self, prefix: str, value: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9._:-]+", "-", value).strip("-")
        return f"{prefix}:{normalized or 'component'}"

    def _split_library_version(self, library: str) -> tuple[str, str | None]:
        if ":" in library:
            name, version = library.rsplit(":", 1)
            return name, version
        return library, None
