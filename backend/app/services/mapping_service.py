import json
from pathlib import Path
from typing import Any


class MappingService:
    """Build evidence-to-control traceability for MASVS, MASWE, and MASTG."""

    AUTH_HINTS = ("login", "sign in", "signin", "password", "credential", "otp", "session", "auth")
    PRIVACY_HINTS = ("profile", "account", "email", "phone", "personal", "privacy", "consent", "pii")
    CRYPTO_HINTS = ("crypto", "cipher", "keystore", "encrypt", "decrypt", "certificate", "tls", "ssl")
    IMPORT_HINTS = ("finding", "issue", "severity", "vulnerability", "rule", "warning")
    MOBIXLER_TYPES = {"mobixler", "mobixler_dynamic"}
    NETWORK_HINTS = ("http", "https", "tls", "ssl", "certificate", "proxy", "request", "response", "cleartext")
    STORAGE_HINTS = ("sqlite", "sharedpref", "shared preference", "database", "file", "sdcard", "external storage")

    def __init__(self, mappings_dir: Path):
        self.mappings_dir = mappings_dir
        self.masvs_map = self._load("masvs_map.json")
        self.maswe_map = self._load("maswe_map.json")
        self.mastg_map = self._load("mastg_map.json")

    def _load(self, filename: str) -> dict:
        with (self.mappings_dir / filename).open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def map_evidence(self, evidence_type: str, tags: list[str] | None = None) -> dict[str, list[str]]:
        tags = tags or []
        matched = {
            "masvs": self.masvs_map.get(evidence_type, []),
            "maswe": self.maswe_map.get(evidence_type, []),
            "mastg": self.mastg_map.get(evidence_type, []),
        }
        for tag in tags:
            matched["masvs"].extend(self.masvs_map.get(tag, []))
            matched["maswe"].extend(self.maswe_map.get(tag, []))
            matched["mastg"].extend(self.mastg_map.get(tag, []))
        return {key: sorted(set(value)) for key, value in matched.items()}

    def map_evidence_item(
        self,
        evidence_item: Any,
        payload: Any = None,
        raw_text: str | None = None,
    ) -> dict[str, Any]:
        evidence_type = getattr(evidence_item, "evidence_type", "") or ""
        tags = self._split_tags(getattr(evidence_item, "tags", None))
        refs = self._empty_refs()
        reasons: list[str] = []
        matched_signals: list[str] = []

        if evidence_type == "apk_hash":
            self._map_apk_hash(refs, reasons, matched_signals, payload)
        elif evidence_type == "manifest_summary":
            self._map_manifest_summary(refs, reasons, matched_signals, payload)
        elif evidence_type == "manifest_xml":
            self._map_manifest_xml(refs, reasons, matched_signals, raw_text or "")
        elif evidence_type == "permissions":
            self._map_permissions(refs, reasons, matched_signals, payload)
        elif evidence_type == "components":
            self._map_components(refs, reasons, matched_signals, payload)
        elif evidence_type == "sbom":
            self._map_sbom(refs, reasons, matched_signals, payload)
        elif evidence_type == "log":
            self._map_log(refs, reasons, matched_signals, evidence_item, raw_text or "")
        elif evidence_type == "screenshot":
            self._map_screenshot(refs, reasons, matched_signals, evidence_item)
        elif evidence_type == "mobsf":
            self._map_mobsf(refs, reasons, matched_signals, payload, raw_text or "")
        elif evidence_type in self.MOBIXLER_TYPES:
            self._map_mobixler_dynamic(refs, reasons, matched_signals, payload, raw_text or "")
        elif evidence_type == "jadx":
            self._map_jadx(refs, reasons, matched_signals, payload, raw_text or "")

        normalized_refs = {key: sorted(values) for key, values in refs.items()}
        if not any(normalized_refs.values()):
            normalized_refs = self.map_evidence(evidence_type, tags)

        status = "mapped" if reasons else ("partially_mapped" if any(normalized_refs.values()) else "unmapped")
        notes = self._build_note(evidence_item, reasons, matched_signals, status)
        return {
            "masvs": normalized_refs["masvs"],
            "maswe": normalized_refs["maswe"],
            "mastg": normalized_refs["mastg"],
            "status": status,
            "notes": notes,
            "matched_signals": matched_signals,
        }

    def coverage_summary(self, mapping_refs: list[dict]) -> dict:
        masvs_domains: dict[str, int] = {}
        for item in mapping_refs:
            for ref in item.get("masvs", []):
                parts = ref.split("-")
                domain = "-".join(parts[:2]) if len(parts) > 1 else ref
                masvs_domains[domain] = masvs_domains.get(domain, 0) + 1
        return {"domain_counts": masvs_domains}

    def _empty_refs(self) -> dict[str, set[str]]:
        return {"masvs": set(), "maswe": set(), "mastg": set()}

    def _split_tags(self, tags: str | None) -> list[str]:
        if not tags:
            return []
        return [tag.strip() for tag in tags.split(",") if tag.strip()]

    def _record(
        self,
        refs: dict[str, set[str]],
        reasons: list[str],
        matched_signals: list[str],
        *,
        reason: str,
        signal: str,
        masvs: list[str] | None = None,
        maswe: list[str] | None = None,
        mastg: list[str] | None = None,
    ) -> None:
        for ref in masvs or []:
            refs["masvs"].add(ref)
        for ref in maswe or []:
            refs["maswe"].add(ref)
        for ref in mastg or []:
            refs["mastg"].add(ref)
        reasons.append(reason)
        matched_signals.append(signal)

    def _map_apk_hash(self, refs: dict[str, set[str]], reasons: list[str], matched_signals: list[str], payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        sha256_value = payload.get("sha256")
        if sha256_value:
            self._record(
                refs,
                reasons,
                matched_signals,
                reason=(
                    f"Hash evidence includes SHA-256 {sha256_value[:12]}..., which ties the audit pack to a specific APK "
                    "binary and supports integrity verification."
                ),
                signal="sha256-present",
                masvs=["MASVS-RESILIENCE-1"],
                mastg=["MASTG-KNOW-0011"],
            )

    def _map_manifest_summary(
        self,
        refs: dict[str, set[str]],
        reasons: list[str],
        matched_signals: list[str],
        payload: Any,
    ) -> None:
        if not isinstance(payload, dict):
            return
        package_name = payload.get("package") or payload.get("package_name") or "unknown package"
        min_sdk = payload.get("min_sdk") or "unknown"
        target_sdk = payload.get("target_sdk") or "unknown"
        summary = payload.get("summary")
        if any(payload.get(key) for key in ("package", "package_name", "version_name", "version_code", "min_sdk", "target_sdk")):
            self._record(
                refs,
                reasons,
                matched_signals,
                reason=(
                    f"Manifest summary identifies {package_name} with minSdk={min_sdk} and targetSdk={target_sdk}, "
                    "providing concrete platform-configuration proof for manifest review."
                ),
                signal="manifest-summary-sdk-metadata",
                masvs=["MASVS-PLATFORM-1"],
                maswe=["MASWE-0058"],
                mastg=["MASTG-TEST-0026"],
            )
        if summary:
            self._record(
                refs,
                reasons,
                matched_signals,
                reason=f"Manifest summary text captures declared app configuration: {summary}.",
                signal="manifest-summary-text",
                masvs=["MASVS-PLATFORM-1"],
                maswe=["MASWE-0058"],
                mastg=["MASTG-TEST-0026"],
            )

    def _map_manifest_xml(
        self,
        refs: dict[str, set[str]],
        reasons: list[str],
        matched_signals: list[str],
        raw_text: str,
    ) -> None:
        manifest_text = raw_text.strip()
        if not manifest_text:
            return
        lower_text = manifest_text.lower()
        self._record(
            refs,
            reasons,
            matched_signals,
            reason="Raw AndroidManifest.xml was extracted, enabling direct verification of declared platform configuration.",
            signal="manifest-xml-present",
            masvs=["MASVS-PLATFORM-1"],
            maswe=["MASWE-0058"],
            mastg=["MASTG-TEST-0026"],
        )

        network_signals: list[str] = []
        if "usescleartexttraffic=\"true\"" in lower_text:
            network_signals.append("cleartext traffic enabled")
        if "networksecurityconfig" in lower_text:
            network_signals.append("networkSecurityConfig declared")
        if "android:exported=\"true\"" in lower_text:
            network_signals.append("exported components declared")
        if network_signals:
            self._record(
                refs,
                reasons,
                matched_signals,
                reason=(
                    "Manifest XML includes network-exposure markers: "
                    + ", ".join(network_signals)
                    + "."
                ),
                signal="manifest-network-markers",
                masvs=["MASVS-NETWORK-1"],
                maswe=["MASWE-0050"],
                mastg=["MASTG-TEST-0286"],
            )

    def _map_permissions(
        self,
        refs: dict[str, set[str]],
        reasons: list[str],
        matched_signals: list[str],
        payload: Any,
    ) -> None:
        if not isinstance(payload, dict):
            return
        permissions = payload.get("permissions") or []
        sensitive_permissions = payload.get("sensitive_permissions") or []
        if permissions:
            self._record(
                refs,
                reasons,
                matched_signals,
                reason=f"Permission inventory lists {len(permissions)} declared permissions for direct manifest and platform review.",
                signal="permission-inventory",
                masvs=["MASVS-PLATFORM-1"],
                maswe=["MASWE-0001"],
                mastg=["MASTG-TEST-0027"],
            )
        if sensitive_permissions:
            preview = ", ".join(sensitive_permissions[:4])
            self._record(
                refs,
                reasons,
                matched_signals,
                reason=f"Sensitive permissions were identified ({preview}), which makes this proof directly relevant to privacy-impact review.",
                signal="sensitive-permissions-present",
                masvs=["MASVS-PRIVACY-1"],
                maswe=["MASWE-0001"],
                mastg=["MASTG-TEST-0027"],
            )

    def _map_components(
        self,
        refs: dict[str, set[str]],
        reasons: list[str],
        matched_signals: list[str],
        payload: Any,
    ) -> None:
        if not isinstance(payload, dict):
            return
        exported_components = payload.get("exported_components") or []
        embedded_domains = payload.get("embedded_domains") or []
        network_security_config = payload.get("network_security_config")
        cleartext_traffic_allowed = payload.get("cleartext_traffic_allowed")
        if exported_components:
            self._record(
                refs,
                reasons,
                matched_signals,
                reason=(
                    f"Component evidence enumerates {len(exported_components)} exported component(s), "
                    "which directly supports review of externally reachable app surfaces."
                ),
                signal="exported-components-present",
                masvs=["MASVS-PLATFORM-2"],
                maswe=["MASWE-0064"],
                mastg=["MASTG-TEST-0028"],
            )
        if embedded_domains or network_security_config or cleartext_traffic_allowed is not None:
            domain_count = len(embedded_domains)
            cleartext_label = cleartext_traffic_allowed if cleartext_traffic_allowed is not None else "not stated"
            self._record(
                refs,
                reasons,
                matched_signals,
                reason=(
                    f"Component evidence captures {domain_count} embedded domain/end-point hint(s), "
                    f"networkSecurityConfig={network_security_config or 'absent'}, "
                    f"cleartextTraffic={cleartext_label}."
                ),
                signal="network-exposure-component-signals",
                masvs=["MASVS-NETWORK-1"],
                maswe=["MASWE-0050"],
                mastg=["MASTG-TEST-0286"],
            )

    def _map_sbom(self, refs: dict[str, set[str]], reasons: list[str], matched_signals: list[str], payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        components = payload.get("components") or []
        statistics = payload.get("statistics") or {}
        source_artifact = payload.get("source_artifact") or {}
        if components:
            self._record(
                refs,
                reasons,
                matched_signals,
                reason=(
                    f"SBOM enumerates {len(components)} component(s), providing concrete dependency and software inventory evidence."
                ),
                signal="sbom-components-enumerated",
                masvs=["MASVS-CODE-1"],
                maswe=["MASWE-0093"],
                mastg=["MASTG-KNOW-0073"],
            )
        if statistics.get("native_library_count") or statistics.get("dex_unit_count") or source_artifact.get("sha256"):
            self._record(
                refs,
                reasons,
                matched_signals,
                reason=(
                    "SBOM statistics include archive-derived implementation details "
                    f"(native libraries={statistics.get('native_library_count', 0)}, dex units={statistics.get('dex_unit_count', 0)}), "
                    "supporting resilience and inventory traceability."
                ),
                signal="sbom-archive-details",
                masvs=["MASVS-RESILIENCE-2"],
                maswe=["MASWE-0093"],
                mastg=["MASTG-KNOW-0073"],
            )

    def _map_log(
        self,
        refs: dict[str, set[str]],
        reasons: list[str],
        matched_signals: list[str],
        evidence_item: Any,
        raw_text: str,
    ) -> None:
        excerpt = raw_text.strip()
        if excerpt:
            self._record(
                refs,
                reasons,
                matched_signals,
                reason="Sanitized runtime log content is available for runtime-observation and troubleshooting review.",
                signal="runtime-log-excerpt",
                masvs=["MASVS-RESILIENCE-1"],
                mastg=["MASTG-TEST-0001"],
            )
        if getattr(evidence_item, "anonymized_flag", False):
            self._record(
                refs,
                reasons,
                matched_signals,
                reason="The runtime log was anonymized before storage, which makes this proof directly relevant to privacy-preserving evidence handling.",
                signal="log-anonymized",
                masvs=["MASVS-PRIVACY-1"],
                maswe=["MASWE-0007"],
                mastg=["MASTG-TEST-0001"],
            )

    def _map_screenshot(self, refs: dict[str, set[str]], reasons: list[str], matched_signals: list[str], evidence_item: Any) -> None:
        description_parts = [
            getattr(evidence_item, "description", None) or "",
            getattr(evidence_item, "original_filename", None) or "",
        ]
        description = " ".join(description_parts).lower()
        self._record(
            refs,
            reasons,
            matched_signals,
            reason="A UI screenshot was captured and preserved as proof of the observed application state during the audit.",
            signal="ui-screenshot-present",
            mastg=["MASTG-KNOW-0019"],
        )
        if any(hint in description for hint in self.AUTH_HINTS):
            self._record(
                refs,
                reasons,
                matched_signals,
                reason="Screenshot metadata indicates an authentication-related screen, so the proof supports review of visible login and session UX controls.",
                signal="screenshot-auth-context",
                masvs=["MASVS-AUTH-1"],
                maswe=["MASWE-0102"],
                mastg=["MASTG-KNOW-0019"],
            )
        if any(hint in description for hint in self.PRIVACY_HINTS):
            self._record(
                refs,
                reasons,
                matched_signals,
                reason="Screenshot metadata suggests user-account or personal-data context, which makes it relevant to privacy-related UI review.",
                signal="screenshot-privacy-context",
                masvs=["MASVS-PRIVACY-1"],
                mastg=["MASTG-KNOW-0019"],
            )

    def _map_mobsf(
        self,
        refs: dict[str, set[str]],
        reasons: list[str],
        matched_signals: list[str],
        payload: Any,
        raw_text: str,
    ) -> None:
        payload_text = self._payload_text(payload, raw_text)
        if not payload_text:
            return
        self._record(
            refs,
            reasons,
            matched_signals,
            reason="MobSF import provides tool-generated static analysis findings that can be traced back to concrete scan output.",
            signal="mobsf-import-present",
            masvs=["MASVS-CODE-1"],
            mastg=["MASTG-TOOL-0008"],
        )
        if any(hint in payload_text for hint in self.CRYPTO_HINTS):
            self._record(
                refs,
                reasons,
                matched_signals,
                reason="MobSF findings contain cryptography-related signals, supporting traceability to crypto review controls.",
                signal="mobsf-crypto-keywords",
                masvs=["MASVS-CRYPTO-1"],
                mastg=["MASTG-TOOL-0008"],
            )

    def _map_mobixler_dynamic(
        self,
        refs: dict[str, set[str]],
        reasons: list[str],
        matched_signals: list[str],
        payload: Any,
        raw_text: str,
    ) -> None:
        payload_text = self._payload_text(payload, raw_text)
        if not payload_text:
            return
        self._record(
            refs,
            reasons,
            matched_signals,
            reason=(
                "Mobixler dynamic-analysis import provides tool-generated runtime findings that can be traced back "
                "to observed app behavior."
            ),
            signal="mobixler-dynamic-import-present",
            masvs=["MASVS-RESILIENCE-1"],
            mastg=["MASTG-TOOL-0008", "MASTG-TEST-0001"],
        )
        if any(hint in payload_text for hint in self.NETWORK_HINTS):
            self._record(
                refs,
                reasons,
                matched_signals,
                reason="Mobixler dynamic findings include network traffic or transport-security signals from runtime observation.",
                signal="mobixler-network-signals",
                masvs=["MASVS-NETWORK-1"],
                maswe=["MASWE-0050"],
                mastg=["MASTG-TEST-0286"],
            )
        if any(hint in payload_text for hint in self.AUTH_HINTS):
            self._record(
                refs,
                reasons,
                matched_signals,
                reason="Mobixler dynamic findings include authentication or session-related runtime signals.",
                signal="mobixler-auth-signals",
                masvs=["MASVS-AUTH-1"],
                maswe=["MASWE-0102"],
                mastg=["MASTG-TEST-0001"],
            )
        if any(hint in payload_text for hint in self.PRIVACY_HINTS + self.STORAGE_HINTS):
            self._record(
                refs,
                reasons,
                matched_signals,
                reason="Mobixler dynamic findings include privacy, local-storage, or personal-data handling signals.",
                signal="mobixler-privacy-storage-signals",
                masvs=["MASVS-PRIVACY-1"],
                maswe=["MASWE-0007"],
                mastg=["MASTG-TEST-0001"],
            )

    def _map_jadx(
        self,
        refs: dict[str, set[str]],
        reasons: list[str],
        matched_signals: list[str],
        payload: Any,
        raw_text: str,
    ) -> None:
        payload_text = self._payload_text(payload, raw_text)
        if not payload_text:
            return
        self._record(
            refs,
            reasons,
            matched_signals,
            reason="JADX import contributes decompiled code evidence that supports source-level review of implementation details.",
            signal="jadx-import-present",
            masvs=["MASVS-CODE-1"],
            mastg=["MASTG-TOOL-0003"],
        )
        if any(hint in payload_text for hint in self.IMPORT_HINTS):
            self._record(
                refs,
                reasons,
                matched_signals,
                reason="The imported JADX material includes finding-like markers that can be tied to concrete code-review observations.",
                signal="jadx-finding-keywords",
                masvs=["MASVS-CODE-1"],
                mastg=["MASTG-TOOL-0003"],
            )

    def _payload_text(self, payload: Any, raw_text: str) -> str:
        if isinstance(payload, dict):
            return json.dumps(payload, sort_keys=True).lower()
        if isinstance(payload, list):
            return json.dumps(payload).lower()
        return raw_text.lower()

    def _build_note(
        self,
        evidence_item: Any,
        reasons: list[str],
        matched_signals: list[str],
        status: str,
    ) -> str:
        evidence_label = getattr(evidence_item, "original_filename", None) or getattr(evidence_item, "evidence_type", "evidence")
        if reasons:
            return (
                f"Concrete proof '{evidence_label}' mapped with signals [{', '.join(sorted(set(matched_signals)))}]. "
                + " ".join(reasons)
            )
        if status == "partially_mapped":
            return (
                f"'{evidence_label}' was linked using generic evidence-type coverage because no stronger proof-specific signals "
                "were extracted from its payload."
            )
        return f"No MASVS, MASWE, or MASTG references could be justified from '{evidence_label}'."
