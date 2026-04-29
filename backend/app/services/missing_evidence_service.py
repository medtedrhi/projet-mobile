class MissingEvidenceService:
    """Evaluate expected audit evidence and produce collection guidance."""

    DEFAULT_RULES = [
        {
            "rule_id": "apk_hash",
            "category": "integrity",
            "severity": "high",
            "title": "APK hashes are missing",
            "requires": ["apk_hash"],
            "rationale": "Integrity verification is expected for reproducible audit evidence.",
            "recommendation": "Upload the APK and regenerate the evidence inventory to capture SHA-256, SHA-1, and MD5.",
        },
        {
            "rule_id": "manifest_extract",
            "category": "static-analysis",
            "severity": "high",
            "title": "Manifest extract is missing",
            "requires": ["manifest_summary", "manifest_xml"],
            "require_mode": "all",
            "rationale": "Manifest metadata anchors package identification, permissions, and component review.",
            "recommendation": "Provide the APK or a parsed manifest export so platform configuration evidence can be recorded.",
        },
        {
            "rule_id": "permissions_list",
            "category": "static-analysis",
            "severity": "medium",
            "title": "Permissions list is missing",
            "requires": ["permissions"],
            "rationale": "Permission review supports MASVS platform and privacy assessments.",
            "recommendation": "Collect permission evidence from the APK manifest or a trusted external analyzer.",
        },
        {
            "rule_id": "sbom",
            "category": "dependencies",
            "severity": "medium",
            "title": "SBOM evidence is missing",
            "requires": ["sbom"],
            "rationale": "Dependency visibility supports supply-chain review and remediation tracking.",
            "recommendation": "Generate or import an SBOM, or attach dependency exports from supporting tools.",
        },
        {
            "rule_id": "screenshots",
            "category": "ui-evidence",
            "severity": "low",
            "title": "No screenshots were collected",
            "requires": ["screenshot"],
            "rationale": "UI evidence helps validate visible security controls and reporting context.",
            "recommendation": "Upload representative screenshots for authentication, consent, and security-sensitive screens.",
        },
        {
            "rule_id": "logs",
            "category": "dynamic-analysis",
            "severity": "medium",
            "title": "No sanitized runtime logs were collected",
            "requires": ["log"],
            "rationale": "Dynamic evidence improves coverage for runtime behavior and control validation.",
            "recommendation": "Upload sanitized runtime logs or capture anonymized telemetry artifacts.",
        },
        {
            "rule_id": "components",
            "category": "static-analysis",
            "severity": "medium",
            "title": "No component exposure evidence was collected",
            "requires": ["components"],
            "rationale": "Activity, service, receiver, and provider visibility supports attack-surface and platform review.",
            "recommendation": "Collect exported component evidence from the APK or import static-analysis output.",
        },
        {
            "rule_id": "network-config",
            "category": "network",
            "severity": "medium",
            "title": "No network configuration evidence was collected",
            "requires": ["manifest_xml", "components"],
            "require_mode": "all",
            "rationale": "Network security configuration and cleartext traffic settings are important compliance anchors.",
            "recommendation": "Collect raw manifest XML and derived network configuration evidence.",
        },
    ]

    def evaluate(self, available_types: set[str]) -> list[dict]:
        issues = []
        for rule in self.DEFAULT_RULES:
            require_mode = rule.get("require_mode", "any")
            matched = all(req in available_types for req in rule["requires"]) if require_mode == "all" else any(
                req in available_types for req in rule["requires"]
            )
            if not matched:
                issues.append(rule)
        return issues
