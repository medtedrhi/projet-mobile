from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.core.config import get_settings

logger = logging.getLogger("app.intelligence")


class OpenRouterReasoner:
    """Best-effort OpenRouter client for evidence narratives."""

    def __init__(self):
        settings = get_settings()
        self.settings = settings
        self.api_key = settings.openrouter_api_key
        self.base_url = settings.openrouter_base_url.rstrip("/")
        self.model = settings.openrouter_model
        self.site_url = settings.openrouter_site_url
        self.app_name = settings.app_name

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.model)

    def complete(
        self,
        system_prompt: str,
        user_payload: dict[str, Any],
        max_tokens: int = 220,
        purpose: str = "completion",
    ) -> str | None:
        if not self.enabled:
            self._debug_log(f"[AI:{purpose}] OpenRouter disabled. Missing API key or model configuration.")
            return None

        self._debug_log(
            f"[AI:{purpose}] Sending request to OpenRouter model={self.model} "
            f"base_url={self.base_url} payload_keys={sorted(user_payload.keys())}"
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-Title": self.app_name,
        }
        if self.site_url:
            headers["HTTP-Referer"] = self.site_url

        payload = {
            "model": self.model,
            "temperature": 0.2,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, indent=2, default=str)},
            ],
        }

        try:
            response = httpx.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=self.settings.openrouter_timeout_seconds,
            )
            response.raise_for_status()
            response_payload = response.json()
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            self._debug_log(f"[AI:{purpose}] OpenRouter request failed: {exc}")
            return None

        try:
            content = response_payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            self._debug_log(f"[AI:{purpose}] OpenRouter response parse failed: {exc}")
            return None

        if isinstance(content, list):
            text_parts = [part.get("text", "") for part in content if isinstance(part, dict)]
            content = "\n".join(part for part in text_parts if part)
        if not isinstance(content, str):
            self._debug_log(f"[AI:{purpose}] OpenRouter returned non-text content of type {type(content).__name__}.")
            return None

        cleaned = content.strip()
        if cleaned:
            self._debug_log(f"[AI:{purpose}] OpenRouter response:\n{cleaned}")
        else:
            self._debug_log(f"[AI:{purpose}] OpenRouter returned an empty response.")
        return cleaned or None

    def _debug_log(self, message: str) -> None:
        if self.settings.openrouter_debug_logging:
            logger.warning(message)


class SummaryProvider:
    def __init__(self):
        self.reasoner = OpenRouterReasoner()

    def summarize_collection(self, case_context: dict[str, Any]) -> str:
        llm_summary = self.reasoner.complete(
            system_prompt=(
                "You are summarizing defensive Android audit evidence for a compliance pack. "
                "Write 2-4 concise sentences. Describe what evidence was collected, what it supports, "
                "and what important gaps remain. Do not invent findings beyond the provided evidence."
            ),
            user_payload=case_context,
            max_tokens=220,
            purpose="collection-summary",
        )
        if llm_summary:
            return llm_summary

        evidence_count = case_context.get("total_evidence_items", 0)
        missing_count = case_context.get("total_missing_issues", 0)
        package_name = case_context.get("package_name") or "the target application"
        evidence_types = ", ".join(case_context.get("evidence_types", [])) or "no evidence types"
        if evidence_count == 0:
            fallback = "No evidence has been collected yet."
            self.reasoner._debug_log(f"[AI:collection-summary] Using fallback summary:\n{fallback}")
            return fallback
        if missing_count == 0:
            fallback = (
                f"{evidence_count} evidence items were collected for {package_name}, covering {evidence_types}. "
                "Core audit inputs appear complete for the current evidence pack."
            )
            self.reasoner._debug_log(f"[AI:collection-summary] Using fallback summary:\n{fallback}")
            return fallback
        fallback = (
            f"{evidence_count} evidence items were collected for {package_name}, covering {evidence_types}, "
            f"but {missing_count} collection gaps still affect compliance readiness."
        )
        self.reasoner._debug_log(f"[AI:collection-summary] Using fallback summary:\n{fallback}")
        return fallback


class MappingReasoner:
    def infer_domains(self, evidence_type: str) -> list[str]:
        hints = {
            "permissions": ["MASVS-PLATFORM", "MASVS-PRIVACY"],
            "manifest_summary": ["MASVS-PLATFORM"],
            "manifest_xml": ["MASVS-PLATFORM", "MASVS-NETWORK"],
            "log": ["MASVS-RESILIENCE", "MASVS-PRIVACY"],
            "sbom": ["MASVS-CODE", "MASVS-RESILIENCE"],
            "screenshot": ["MASVS-AUTH", "MASVS-PRIVACY"],
        }
        return hints.get(evidence_type, ["MASVS-GENERAL"])


class ComplianceNarrativeGenerator:
    def __init__(self):
        self.reasoner = OpenRouterReasoner()

    def explain_gap(self, title: str, recommendation: str, rationale: str | None = None, context: dict[str, Any] | None = None) -> str:
        user_payload = {
            "gap_title": title,
            "rationale": rationale,
            "recommendation": recommendation,
            "context": context or {},
        }
        llm_summary = self.reasoner.complete(
            system_prompt=(
                "You explain a missing-evidence gap in a defensive Android compliance report. "
                "Write exactly 1-2 concise sentences describing why the gap matters and what the next action should be. "
                "Stay grounded in the provided inputs."
            ),
            user_payload=user_payload,
            max_tokens=140,
            purpose="gap-narrative",
        )
        if llm_summary:
            return llm_summary
        fallback = f"{title}. Recommended next step: {recommendation}"
        self.reasoner._debug_log(f"[AI:gap-narrative] Using fallback narrative:\n{fallback}")
        return fallback
