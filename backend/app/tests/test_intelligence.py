import httpx

from app.core.config import get_settings
from app.services.intelligence import ComplianceNarrativeGenerator, SummaryProvider


def test_summary_provider_falls_back_without_openrouter(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "")
    get_settings.cache_clear()

    summary = SummaryProvider().summarize_collection(
        {
            "package_name": "com.example.demo",
            "total_evidence_items": 4,
            "total_missing_issues": 2,
            "evidence_types": ["apk", "manifest_summary", "permissions", "sbom"],
        }
    )

    assert "4 evidence items were collected" in summary
    assert "2 collection gaps" in summary
    get_settings.cache_clear()


def test_summary_provider_uses_openrouter_response(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setenv("OPENROUTER_MODEL", "mistralai/mistral-7b-instruct-v0.3")
    get_settings.cache_clear()

    def fake_post(*args, **kwargs):
        request = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
        return httpx.Response(
            200,
            request=request,
            json={"choices": [{"message": {"content": "AI generated summary from OpenRouter."}}]},
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    summary = SummaryProvider().summarize_collection(
        {
            "package_name": "com.example.demo",
            "total_evidence_items": 5,
            "total_missing_issues": 1,
            "evidence_types": ["apk", "manifest_summary"],
        }
    )

    assert summary == "AI generated summary from OpenRouter."


def test_gap_narrative_uses_openrouter_response(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setenv("OPENROUTER_MODEL", "mistralai/mistral-7b-instruct-v0.3")
    get_settings.cache_clear()

    def fake_post(*args, **kwargs):
        request = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
        return httpx.Response(
            200,
            request=request,
            json={"choices": [{"message": {"content": "The missing screenshot evidence limits UI control validation. Capture a representative authenticated screen next."}}]},
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    narrative = ComplianceNarrativeGenerator().explain_gap(
        "No screenshots were collected",
        "Upload representative screenshots",
        rationale="UI evidence helps validate visible security controls.",
        context={"available_evidence_types": ["apk", "manifest_summary"]},
    )

    assert "limits UI control validation" in narrative
    get_settings.cache_clear()


def test_summary_provider_logs_ai_response_when_debug_enabled(monkeypatch, caplog):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setenv("OPENROUTER_MODEL", "mistralai/mistral-7b-instruct-v0.3")
    monkeypatch.setenv("OPENROUTER_DEBUG_LOGGING", "true")
    get_settings.cache_clear()

    def fake_post(*args, **kwargs):
        request = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
        return httpx.Response(
            200,
            request=request,
            json={"choices": [{"message": {"content": "Visible debug AI summary."}}]},
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    with caplog.at_level("WARNING", logger="app.intelligence"):
        summary = SummaryProvider().summarize_collection(
            {
                "package_name": "com.example.demo",
                "total_evidence_items": 5,
                "total_missing_issues": 0,
                "evidence_types": ["apk", "manifest_summary"],
            }
        )

    assert summary == "Visible debug AI summary."
    assert "Visible debug AI summary." in caplog.text
    get_settings.cache_clear()
