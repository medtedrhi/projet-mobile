from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_ROOT.parent


class Settings(BaseSettings):
    app_name: str = "Evidence Collector & Compliance Pack"
    app_version: str = "0.1.0"
    api_v1_prefix: str = "/api"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    database_url: str = "sqlite:///./evidence_collector.db"
    mysql_database_url: str | None = None
    uploads_dir: Path = Field(default=Path("./data/uploads"))
    exports_dir: Path = Field(default=Path("./data/exports"))
    reports_dir: Path = Field(default=Path("./data/reports"))
    max_upload_size_mb: int = 50
    allow_original_logs: bool = False
    redact_ipv6: bool = True
    adb_executable: str = "adb"
    screenshot_capture_timeout_seconds: int = 15
    runtime_log_capture_timeout_seconds: int = 20
    runtime_log_capture_line_count: int = 400
    dynamic_analysis_enabled: bool = True
    dynamic_analysis_monkey_event_count: int = 120
    dynamic_analysis_log_line_count: int = 1000
    dynamic_analysis_wait_after_launch_seconds: int = 5
    dynamic_analysis_screenshot_count: int = 3
    dynamic_analysis_auto_export: bool = True
    openrouter_api_key: str | None = None
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str | None = "mistralai/mistral-7b-instruct-v0.3"
    openrouter_site_url: str | None = "http://localhost:8000"
    openrouter_timeout_seconds: int = 30
    openrouter_debug_logging: bool = False
    model_config = SettingsConfigDict(
        env_file=(PROJECT_ROOT / ".env", BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    settings.exports_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    return settings
