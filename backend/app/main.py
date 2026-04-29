from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import cases, evidence, exports, mapping, reports, uploads
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.base import Base
from app.db.session import engine

settings = get_settings()
configure_logging()
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Defensive evidence collection and compliance pack generator for Android APK audits.",
)

app.add_middleware(
    CORSMiddleware,
    # Parse `CORS_ORIGINS` robustly: accept a JSON list string, a single origin string,
    # or a python list. If parsing fails or the value is empty, default to allow-all
    # (useful for local development).
    allow_origins=(lambda v: (lambda x: x)(
        __import__('json').loads(v) if isinstance(v, str) and v.strip().startswith('[') else
        ([v] if isinstance(v, str) and v.strip() else v) if v is not None else ['*']
    ))(settings.cors_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(cases.router, prefix="/api")
app.include_router(uploads.router, prefix="/api")
app.include_router(evidence.router, prefix="/api")
app.include_router(mapping.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(exports.router, prefix="/api")


@app.get("/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}
