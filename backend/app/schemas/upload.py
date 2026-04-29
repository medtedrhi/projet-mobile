from app.schemas.common import ORMModel, TimestampedSchema


class UploadedArtifactRead(TimestampedSchema):
    case_id: str
    artifact_type: str
    source: str
    original_filename: str
    stored_path: str
    mime_type: str | None
    file_size: int
    file_hash_sha256: str
    description: str | None
    anonymized: bool


class ScreenshotCaptureRequest(ORMModel):
    device_serial: str | None = None
    source: str = "adb-capture"
    description: str | None = None


class AndroidDeviceRead(ORMModel):
    serial: str
    state: str
    model: str | None = None
    product: str | None = None
    device: str | None = None
    transport_id: str | None = None
