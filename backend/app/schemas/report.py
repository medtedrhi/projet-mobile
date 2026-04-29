from app.schemas.common import TimestampedSchema


class GeneratedReportRead(TimestampedSchema):
    case_id: str
    report_type: str
    output_path: str
    status: str


class ExportBundleRead(TimestampedSchema):
    case_id: str
    bundle_type: str
    output_path: str
    status: str
