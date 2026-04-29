from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReportService:
    def __init__(self, templates_dir: Path):
        self.env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def render_html(self, report_context: dict, output_path: Path) -> Path:
        template = self.env.get_template("report.html")
        html = template.render(**report_context)
        output_path.write_text(html, encoding="utf-8")
        return output_path
