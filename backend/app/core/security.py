from pathlib import Path
import re
import uuid


FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(filename: str) -> str:
    normalized = FILENAME_SAFE_RE.sub("_", filename.strip())
    return normalized or f"upload_{uuid.uuid4().hex}"


def ensure_within_root(root: Path, target: Path) -> Path:
    resolved_root = root.resolve()
    resolved_target = target.resolve()
    if resolved_root not in resolved_target.parents and resolved_target != resolved_root:
        raise ValueError("Target path escapes allowed root")
    return resolved_target
