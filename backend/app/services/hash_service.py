import hashlib
from pathlib import Path


class HashService:
    """Generate deterministic hashes for evidence integrity tracking."""

    @staticmethod
    def hash_file(path: Path) -> dict[str, str]:
        digests = {"sha256": hashlib.sha256(), "sha1": hashlib.sha1(), "md5": hashlib.md5()}
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                for digest in digests.values():
                    digest.update(chunk)
        return {name: digest.hexdigest() for name, digest in digests.items()}
