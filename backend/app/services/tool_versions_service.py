from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime
from pathlib import Path


class ToolVersionsService:
    """Capture local tool and device versions without blocking export generation."""

    COMMAND_TIMEOUT_SECONDS = 3

    def collect(self) -> dict[str, str]:
        return {
            "java_version": self._java_version(),
            "gradle_version": self._gradle_version(),
            "android_sdk_version": self._android_sdk_version(),
            "adb_version": self._adb_version(),
            "python_version": self._first_line(self._run(["python", "--version"])),
            "apktool_version": self._first_line(self._run(["apktool", "--version"])),
            "jadx_version": self._first_line(self._run(["jadx", "--version"])),
            "device_model": self._adb_prop("ro.product.model"),
            "android_version": self._adb_prop("ro.build.version.release"),
            "analysis_date": datetime.now().isoformat(timespec="seconds"),
        }

    def _java_version(self) -> str:
        output = self._run(["java", "-version"])
        match = re.search(r'version "([^"]+)"', output)
        return match.group(1) if match else self._first_line(output)

    def _gradle_version(self) -> str:
        output = self._run(["gradle", "-version"])
        match = re.search(r"Gradle\s+([^\s]+)", output)
        return match.group(1) if match else self._first_line(output)

    def _adb_version(self) -> str:
        output = self._run(["adb", "version"])
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if len(lines) >= 2 and lines[0].startswith("Android Debug Bridge"):
            return f"{lines[0]} ({lines[1]})"
        return self._first_line(output)

    def _adb_prop(self, prop_name: str) -> str:
        value = self._run(["adb", "shell", "getprop", prop_name])
        return self._first_line(value)

    def _android_sdk_version(self) -> str:
        sdk_root = self._android_sdk_root()
        if sdk_root is None:
            return "not_found"

        platforms_dir = sdk_root / "platforms"
        if not platforms_dir.exists():
            return "not_found"

        versions = []
        for platform in platforms_dir.glob("android-*"):
            try:
                versions.append(int(platform.name.split("-", 1)[1]))
            except (IndexError, ValueError):
                continue
        if versions:
            return f"android-{max(versions)}"
        return "not_found"

    def _android_sdk_root(self) -> Path | None:
        for env_name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
            value = os.environ.get(env_name)
            if value:
                path = Path(value)
                if path.exists():
                    return path

        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            path = Path(local_app_data) / "Android" / "Sdk"
            if path.exists():
                return path
        return None

    def _run(self, command: list[str]) -> str:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
        except FileNotFoundError:
            return "not_found"
        except subprocess.TimeoutExpired:
            return "unavailable"
        except OSError:
            return "unavailable"

        output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part and part.strip())
        return output.strip() or "unavailable"

    def _first_line(self, output: str) -> str:
        for line in output.splitlines():
            line = line.strip()
            if line:
                return line
        return "unavailable"
