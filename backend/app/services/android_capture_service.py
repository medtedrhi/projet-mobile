from __future__ import annotations

import subprocess


class AndroidCaptureService:
    """Capture Android UI screenshots and runtime logs from a connected device or emulator via adb."""

    def __init__(
        self,
        adb_executable: str = "adb",
        timeout_seconds: int = 15,
        runtime_log_timeout_seconds: int | None = None,
        runtime_log_line_count: int = 400,
    ):
        self.adb_executable = adb_executable
        self.timeout_seconds = timeout_seconds
        self.runtime_log_timeout_seconds = runtime_log_timeout_seconds or timeout_seconds
        self.runtime_log_line_count = runtime_log_line_count

    def list_devices(self) -> list[dict[str, str | None]]:
        completed = self._run(["devices", "-l"])
        lines = [line.strip() for line in completed.stdout.splitlines()]
        if not lines:
            return []

        devices: list[dict[str, str | None]] = []
        for line in lines[1:]:
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            metadata: dict[str, str | None] = {
                "serial": parts[0],
                "state": parts[1],
                "model": None,
                "product": None,
                "device": None,
                "transport_id": None,
            }
            for token in parts[2:]:
                if ":" not in token:
                    continue
                key, value = token.split(":", 1)
                if key in metadata:
                    metadata[key] = value.replace("_", " ")
            devices.append(metadata)
        return devices

    def capture_screenshot(self, device_serial: str | None = None) -> tuple[bytes, dict[str, str]]:
        selected_serial = device_serial or self._default_device_serial()
        command = self._device_args(selected_serial) + ["exec-out", "screencap", "-p"]
        completed = self._run(command, text=False)
        image_bytes = completed.stdout
        if not image_bytes:
            raise ValueError("adb returned an empty screenshot payload.")
        if not image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("adb screenshot capture did not return a PNG payload.")

        safe_serial = selected_serial.replace(":", "_")
        filename = f"auto_screenshot_{safe_serial}.png"
        return image_bytes, {
            "device_serial": selected_serial,
            "filename": filename,
            "mime_type": "image/png",
        }

    def capture_runtime_logs(
        self,
        device_serial: str | None = None,
        line_count: int | None = None,
    ) -> tuple[bytes, dict[str, str]]:
        selected_serial = device_serial or self._default_device_serial()
        lines = max(1, line_count or self.runtime_log_line_count)
        command = self._device_args(selected_serial) + ["logcat", "-d", "-t", str(lines)]
        completed = self._run(command, text=True, timeout_seconds=self.runtime_log_timeout_seconds)
        log_text = completed.stdout.strip()
        if not log_text:
            raise ValueError("adb logcat returned no runtime logs.")

        safe_serial = selected_serial.replace(":", "_")
        filename = f"runtime_log_{safe_serial}.log"
        return log_text.encode("utf-8"), {
            "device_serial": selected_serial,
            "filename": filename,
            "mime_type": "text/plain",
            "line_count": str(lines),
        }

    def _default_device_serial(self) -> str:
        available = [device for device in self.list_devices() if device["state"] == "device"]
        if not available:
            raise ValueError(
                "No Android device is available for automatic capture. Connect a device or start an emulator and ensure 'adb devices' shows it as 'device'."
            )
        if len(available) > 1:
            raise ValueError("Multiple Android devices are connected. Select a device serial before capturing a screenshot.")
        return str(available[0]["serial"])

    def _device_args(self, device_serial: str) -> list[str]:
        return ["-s", device_serial]

    def _run(self, args: list[str], text: bool = True, timeout_seconds: int | None = None):
        command = [self.adb_executable, *args]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=text,
                timeout=timeout_seconds or self.timeout_seconds,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ValueError(
                f"adb executable '{self.adb_executable}' was not found. Install Android platform-tools or set ADB_EXECUTABLE in .env."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ValueError("adb capture command timed out.") from exc
        except OSError as exc:
            raise ValueError(f"adb execution failed: {exc}") from exc

        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="ignore") if isinstance(completed.stderr, bytes) else completed.stderr
            stdout = completed.stdout.decode("utf-8", errors="ignore") if isinstance(completed.stdout, bytes) else completed.stdout
            detail = (stderr or stdout or "Unknown adb error").strip()
            raise ValueError(f"adb command failed: {detail}")
        return completed
