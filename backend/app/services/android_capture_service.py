from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


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

    def run_dynamic_apk_analysis(
        self,
        apk_path: Path,
        package_name: str,
        device_serial: str | None = None,
        monkey_event_count: int = 120,
        log_line_count: int | None = None,
    ) -> tuple[bytes, dict[str, str]]:
        if not apk_path.exists():
            raise ValueError("APK file for dynamic analysis was not found.")
        if not package_name:
            raise ValueError("Package name is required before running dynamic APK analysis.")

        selected_serial = device_serial or self._default_device_serial()
        safe_serial = selected_serial.replace(":", "_")
        events = max(1, monkey_event_count)
        lines = max(1, log_line_count or self.runtime_log_line_count)
        device_prefix = self._device_args(selected_serial)

        steps: list[dict[str, Any]] = []
        self._record_step(steps, "device-selected", True, f"Using Android target {selected_serial}.")

        device_props = {
            "model": self._try_stdout(device_prefix + ["shell", "getprop", "ro.product.model"]),
            "android_version": self._try_stdout(device_prefix + ["shell", "getprop", "ro.build.version.release"]),
            "sdk": self._try_stdout(device_prefix + ["shell", "getprop", "ro.build.version.sdk"]),
        }

        install_result = self._try_run(device_prefix + ["install", "-r", "-t", str(apk_path)])
        self._record_step(steps, "install-apk", install_result["ok"], install_result["output"])
        if not install_result["ok"]:
            raise ValueError(f"APK install failed during dynamic analysis: {install_result['output']}")

        self._try_run(device_prefix + ["logcat", "-c"])

        launch_result = self._try_run(
            device_prefix + ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            timeout_seconds=self.timeout_seconds,
        )
        self._record_step(steps, "launch-app", launch_result["ok"], launch_result["output"])

        exercise_result = self._try_run(
            device_prefix + ["shell", "monkey", "-p", package_name, "--throttle", "250", str(events)],
            timeout_seconds=max(self.timeout_seconds, int(events * 0.4)),
        )
        self._record_step(steps, "exercise-app-with-monkey", exercise_result["ok"], exercise_result["output"])

        screenshot = self._try_run(device_prefix + ["exec-out", "screencap", "-p"], text=False)
        self._record_step(
            steps,
            "capture-screenshot",
            screenshot["ok"] and isinstance(screenshot["output"], bytes) and screenshot["output"].startswith(b"\x89PNG"),
            "Screenshot captured." if screenshot["ok"] else screenshot["output"],
        )

        logcat = self._try_stdout(device_prefix + ["logcat", "-d", "-t", str(lines)], timeout_seconds=self.runtime_log_timeout_seconds)
        dumpsys_package = self._try_stdout(device_prefix + ["shell", "dumpsys", "package", package_name])
        dumpsys_activity = self._try_stdout(device_prefix + ["shell", "dumpsys", "activity", "top"])
        meminfo = self._try_stdout(device_prefix + ["shell", "dumpsys", "meminfo", package_name])
        process_list = self._try_stdout(device_prefix + ["shell", "ps", "-A"])
        proc_net_tcp = self._try_stdout(device_prefix + ["shell", "cat", "/proc/net/tcp"])

        payload = {
            "tool": "built-in-mobixler-style-dynamic-analysis",
            "analysis_type": "android_dynamic_apk",
            "device": {
                "serial": selected_serial,
                **device_props,
            },
            "target": {
                "apk_filename": apk_path.name,
                "package_name": package_name,
            },
            "execution": {
                "monkey_event_count": events,
                "log_line_count": lines,
                "steps": steps,
            },
            "runtime": {
                "logcat_excerpt": logcat[:6000],
                "activity_top_excerpt": dumpsys_activity[:2500],
                "meminfo_excerpt": meminfo[:2500],
                "package_excerpt": dumpsys_package[:3000],
                "process_present": package_name in process_list,
                "tcp_table_excerpt": proc_net_tcp[:2500],
            },
            "findings": self._dynamic_findings(logcat, dumpsys_package, dumpsys_activity, meminfo, proc_net_tcp),
        }

        return json.dumps(payload, indent=2).encode("utf-8"), {
            "device_serial": selected_serial,
            "filename": f"mobixler_dynamic_{safe_serial}.json",
            "mime_type": "application/json",
            "package_name": package_name,
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

    def _try_run(self, args: list[str], text: bool = True, timeout_seconds: int | None = None) -> dict[str, Any]:
        try:
            completed = self._run(args, text=text, timeout_seconds=timeout_seconds)
        except ValueError as exc:
            return {"ok": False, "output": str(exc)}
        return {"ok": True, "output": completed.stdout}

    def _try_stdout(self, args: list[str], timeout_seconds: int | None = None) -> str:
        result = self._try_run(args, timeout_seconds=timeout_seconds)
        output = result["output"]
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="ignore")
        return str(output).strip()

    def _record_step(self, steps: list[dict[str, Any]], name: str, ok: bool, detail: str) -> None:
        steps.append({"name": name, "status": "ok" if ok else "failed", "detail": str(detail).strip()[:1000]})

    def _dynamic_findings(self, *texts: str) -> list[dict[str, str]]:
        combined = "\n".join(text for text in texts if text).lower()
        findings: list[dict[str, str]] = []
        rules = [
            (
                "network-runtime-signals",
                "Network or transport activity observed during runtime analysis.",
                r"https?://|ssl|tls|cleartext|certificate|socket|/proc/net/tcp",
            ),
            (
                "auth-session-runtime-signals",
                "Authentication, credential, token, or session text appeared in runtime output.",
                r"login|password|credential|token|session|oauth|jwt|bearer",
            ),
            (
                "privacy-storage-runtime-signals",
                "Privacy, account, or local-storage text appeared in runtime output.",
                r"email|phone|profile|account|privacy|pii|sqlite|sharedpref|database|sdcard",
            ),
            (
                "runtime-error-signals",
                "Errors, exceptions, crashes, or ANR markers appeared during runtime analysis.",
                r"exception|fatal exception|crash|anr|error",
            ),
        ]
        for rule_id, title, pattern in rules:
            if re.search(pattern, combined):
                findings.append({"rule_id": rule_id, "severity": "medium", "title": title})
        if not findings:
            findings.append(
                {
                    "rule_id": "dynamic-run-completed",
                    "severity": "info",
                    "title": "APK was installed, launched, exercised, and runtime evidence was collected.",
                }
            )
        return findings
