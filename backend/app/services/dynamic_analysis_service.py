from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.services.android_capture_service import AndroidCaptureService
from app.services.log_sanitizer import LogSanitizer


CRASH_PATTERNS = (
    "FATAL EXCEPTION",
    "Force finishing activity",
    "Process crashed",
    "SIGSEGV",
    "signal 11",
    "native crash",
    "java.lang.RuntimeException",
)
ANR_PATTERNS = ("ANR", "Application Not Responding")
FOREGROUND_PATTERNS = (
    re.compile(r"(?:mResumedActivity|ResumedActivity|topResumedActivity|mFocusedActivity)\s*[=:]\s*ActivityRecord\{[^}]*\s+([A-Za-z0-9_.]+)/([A-Za-z0-9_.$/]+)"),
    re.compile(r"(?:mCurrentFocus|mFocusedApp)\s*[=:]\s*Window\{[^}]*\s+([A-Za-z0-9_.]+)/([A-Za-z0-9_.$/]+)"),
    re.compile(r"(?:mCurrentFocus|mFocusedApp)\s*[=:]\s*AppWindowToken\{[^}]*\s+token=Token\{[^}]*ActivityRecord\{[^}]*\s+([A-Za-z0-9_.]+)/([A-Za-z0-9_.$/]+)"),
)


@dataclass
class DynamicArtifact:
    evidence_type: str
    path: Path
    filename: str
    mime_type: str
    description: str
    anonymized: bool = False


@dataclass
class DynamicAnalysisResult:
    device: dict[str, Any] = field(default_factory=dict)
    target: dict[str, Any] = field(default_factory=dict)
    execution: dict[str, Any] = field(default_factory=dict)
    runtime: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    artifacts: list[DynamicArtifact] = field(default_factory=list)

    @property
    def install_ok(self) -> bool:
        return bool(self.execution.get("install_ok"))

    @property
    def launch_ok(self) -> bool:
        return bool(self.execution.get("launch_ok"))

    @property
    def monkey_ok(self) -> bool:
        return bool(self.execution.get("monkey_ok"))

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("artifacts", None)
        return payload


class DynamicAnalysisService:
    """Run defensive MobSF/Mobisef-style dynamic collection through adb."""

    def __init__(
        self,
        android_capture: AndroidCaptureService | None = None,
        sanitizer: LogSanitizer | None = None,
    ):
        settings = get_settings()
        self.settings = settings
        self.android_capture = android_capture or AndroidCaptureService(
            adb_executable=settings.adb_executable,
            timeout_seconds=settings.screenshot_capture_timeout_seconds,
            runtime_log_timeout_seconds=settings.runtime_log_capture_timeout_seconds,
            runtime_log_line_count=settings.dynamic_analysis_log_line_count,
        )
        self.sanitizer = sanitizer or LogSanitizer()

    def run_full_dynamic_analysis(
        self,
        apk_path: Path,
        package_name: str,
        case_id: str,
        device_serial: str | None = None,
        monkey_event_count: int = 120,
        log_line_count: int = 1000,
        wait_after_launch_seconds: int = 5,
        apk_info: dict[str, Any] | None = None,
    ) -> DynamicAnalysisResult:
        result = DynamicAnalysisResult()
        apk_info = apk_info or {}
        if not apk_path.exists():
            result.errors.append("APK file missing. Upload an APK before running dynamic analysis.")
            return result
        if not package_name:
            result.errors.append("Package name not found. The APK parser could not identify the target package.")
            return result

        output_dir = self.settings.uploads_dir / case_id / "dynamic_analysis"
        output_dir.mkdir(parents=True, exist_ok=True)
        result.target = {
            "apk_filename": apk_path.name,
            "package_name": package_name,
            "version_name": apk_info.get("version_name"),
            "version_code": apk_info.get("version_code"),
        }

        try:
            selected_serial = self._select_device(device_serial)
        except ValueError as exc:
            result.errors.append(str(exc))
            return result

        prefix = self.android_capture._device_args(selected_serial)
        result.device = {
            "serial": selected_serial,
            "model": self._try_stdout(prefix + ["shell", "getprop", "ro.product.model"], result, "device model"),
            "android_version": self._try_stdout(prefix + ["shell", "getprop", "ro.build.version.release"], result, "Android version"),
            "sdk": self._try_stdout(prefix + ["shell", "getprop", "ro.build.version.sdk"], result, "Android SDK"),
        }

        events = max(1, int(monkey_event_count))
        lines = max(1, int(log_line_count))
        wait_seconds = max(0, int(wait_after_launch_seconds))
        result.execution = {
            "install_ok": False,
            "launch_ok": False,
            "monkey_ok": False,
            "monkey_event_count": events,
            "screenshots_captured": 0,
            "logs_captured": False,
        }

        install = self._run(prefix + ["install", "-r", "-t", str(apk_path)], timeout_seconds=90)
        install_log = self._write_text(output_dir / "install_output.log", self._sanitize_text(install["output"]))
        result.artifacts.append(self._artifact("log", install_log, "APK install output captured from adb.", anonymized=True))
        result.execution["install_ok"] = install["ok"]
        if not install["ok"]:
            result.errors.append(f"APK install failed: {install['output'][:1000]}")
            self._write_result_files(output_dir, result)
            return result

        self._run(prefix + ["logcat", "-c"])
        launch = self._run(
            prefix + ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            timeout_seconds=30,
        )
        launch_log = self._write_text(output_dir / "launch_output.log", self._sanitize_text(launch["output"]))
        result.artifacts.append(self._artifact("log", launch_log, "App launch output captured from adb monkey.", anonymized=True))
        result.execution["launch_ok"] = launch["ok"]
        if not launch["ok"]:
            result.errors.append(f"App launch failed: {launch['output'][:1000]}")

        if wait_seconds:
            time.sleep(wait_seconds)

        activity_tracking: dict[str, Any] = {
            "target_activity_after_launch": {},
            "target_activity_before_monkey": {},
            "foreground_activity_after_monkey": {},
            "foreground_activity_final": {},
            "was_target_foreground_after_launch": False,
            "was_target_foreground_final": False,
            "monkey_left_app": False,
            "retry_launch_attempted": False,
            "refocus_attempted_after_monkey": False,
            "refocus_success": False,
        }
        after_launch = self.get_foreground_activity(prefix, package_name, result, "after launch")
        activity_tracking["target_activity_after_launch"] = after_launch
        activity_tracking["was_target_foreground_after_launch"] = is_target_foreground(after_launch, package_name)
        if not activity_tracking["was_target_foreground_after_launch"]:
            activity_tracking["retry_launch_attempted"] = True
            self._launch_target(prefix, package_name, result, "retry after launch")
            if wait_seconds:
                time.sleep(wait_seconds)
            retry_launch = self.get_foreground_activity(prefix, package_name, result, "after launch retry")
            activity_tracking["target_activity_after_launch_retry"] = retry_launch
            if is_target_foreground(retry_launch, package_name):
                activity_tracking["target_activity_after_launch"] = retry_launch
                activity_tracking["was_target_foreground_after_launch"] = True
        self._capture_screenshot(prefix, output_dir / "001_after_launch.png", result, "Screenshot captured after launch.")

        before_monkey = self.get_foreground_activity(prefix, package_name, result, "before monkey")
        activity_tracking["target_activity_before_monkey"] = before_monkey
        monkey = self._run(
            prefix
            + [
                "shell",
                "monkey",
                "-p",
                package_name,
                "--pct-syskeys",
                "0",
                "--pct-nav",
                "5",
                "--pct-majornav",
                "5",
                "--ignore-crashes",
                "--ignore-timeouts",
                "--monitor-native-crashes",
                "-v",
                "--throttle",
                "250",
                str(events),
            ],
            timeout_seconds=max(45, int(events * 0.5)),
        )
        monkey_log = self._write_text(output_dir / "monkey_output.log", self._sanitize_text(monkey["output"]))
        result.artifacts.append(self._artifact("log", monkey_log, "Monkey UI interaction output captured from adb.", anonymized=True))
        result.execution["monkey_ok"] = monkey["ok"]
        if not monkey["ok"]:
            result.errors.append(f"Monkey UI events failed: {monkey['output'][:1000]}")

        after_monkey = self.get_foreground_activity(prefix, package_name, result, "after monkey")
        activity_tracking["foreground_activity_after_monkey"] = after_monkey
        activity_tracking["monkey_left_app"] = not is_target_foreground(after_monkey, package_name)
        self._capture_screenshot(prefix, output_dir / "002_after_monkey.png", result, "Screenshot captured after monkey UI events.")
        if activity_tracking["monkey_left_app"]:
            activity_tracking["refocus_attempted_after_monkey"] = True
            self._launch_target(prefix, package_name, result, "refocus after monkey")
            time.sleep(max(2, min(5, wait_seconds or 2)))
        final_activity = self.get_foreground_activity(prefix, package_name, result, "final")
        activity_tracking["foreground_activity_final"] = final_activity
        activity_tracking["was_target_foreground_final"] = is_target_foreground(final_activity, package_name)
        activity_tracking["refocus_success"] = bool(
            activity_tracking["refocus_attempted_after_monkey"] and activity_tracking["was_target_foreground_final"]
        )
        self._capture_screenshot(prefix, output_dir / "003_final_state.png", result, "Final state screenshot captured after dynamic analysis.")

        raw_logcat = self._try_stdout(prefix + ["logcat", "-d", "-t", str(lines)], result, "logcat capture", timeout_seconds=30)
        sanitized_logcat = self.sanitizer.sanitize(raw_logcat, self.settings.redact_ipv6)
        logcat_path = self._write_text(output_dir / "runtime_logcat_sanitized.log", sanitized_logcat)
        result.artifacts.append(self._artifact("log", logcat_path, "Sanitized runtime logcat captured after dynamic analysis.", anonymized=True))
        result.execution["logs_captured"] = bool(sanitized_logcat.strip())
        if not sanitized_logcat.strip():
            result.errors.append("Logcat capture failed: adb returned no runtime logs.")

        dumpsys_package = self._try_stdout(prefix + ["shell", "dumpsys", "package", package_name], result, "dumpsys package")
        top_activity = best_top_activity_excerpt(activity_tracking)
        meminfo = self._try_stdout(prefix + ["shell", "dumpsys", "meminfo", package_name], result, "dumpsys meminfo")
        ps_list = self._try_stdout(prefix + ["shell", "ps", "-A"], result, "process list")
        tcp_table = self._try_stdout(prefix + ["shell", "cat", "/proc/net/tcp"], result, "/proc/net/tcp")
        crash = detect_crash_anr(sanitized_logcat)

        result.runtime = {
            "process_present": package_name in ps_list,
            "crash_detected": crash["crash_detected"],
            "anr_detected": crash["anr_detected"],
            "top_activity_excerpt": top_activity[:2500],
            "meminfo_excerpt": meminfo[:2500],
            "tcp_table_excerpt": tcp_table[:2500],
            "network_table_excerpt": tcp_table[:2500],
            "activity_tracking": activity_tracking,
        }
        runtime_state = {
            "dumpsys_package_excerpt": dumpsys_package[:4000],
            "top_activity_excerpt": top_activity[:4000],
            "activity_tracking": activity_tracking,
            "meminfo_excerpt": meminfo[:4000],
            "process_list_excerpt": ps_list[:4000],
            "tcp_table_excerpt": tcp_table[:4000],
            "process_present": result.runtime["process_present"],
        }
        runtime_path = self._write_json(output_dir / "runtime_state.json", runtime_state)
        crash_summary_path = self._write_json(output_dir / "crash_summary.json", crash)
        result.artifacts.append(self._artifact("runtime_state", runtime_path, "Runtime state captured from dumpsys, ps, and /proc/net/tcp."))
        result.artifacts.append(self._artifact("crash_summary", crash_summary_path, "Crash and ANR indicators parsed from sanitized logcat."))
        if crash["excerpts"]:
            crash_log = self._write_text(output_dir / "crash_log.txt", "\n\n".join(crash["excerpts"]))
            result.artifacts.append(self._artifact("log", crash_log, "Crash or ANR excerpts parsed from runtime logcat.", anonymized=True))

        result.findings = self._findings(result)
        self._write_result_files(output_dir, result)
        return result

    def _select_device(self, device_serial: str | None) -> str:
        try:
            devices = self.android_capture.list_devices()
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

        if device_serial:
            selected = next((device for device in devices if device.get("serial") == device_serial), None)
            if selected is None:
                raise ValueError(f"Selected Android device '{device_serial}' was not found in adb devices.")
            if selected.get("state") != "device":
                raise ValueError(f"Selected Android device '{device_serial}' is {selected.get('state') or 'not ready'}.")
            return device_serial

        ready = [device for device in devices if device.get("state") == "device"]
        if not devices or not ready:
            offline = [device.get("serial") for device in devices if device.get("state") and device.get("state") != "device"]
            if offline:
                raise ValueError(f"No ready Android device is connected. Offline/unauthorized devices: {', '.join(map(str, offline))}.")
            raise ValueError("No Android emulator/device connected. Start an emulator or connect a device and verify adb devices.")
        if len(ready) > 1:
            raise ValueError("Multiple Android devices are connected. Select a device serial before running dynamic analysis.")
        return str(ready[0]["serial"])

    def _capture_screenshot(self, prefix: list[str], path: Path, result: DynamicAnalysisResult, description: str) -> None:
        capture = self._run(prefix + ["exec-out", "screencap", "-p"], text=False, timeout_seconds=20)
        output = capture["output"]
        png_bytes = self._normalize_png_payload(output) if capture["ok"] and isinstance(output, bytes) else None
        if png_bytes:
            path.write_bytes(png_bytes)
            result.artifacts.append(self._artifact("screenshot", path, description))
            result.execution["screenshots_captured"] = int(result.execution.get("screenshots_captured", 0)) + 1
            return
        detail = output.decode("utf-8", errors="ignore") if isinstance(output, bytes) else str(output)
        result.errors.append(f"Screenshot capture failed for {path.name}: {detail[:500]}")

    def get_foreground_activity(
        self,
        prefix: list[str],
        package_name: str,
        result: DynamicAnalysisResult,
        phase: str,
    ) -> dict[str, Any]:
        commands = [
            ("dumpsys activity activities", prefix + ["shell", "dumpsys", "activity", "activities"]),
            ("dumpsys window windows", prefix + ["shell", "dumpsys", "window", "windows"]),
        ]
        errors = []
        first_raw = ""
        for source, command in commands:
            completed = self._run(command, timeout_seconds=20)
            output = completed["output"]
            raw = output.decode("utf-8", errors="ignore") if isinstance(output, bytes) else str(output)
            if raw and not first_raw:
                first_raw = raw
            if not completed["ok"]:
                errors.append(f"{source}: {raw[:300]}")
                continue
            foreground = parse_foreground_activity(raw, source, package_name)
            if foreground.get("component"):
                return foreground
        if errors:
            result.errors.append(f"Foreground activity capture failed {phase}: {'; '.join(errors)[:800]}")
        return {
            "raw_excerpt": first_raw[:2500],
            "package": None,
            "activity": None,
            "component": None,
            "source": "foreground activity unavailable",
            "is_target_package": False,
            "error": "Could not parse foreground activity from dumpsys output." if first_raw else "No foreground activity dumpsys output.",
        }

    def _launch_target(self, prefix: list[str], package_name: str, result: DynamicAnalysisResult, phase: str) -> None:
        relaunch = self._run(
            prefix + ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            timeout_seconds=30,
        )
        if not relaunch["ok"]:
            result.errors.append(f"Target app launch failed during {phase}: {str(relaunch['output'])[:500]}")

    def _normalize_png_payload(self, payload: bytes) -> bytes | None:
        candidates = [
            payload,
            payload.replace(b"\r\r\n", b"\r\n"),
            payload.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"),
        ]
        for candidate in candidates:
            if self._is_valid_png(candidate):
                return candidate
        return None

    def _is_valid_png(self, payload: bytes) -> bool:
        return payload.startswith(b"\x89PNG\r\n\x1a\n") and payload.rstrip().endswith(b"IEND\xaeB`\x82")

    def _write_result_files(self, output_dir: Path, result: DynamicAnalysisResult) -> None:
        mobisef_payload = {
            "tool": "built-in-mobisef-style-dynamic-analysis",
            "analysis_type": "android_dynamic_apk",
            "device": result.device,
            "target": result.target,
            "execution": result.execution,
            "runtime": result.runtime,
            "findings": result.findings or self._findings(result),
            "errors": result.errors,
        }
        mobisef_path = self._write_json(output_dir / "mobisef_dynamic.json", mobisef_payload)
        summary_path = self._write_json(output_dir / "dynamic_run_summary.json", result.to_payload())
        result.artifacts.append(self._artifact("mobixler_dynamic", mobisef_path, "Structured Mobisef-style dynamic analysis import."))
        result.artifacts.append(self._artifact("dynamic_run_summary", summary_path, "Full dynamic analysis run summary."))

    def _findings(self, result: DynamicAnalysisResult) -> list[dict[str, str]]:
        findings = [
            {
                "rule_id": "dynamic-run-completed",
                "severity": "info",
                "title": "Dynamic run completed",
                "evidence": "APK was installed, launched, exercised, and runtime logs/screenshots were collected."
                if result.install_ok
                else "Dynamic run started but did not complete APK installation.",
            }
        ]
        if result.runtime.get("crash_detected"):
            findings.append(
                {
                    "rule_id": "runtime-crash-detected",
                    "severity": "high",
                    "title": "Runtime crash indicators detected",
                    "evidence": "Crash markers were observed in logcat. Review crash_log.txt for exact excerpts.",
                }
            )
        if result.runtime.get("anr_detected"):
            findings.append(
                {
                    "rule_id": "runtime-anr-detected",
                    "severity": "medium",
                    "title": "ANR indicators detected",
                    "evidence": "ANR markers were observed in logcat. Review crash_log.txt for exact excerpts.",
                }
            )
        tracking = result.runtime.get("activity_tracking") or {}
        if tracking.get("was_target_foreground_after_launch"):
            findings.append(
                {
                    "rule_id": "dynamic-target-foreground-after-launch",
                    "severity": "info",
                    "title": "Target app reached foreground after launch",
                    "evidence": "The foreground activity after launch belonged to the analyzed package.",
                }
            )
        elif tracking:
            findings.append(
                {
                    "rule_id": "dynamic-target-not-foreground-after-launch",
                    "severity": "low",
                    "title": "Target app was not foreground after launch",
                    "evidence": "The foreground activity after launch did not clearly belong to the analyzed package.",
                }
            )
        if tracking.get("monkey_left_app"):
            findings.append(
                {
                    "rule_id": "dynamic-monkey-left-target-app",
                    "severity": "low",
                    "title": "Monkey navigation left target app",
                    "evidence": "After Monkey execution, the foreground activity belonged to another package. The tool re-focused the target app before final screenshot.",
                }
            )
        if tracking and not tracking.get("was_target_foreground_final"):
            findings.append(
                {
                    "rule_id": "dynamic-final-refocus-failed",
                    "severity": "medium",
                    "title": "Target app was not foreground at final capture",
                    "evidence": "The final foreground activity did not belong to the analyzed package.",
                }
            )
        return findings

    def _try_stdout(self, args: list[str], result: DynamicAnalysisResult, label: str, timeout_seconds: int | None = None) -> str:
        completed = self._run(args, timeout_seconds=timeout_seconds)
        output = completed["output"]
        if not completed["ok"]:
            result.errors.append(f"{label} failed: {str(output)[:500]}")
            return ""
        if isinstance(output, bytes):
            return output.decode("utf-8", errors="ignore").strip()
        return str(output).strip()

    def _run(self, args: list[str], text: bool = True, timeout_seconds: int | None = None) -> dict[str, Any]:
        try:
            completed = self.android_capture._run(args, text=text, timeout_seconds=timeout_seconds)
        except ValueError as exc:
            return {"ok": False, "output": str(exc)}
        return {"ok": True, "output": completed.stdout}

    def _artifact(self, evidence_type: str, path: Path, description: str, anonymized: bool = False) -> DynamicArtifact:
        mime = "application/json" if path.suffix.lower() == ".json" else "text/plain"
        if path.suffix.lower() == ".png":
            mime = "image/png"
        return DynamicArtifact(evidence_type, path, path.name, mime, description, anonymized)

    def _write_text(self, path: Path, text: str | bytes) -> Path:
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="ignore")
        path.write_text(text or "", encoding="utf-8", errors="ignore")
        return path

    def _sanitize_text(self, text: str | bytes) -> str:
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="ignore")
        return self.sanitizer.sanitize(str(text), self.settings.redact_ipv6)

    def _write_json(self, path: Path, payload: dict[str, Any]) -> Path:
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path


def detect_crash_anr(logcat_text: str) -> dict[str, Any]:
    excerpts = []
    lines = logcat_text.splitlines()
    for index, line in enumerate(lines):
        if any(pattern.lower() in line.lower() for pattern in (*CRASH_PATTERNS, *ANR_PATTERNS)):
            start = max(0, index - 4)
            end = min(len(lines), index + 8)
            excerpts.append("\n".join(lines[start:end]))
    crash_detected = any(re.search(re.escape(pattern), logcat_text, flags=re.IGNORECASE) for pattern in CRASH_PATTERNS)
    anr_detected = any(re.search(re.escape(pattern), logcat_text, flags=re.IGNORECASE) for pattern in ANR_PATTERNS)
    return {
        "crash_detected": crash_detected,
        "anr_detected": anr_detected,
        "excerpts": excerpts[:8],
    }


def parse_foreground_activity(raw_text: str, source: str, package_name: str | None = None) -> dict[str, Any]:
    raw_excerpt = raw_text[:2500]
    for pattern in FOREGROUND_PATTERNS:
        match = pattern.search(raw_text)
        if not match:
            continue
        package = match.group(1)
        activity = match.group(2)
        component = normalize_component(package, activity)
        foreground = {
            "raw_excerpt": raw_excerpt,
            "package": package,
            "activity": activity,
            "component": component,
            "source": source,
            "is_target_package": False,
            "error": None,
        }
        foreground["is_target_package"] = is_target_foreground(foreground, package_name or "")
        return foreground
    return {
        "raw_excerpt": raw_excerpt,
        "package": None,
        "activity": None,
        "component": None,
        "source": source,
        "is_target_package": False,
        "error": "Could not parse foreground activity from dumpsys output.",
    }


def normalize_component(package: str, activity: str) -> str:
    if activity.startswith("/"):
        return f"{package}{activity}"
    return f"{package}/{activity}"


def is_target_foreground(foreground_info: dict[str, Any], package_name: str) -> bool:
    if not foreground_info or not package_name:
        return False
    package = foreground_info.get("package")
    component = foreground_info.get("component") or ""
    raw_excerpt = foreground_info.get("raw_excerpt") or ""
    return bool(package == package_name or str(component).startswith(f"{package_name}/") or package_name in raw_excerpt)


def best_top_activity_excerpt(activity_tracking: dict[str, Any]) -> str:
    after_launch = activity_tracking.get("target_activity_after_launch") or {}
    final = activity_tracking.get("foreground_activity_final") or {}
    after_monkey = activity_tracking.get("foreground_activity_after_monkey") or {}
    for candidate in (after_launch, final, after_monkey):
        if candidate.get("is_target_package") and candidate.get("raw_excerpt"):
            return str(candidate["raw_excerpt"])
    for candidate in (final, after_monkey, after_launch):
        if candidate.get("raw_excerpt"):
            return str(candidate["raw_excerpt"])
    return ""
