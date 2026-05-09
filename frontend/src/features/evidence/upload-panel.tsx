import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../../api/client";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";
import { Input } from "../../components/ui/input";
import type { AndroidDevice, FullDynamicAnalysisResult } from "../../types";

export function UploadPanel({ caseId }: { caseId?: string }) {
  const [artifactType, setArtifactType] = useState("apk");
  const [file, setFile] = useState<File | null>(null);
  const [deviceSerial, setDeviceSerial] = useState("");
  const [runtimeLogLineCount, setRuntimeLogLineCount] = useState("400");
  const [dynamicMonkeyEventCount, setDynamicMonkeyEventCount] = useState("120");
  const [waitAfterLaunchSeconds, setWaitAfterLaunchSeconds] = useState("5");
  const [dynamicResult, setDynamicResult] = useState<FullDynamicAnalysisResult | null>(null);
  const queryClient = useQueryClient();
  const devicesQuery = useQuery<AndroidDevice[]>({
    queryKey: ["android-devices"],
    queryFn: () => api.listAndroidDevices() as Promise<AndroidDevice[]>,
    refetchInterval: 10000,
  });
  const mutation = useMutation({
    mutationFn: async () => {
      if (!caseId || !file) return;
      const formData = new FormData();
      formData.append("artifact_type", artifactType);
      formData.append("source", "ui-upload");
      formData.append("file", file);
      return api.uploadArtifact(caseId, formData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["case", caseId] });
      queryClient.invalidateQueries({ queryKey: ["case-insights", caseId] });
      queryClient.invalidateQueries({ queryKey: ["evidence", caseId] });
      queryClient.invalidateQueries({ queryKey: ["mapping", caseId] });
      queryClient.invalidateQueries({ queryKey: ["missing-evidence", caseId] });
      setFile(null);
    },
  });
  const captureMutation = useMutation({
    mutationFn: async () => {
      if (!caseId) return;
      return api.captureScreenshot(caseId, {
        device_serial: deviceSerial || undefined,
        source: "adb-capture",
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["case", caseId] });
      queryClient.invalidateQueries({ queryKey: ["case-insights", caseId] });
      queryClient.invalidateQueries({ queryKey: ["evidence", caseId] });
      queryClient.invalidateQueries({ queryKey: ["mapping", caseId] });
      queryClient.invalidateQueries({ queryKey: ["missing-evidence", caseId] });
    },
  });
  const captureLogsMutation = useMutation({
    mutationFn: async () => {
      if (!caseId) return;
      return api.captureRuntimeLogs(caseId, {
        device_serial: deviceSerial || undefined,
        source: "adb-logcat",
        line_count: Number(runtimeLogLineCount) || 400,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["case", caseId] });
      queryClient.invalidateQueries({ queryKey: ["case-insights", caseId] });
      queryClient.invalidateQueries({ queryKey: ["evidence", caseId] });
      queryClient.invalidateQueries({ queryKey: ["mapping", caseId] });
      queryClient.invalidateQueries({ queryKey: ["missing-evidence", caseId] });
    },
  });
  const dynamicAnalysisMutation = useMutation({
    mutationFn: async () => {
      if (!caseId) return;
      return api.runDynamicAnalysis(caseId, {
        device_serial: deviceSerial || undefined,
        source: "adb-dynamic-analysis",
        monkey_event_count: Number(dynamicMonkeyEventCount) || 120,
        log_line_count: Number(runtimeLogLineCount) || 400,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["case", caseId] });
      queryClient.invalidateQueries({ queryKey: ["case-insights", caseId] });
      queryClient.invalidateQueries({ queryKey: ["evidence", caseId] });
      queryClient.invalidateQueries({ queryKey: ["mapping", caseId] });
      queryClient.invalidateQueries({ queryKey: ["missing-evidence", caseId] });
    },
  });
  const fullDynamicAnalysisMutation = useMutation({
    mutationFn: async () => {
      if (!caseId) return;
      setDynamicResult(null);
      return api.runFullDynamicAnalysis(caseId, {
        file: artifactType === "apk" ? file : null,
        device_serial: deviceSerial || undefined,
        monkey_event_count: Number(dynamicMonkeyEventCount) || 120,
        log_line_count: Number(runtimeLogLineCount) || 1000,
        wait_after_launch_seconds: Number(waitAfterLaunchSeconds) || 5,
      }) as Promise<FullDynamicAnalysisResult>;
    },
    onSuccess: (result) => {
      if (result) setDynamicResult(result);
      queryClient.invalidateQueries({ queryKey: ["case", caseId] });
      queryClient.invalidateQueries({ queryKey: ["case-insights", caseId] });
      queryClient.invalidateQueries({ queryKey: ["evidence", caseId] });
      queryClient.invalidateQueries({ queryKey: ["mapping", caseId] });
      queryClient.invalidateQueries({ queryKey: ["missing-evidence", caseId] });
      setFile(null);
    },
  });

  const devices = devicesQuery.data ?? [];

  return (
    <Card>
      <h3 className="font-display text-xl">Upload Or Capture Evidence</h3>
      <div className="mt-4 grid gap-4 md:grid-cols-[160px_1fr_auto]">
        <select className="rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm" value={artifactType} onChange={(event) => setArtifactType(event.target.value)}>
          <option value="apk">APK</option>
          <option value="screenshot">Screenshot</option>
          <option value="log">Runtime Log</option>
          <option value="mobsf">MobSF JSON</option>
          <option value="mobixler_dynamic">Mobixler Dynamic JSON</option>
          <option value="jadx">JADX Export</option>
        </select>
        <Input type="file" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
        <Button onClick={() => mutation.mutate()} disabled={!caseId || !file || mutation.isPending}>Upload</Button>
      </div>
      <div className="mt-5 grid gap-4 rounded-2xl border border-slate-200 bg-slate-50/70 p-4 md:grid-cols-[1fr_auto]">
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium text-slate-700">Automatic UI Screenshot</p>
            <p className="text-xs text-slate-500">
              Captures the current screen from a connected Android device or emulator through adb and stores it as screenshot evidence.
            </p>
          </div>
          <select
            className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm"
            value={deviceSerial}
            onChange={(event) => setDeviceSerial(event.target.value)}
          >
            <option value="">Auto-select single connected device</option>
            {devices.map((device) => (
              <option key={device.serial} value={device.serial}>
                {device.serial} - {device.model || device.product || device.state}
              </option>
            ))}
          </select>
          <p className="text-xs text-slate-500">
            {devicesQuery.isLoading
              ? "Checking connected devices..."
              : devices.length > 0
                ? `${devices.length} Android device${devices.length === 1 ? "" : "s"} detected.`
                : "No connected Android devices detected yet. Connect a device or start an emulator that appears in adb."}
          </p>
        </div>
        <div className="flex items-start md:items-center">
          <Button variant="secondary" onClick={() => captureMutation.mutate()} disabled={!caseId || captureMutation.isPending}>
            Capture Screenshot
          </Button>
        </div>
      </div>
      <div className="mt-4 grid gap-4 rounded-2xl border border-slate-200 bg-slate-50/70 p-4 md:grid-cols-[1fr_auto]">
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium text-slate-700">Automatic Runtime Logs</p>
            <p className="text-xs text-slate-500">
              Captures recent adb logcat output from the selected Android device or emulator, sanitizes it, and stores it as log evidence.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-[1fr_180px]">
            <select
              className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm"
              value={deviceSerial}
              onChange={(event) => setDeviceSerial(event.target.value)}
            >
              <option value="">Auto-select single connected device</option>
              {devices.map((device) => (
                <option key={`log-${device.serial}`} value={device.serial}>
                  {device.serial} - {device.model || device.product || device.state}
                </option>
              ))}
            </select>
            <Input
              type="number"
              min={50}
              max={5000}
              step={50}
              value={runtimeLogLineCount}
              onChange={(event) => setRuntimeLogLineCount(event.target.value)}
              placeholder="Lines"
            />
          </div>
          <p className="text-xs text-slate-500">
            Capture up to 5000 recent logcat lines. The saved evidence is sanitized automatically before storage.
          </p>
        </div>
        <div className="flex items-start md:items-center">
          <Button variant="secondary" onClick={() => captureLogsMutation.mutate()} disabled={!caseId || captureLogsMutation.isPending}>
            Capture Runtime Logs
          </Button>
        </div>
      </div>
      <div className="mt-4 grid gap-4 rounded-2xl border border-slate-200 bg-slate-50/70 p-4 md:grid-cols-[1fr_auto]">
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium text-slate-700">Mobixler-Style Dynamic APK Analysis</p>
            <p className="text-xs text-slate-500">
              Installs the latest uploaded APK, launches it, drives UI events, and collects runtime JSON evidence from adb.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-[1fr_180px]">
            <select
              className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm"
              value={deviceSerial}
              onChange={(event) => setDeviceSerial(event.target.value)}
            >
              <option value="">Auto-select single connected device</option>
              {devices.map((device) => (
                <option key={`dynamic-${device.serial}`} value={device.serial}>
                  {device.serial} - {device.model || device.product || device.state}
                </option>
              ))}
            </select>
            <Input
              type="number"
              min={1}
              max={5000}
              step={10}
              value={dynamicMonkeyEventCount}
              onChange={(event) => setDynamicMonkeyEventCount(event.target.value)}
              placeholder="Events"
            />
          </div>
          <p className="text-xs text-slate-500">
            Requires an APK in this case and an adb-connected Android device or emulator.
          </p>
        </div>
        <div className="flex items-start md:items-center">
          <Button variant="secondary" onClick={() => dynamicAnalysisMutation.mutate()} disabled={!caseId || dynamicAnalysisMutation.isPending}>
            Run Dynamic Analysis
          </Button>
        </div>
      </div>
      <div className="mt-4 grid gap-4 rounded-lg border border-slate-200 bg-white p-4 md:grid-cols-[1fr_auto]">
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium text-slate-700">Full Android Dynamic Analysis</p>
            <p className="text-xs text-slate-500">
              Uploads or reuses the latest APK, installs it on adb, launches it, captures screenshots and logs, generates the report, and builds the ZIP pack.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-[1fr_140px_140px_140px]">
            <select
              className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
              value={deviceSerial}
              onChange={(event) => setDeviceSerial(event.target.value)}
            >
              <option value="">Auto-select single connected device</option>
              {devices.map((device) => (
                <option key={`full-dynamic-${device.serial}`} value={device.serial}>
                  {device.serial} - {device.model || device.product || device.state}
                </option>
              ))}
            </select>
            <Input
              type="number"
              min={1}
              max={5000}
              step={10}
              value={dynamicMonkeyEventCount}
              onChange={(event) => setDynamicMonkeyEventCount(event.target.value)}
              placeholder="Events"
            />
            <Input
              type="number"
              min={50}
              max={5000}
              step={50}
              value={runtimeLogLineCount}
              onChange={(event) => setRuntimeLogLineCount(event.target.value)}
              placeholder="Log lines"
            />
            <Input
              type="number"
              min={0}
              max={120}
              value={waitAfterLaunchSeconds}
              onChange={(event) => setWaitAfterLaunchSeconds(event.target.value)}
              placeholder="Wait"
            />
          </div>
          {fullDynamicAnalysisMutation.isPending ? (
            <div className="grid gap-2 text-xs text-slate-600 md:grid-cols-4">
              {["Uploading APK", "Installing APK", "Launching app", "Capturing screenshots", "Collecting logs", "Generating report", "Building ZIP", "Complete"].map((step) => (
                <span key={step} className="rounded-md border border-slate-200 bg-slate-50 px-2 py-1">
                  {step}
                </span>
              ))}
            </div>
          ) : null}
          {dynamicResult ? (
            <div className="grid gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700 md:grid-cols-2">
              <span>Package name: {dynamicResult.package_name || "Unknown"}</span>
              <span>Device serial: {dynamicResult.device_serial || "Unknown"}</span>
              <span>Install status: {dynamicResult.install_ok ? "ok" : "failed"}</span>
              <span>Launch status: {dynamicResult.launch_ok ? "ok" : "failed"}</span>
              <span>Screenshots captured: {dynamicResult.screenshots_captured}</span>
              <span>Log file generated: {dynamicResult.log_file_generated ? "yes" : "no"}</span>
              <span>Crash detected: {dynamicResult.crash_detected ? "yes" : "no"}</span>
              <span>AI summary generated: {dynamicResult.ai_summary_generated ? "yes" : "no"}</span>
              {dynamicResult.errors.length ? <span className="text-rose-600 md:col-span-2">{dynamicResult.errors.join(" ")}</span> : null}
              {dynamicResult.export_id ? (
                <a className="md:col-span-2" href={api.exportUrl(dynamicResult.export_id)}>
                  <Button type="button">Download Evidence Pack</Button>
                </a>
              ) : null}
            </div>
          ) : null}
        </div>
        <div className="flex items-start md:items-center">
          <Button onClick={() => fullDynamicAnalysisMutation.mutate()} disabled={!caseId || fullDynamicAnalysisMutation.isPending}>
            Run Full Dynamic Analysis
          </Button>
        </div>
      </div>
      <p className="mt-3 text-xs text-slate-500">Logs are sanitized by default to redact emails, tokens, IPs, and matched device identifiers.</p>
      {mutation.error ? <p className="mt-2 text-sm text-rose-600">{String(mutation.error)}</p> : null}
      {captureMutation.error ? <p className="mt-2 text-sm text-rose-600">{String(captureMutation.error)}</p> : null}
      {captureLogsMutation.error ? <p className="mt-2 text-sm text-rose-600">{String(captureLogsMutation.error)}</p> : null}
      {dynamicAnalysisMutation.error ? <p className="mt-2 text-sm text-rose-600">{String(dynamicAnalysisMutation.error)}</p> : null}
      {fullDynamicAnalysisMutation.error ? <p className="mt-2 text-sm text-rose-600">{String(fullDynamicAnalysisMutation.error)}</p> : null}
    </Card>
  );
}
