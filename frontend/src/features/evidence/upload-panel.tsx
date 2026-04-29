import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../../api/client";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";
import { Input } from "../../components/ui/input";
import type { AndroidDevice } from "../../types";

export function UploadPanel({ caseId }: { caseId?: string }) {
  const [artifactType, setArtifactType] = useState("apk");
  const [file, setFile] = useState<File | null>(null);
  const [deviceSerial, setDeviceSerial] = useState("");
  const [runtimeLogLineCount, setRuntimeLogLineCount] = useState("400");
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
      <p className="mt-3 text-xs text-slate-500">Logs are sanitized by default to redact emails, tokens, IPs, and matched device identifiers.</p>
      {mutation.error ? <p className="mt-2 text-sm text-rose-600">{String(mutation.error)}</p> : null}
      {captureMutation.error ? <p className="mt-2 text-sm text-rose-600">{String(captureMutation.error)}</p> : null}
      {captureLogsMutation.error ? <p className="mt-2 text-sm text-rose-600">{String(captureLogsMutation.error)}</p> : null}
    </Card>
  );
}
