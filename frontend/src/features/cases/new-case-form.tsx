import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api } from "../../api/client";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";
import { Input } from "../../components/ui/input";
import type { AuditCase } from "../../types";

const initialState = {
  app_name: "",
  package_name: "",
  version_name: "",
  version_code: "",
  auditor: "",
  audit_date: new Date().toISOString().slice(0, 10),
  scope: "MASVS baseline evidence collection",
  notes: "",
};

export function NewCaseForm({ onCreated }: { onCreated?: (auditCase: AuditCase) => void }) {
  const [form, setForm] = useState(initialState);
  const [apkFile, setApkFile] = useState<File | null>(null);
  const [fileInputKey, setFileInputKey] = useState(0);
  const [metadataError, setMetadataError] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const metadataMutation = useMutation({
    mutationFn: api.previewApkMetadata,
    onMutate: () => setMetadataError(null),
    onSuccess: (metadata) => {
      setForm((current) => ({
        ...current,
        app_name: metadata.app_name || current.app_name,
        package_name: metadata.package_name || current.package_name,
        version_name: metadata.version_name || current.version_name,
        version_code: metadata.version_code ? String(metadata.version_code) : current.version_code,
      }));
    },
    onError: (error) => {
      setMetadataError(error instanceof Error ? error.message : String(error));
    },
  });
  const mutation = useMutation({
    mutationFn: async () => {
      if (!apkFile) {
        return api.createCase(form);
      }
      const formData = new FormData();
      Object.entries(form).forEach(([key, value]) => {
        if (value) formData.append(key, value);
      });
      formData.append("file", apkFile);
      return api.createCaseWithApk(formData);
    },
    onSuccess: (createdCase) => {
      queryClient.invalidateQueries({ queryKey: ["cases"] });
      queryClient.invalidateQueries({ queryKey: ["case", createdCase.id] });
      queryClient.invalidateQueries({ queryKey: ["evidence", createdCase.id] });
      queryClient.invalidateQueries({ queryKey: ["mapping", createdCase.id] });
      queryClient.invalidateQueries({ queryKey: ["missing-evidence", createdCase.id] });
      setForm(initialState);
      setApkFile(null);
      setFileInputKey((current) => current + 1);
      onCreated?.(createdCase);
    },
  });
  const canCreate = Boolean(form.auditor && (form.app_name || apkFile));
  const handleApkChange = (selectedFile: File | null) => {
    setApkFile(selectedFile);
    setMetadataError(null);
    if (selectedFile) {
      metadataMutation.mutate(selectedFile);
    }
  };

  return (
    <Card>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h3 className="font-display text-xl">New Audit Case</h3>
          <p className="text-sm text-slate-500">Attach an APK here to auto-fill package and version metadata.</p>
        </div>
        <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !canCreate}>Create Case</Button>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        {Object.entries(form).map(([key, value]) => (
          <label key={key} className="space-y-2 text-sm font-medium text-slate-600">
            {key.replace(/_/g, " ")}
            <Input value={value} onChange={(event) => setForm((current) => ({ ...current, [key]: event.target.value }))} />
          </label>
        ))}
        <label className="space-y-2 text-sm font-medium text-slate-600 md:col-span-2">
          APK for automatic metadata
          <Input
            key={fileInputKey}
            type="file"
            accept=".apk,application/vnd.android.package-archive"
            onChange={(event) => handleApkChange(event.target.files?.[0] ?? null)}
          />
          <span className="block text-xs font-normal text-slate-500">
            {metadataMutation.isPending
              ? "Reading APK manifest..."
              : "Selecting an APK fills app name, package name, version name, and version code before case creation."}
          </span>
          {metadataError ? <span className="block text-xs font-normal text-rose-600">{metadataError}</span> : null}
        </label>
      </div>
      {mutation.error ? <p className="mt-3 text-sm text-rose-600">{String(mutation.error)}</p> : null}
    </Card>
  );
}
