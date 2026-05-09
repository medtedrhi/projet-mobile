import type {
  AndroidDevice,
  ApkMetadataPreview,
  AuditCase,
  CaseSummary,
  CaseInsights,
  EvidenceItem,
  ExportBundle,
  FullDynamicAnalysisResult,
  GeneratedReport,
  MappingReference,
  MissingIssue,
} from "../types";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    const message = await response.text();
    let detail = message;
    try {
      const parsed = JSON.parse(message);
      detail = parsed.detail || message;
    } catch {
      detail = message;
    }
    throw new Error(detail || `Request failed with ${response.status}`);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

export const api = {
  listAndroidDevices: () => request<AndroidDevice[]>("/android-devices"),
  previewApkMetadata: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return request<ApkMetadataPreview>("/apk/metadata", { method: "POST", body: formData });
  },
  listCases: () => request<AuditCase[]>("/cases"),
  createCase: (payload: unknown) =>
    request<AuditCase>("/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  createCaseWithApk: (formData: FormData) =>
    request<AuditCase>("/cases/with-apk", {
      method: "POST",
      body: formData,
    }),
  getCase: (caseId: string) => request<{ case: AuditCase; summary: CaseSummary }>(`/cases/${caseId}`),
  deleteCase: (caseId: string) => request<void>(`/cases/${caseId}`, { method: "DELETE" }),
  getCaseInsights: (caseId: string) => request<CaseInsights>(`/cases/${caseId}/insights`),
  getEvidence: (caseId: string) => request<EvidenceItem[]>(`/cases/${caseId}/evidence`),
  getMapping: (caseId: string) => request<MappingReference[]>(`/cases/${caseId}/mapping`),
  getMissingEvidence: (caseId: string) => request<MissingIssue[]>(`/cases/${caseId}/missing-evidence`),
  generateReport: (caseId: string) => request<GeneratedReport>(`/cases/${caseId}/generate-report`, { method: "POST" }),
  exportCase: (caseId: string) => request<ExportBundle>(`/cases/${caseId}/export`, { method: "POST" }),
  captureScreenshot: (caseId: string, payload?: { device_serial?: string; source?: string; description?: string }) => {
    const params = new URLSearchParams();
    if (payload?.device_serial) params.set("device_serial", payload.device_serial);
    if (payload?.source) params.set("source", payload.source);
    if (payload?.description) params.set("description", payload.description);
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return request(`/cases/${caseId}/capture-screenshot${suffix}`, { method: "POST" });
  },
  captureRuntimeLogs: (
    caseId: string,
    payload?: { device_serial?: string; source?: string; description?: string; line_count?: number },
  ) => {
    const params = new URLSearchParams();
    if (payload?.device_serial) params.set("device_serial", payload.device_serial);
    if (payload?.source) params.set("source", payload.source);
    if (payload?.description) params.set("description", payload.description);
    if (payload?.line_count) params.set("line_count", String(payload.line_count));
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return request(`/cases/${caseId}/capture-runtime-logs${suffix}`, { method: "POST" });
  },
  runDynamicAnalysis: (
    caseId: string,
    payload?: { device_serial?: string; source?: string; monkey_event_count?: number; log_line_count?: number },
  ) => {
    const params = new URLSearchParams();
    if (payload?.device_serial) params.set("device_serial", payload.device_serial);
    if (payload?.source) params.set("source", payload.source);
    if (payload?.monkey_event_count) params.set("monkey_event_count", String(payload.monkey_event_count));
    if (payload?.log_line_count) params.set("log_line_count", String(payload.log_line_count));
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return request(`/cases/${caseId}/run-dynamic-analysis${suffix}`, { method: "POST" });
  },
  runFullDynamicAnalysis: (
    caseId: string,
    payload?: {
      file?: File | null;
      device_serial?: string;
      monkey_event_count?: number;
      log_line_count?: number;
      wait_after_launch_seconds?: number;
    },
  ) => {
    const params = new URLSearchParams();
    if (payload?.device_serial) params.set("device_serial", payload.device_serial);
    if (payload?.monkey_event_count) params.set("monkey_event_count", String(payload.monkey_event_count));
    if (payload?.log_line_count) params.set("log_line_count", String(payload.log_line_count));
    if (payload?.wait_after_launch_seconds !== undefined) {
      params.set("wait_after_launch_seconds", String(payload.wait_after_launch_seconds));
    }
    const formData = new FormData();
    const hasFile = Boolean(payload?.file);
    if (payload?.file) formData.append("file", payload.file);
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return request<FullDynamicAnalysisResult>(`/cases/${caseId}/run-full-dynamic-analysis${suffix}`, {
      method: "POST",
      body: hasFile ? formData : undefined,
    });
  },
  uploadArtifact: (caseId: string, formData: FormData) =>
    request(`/cases/${caseId}/upload`, { method: "POST", body: formData }),
  evidenceContentUrl: (caseId: string, evidenceId: string) => `${API_BASE}/cases/${caseId}/evidence/${evidenceId}/content`,
  reportUrl: (reportId: string) => `${API_BASE.replace(/\/api$/, "")}/api/reports/${reportId}`,
  exportUrl: (exportId: string) => `${API_BASE}/exports/${exportId}/download`,
};
