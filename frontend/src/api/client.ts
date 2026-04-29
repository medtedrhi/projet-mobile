const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  listAndroidDevices: () => request("/android-devices"),
  listCases: () => request("/cases"),
  createCase: (payload: unknown) =>
    request("/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getCase: (caseId: string) => request(`/cases/${caseId}`),
  getCaseInsights: (caseId: string) => request(`/cases/${caseId}/insights`),
  getEvidence: (caseId: string) => request(`/cases/${caseId}/evidence`),
  getMapping: (caseId: string) => request(`/cases/${caseId}/mapping`),
  getMissingEvidence: (caseId: string) => request(`/cases/${caseId}/missing-evidence`),
  generateReport: (caseId: string) => request(`/cases/${caseId}/generate-report`, { method: "POST" }),
  exportCase: (caseId: string) => request(`/cases/${caseId}/export`, { method: "POST" }),
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
  uploadArtifact: (caseId: string, formData: FormData) =>
    request(`/cases/${caseId}/upload`, { method: "POST", body: formData }),
  evidenceContentUrl: (caseId: string, evidenceId: string) => `${API_BASE}/cases/${caseId}/evidence/${evidenceId}/content`,
  reportUrl: (reportId: string) => `${API_BASE.replace(/\/api$/, "")}/api/reports/${reportId}`,
  exportUrl: (exportId: string) => `${API_BASE}/exports/${exportId}/download`,
};
