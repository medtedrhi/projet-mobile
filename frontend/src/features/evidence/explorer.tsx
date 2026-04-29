import { Badge } from "../../components/ui/badge";
import { Card } from "../../components/ui/card";
import { Table } from "../../components/ui/table";
import { api } from "../../api/client";
import type { EvidenceItem } from "../../types";

export function EvidenceExplorer({ caseId, evidence }: { caseId: string; evidence: EvidenceItem[] }) {
  const screenshots = evidence.filter((item) => item.evidence_type === "screenshot" && item.mime_type?.startsWith("image/"));

  return (
    <Card>
      <div className="mb-4">
        <h3 className="font-display text-xl">Evidence Explorer</h3>
        <p className="text-sm text-slate-500">Collected evidence items with integrity metadata and traceability hints.</p>
      </div>
      {screenshots.length > 0 ? (
        <div className="mb-6">
          <p className="mb-3 text-sm font-medium text-slate-700">Screenshot Preview</p>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {screenshots.map((item) => (
              <a
                key={item.id}
                className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm transition hover:shadow-md"
                href={api.evidenceContentUrl(caseId, item.id)}
                target="_blank"
                rel="noreferrer"
              >
                <img
                  className="h-52 w-full bg-slate-100 object-contain"
                  src={api.evidenceContentUrl(caseId, item.id)}
                  alt={item.original_filename || "Captured screenshot evidence"}
                  loading="lazy"
                />
                <div className="space-y-1 p-3">
                  <p className="truncate text-sm font-semibold text-ink">{item.original_filename || "Screenshot evidence"}</p>
                  <p className="text-xs text-slate-500">{item.source}</p>
                </div>
              </a>
            ))}
          </div>
        </div>
      ) : null}
      <Table>
        <thead className="bg-slate-50 text-left text-slate-500">
          <tr>
            <th className="px-4 py-3">Type</th>
            <th className="px-4 py-3">Source</th>
            <th className="px-4 py-3">Hash</th>
            <th className="px-4 py-3">Sensitivity</th>
          </tr>
        </thead>
        <tbody>
          {evidence.map((item) => (
            <tr key={item.id} className="border-t border-slate-100">
              <td className="px-4 py-3 font-semibold text-ink">{item.evidence_type}</td>
              <td className="px-4 py-3 text-slate-600">{item.source}</td>
              <td className="px-4 py-3 text-xs text-slate-500">{item.hash_sha256?.slice(0, 18) || "n/a"}</td>
              <td className="px-4 py-3"><Badge tone={item.anonymized_flag ? "success" : "default"}>{item.sensitivity_level}</Badge></td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}
