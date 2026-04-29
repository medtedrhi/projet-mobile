import { Badge } from "../../components/ui/badge";
import { Card } from "../../components/ui/card";
import { Table } from "../../components/ui/table";
import type { MissingIssue } from "../../types";

export function MissingEvidencePanel({ items }: { items: MissingIssue[] }) {
  return (
    <Card>
      <div className="mb-4">
        <h3 className="font-display text-xl">Missing Evidence Detection</h3>
        <p className="text-sm text-slate-500">Rules-based collection gaps with remediation-oriented guidance.</p>
      </div>
      <Table>
        <thead className="bg-slate-50 text-left text-slate-500">
          <tr>
            <th className="px-4 py-3">Severity</th>
            <th className="px-4 py-3">Title</th>
            <th className="px-4 py-3">Why It Matters</th>
            <th className="px-4 py-3">Recommendation</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id} className="border-t border-slate-100">
              <td className="px-4 py-3"><Badge tone={item.severity === "high" ? "danger" : item.severity === "medium" ? "warning" : "default"}>{item.severity}</Badge></td>
              <td className="px-4 py-3 font-semibold text-ink">{item.title}</td>
              <td className="px-4 py-3 text-sm text-slate-600">{item.rationale}</td>
              <td className="px-4 py-3 text-sm text-slate-600">{item.recommendation}</td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}
