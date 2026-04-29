import { Badge } from "../../components/ui/badge";
import { Card } from "../../components/ui/card";
import { Table } from "../../components/ui/table";
import type { AuditCase } from "../../types";

export function CasesTable({ cases, selectedCaseId, onSelect }: { cases: AuditCase[]; selectedCaseId?: string; onSelect: (caseId: string) => void }) {
  return (
    <Card>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h3 className="font-display text-xl">Audit Cases</h3>
          <p className="text-sm text-slate-500">Open a case to inspect evidence coverage and exports.</p>
        </div>
      </div>
      <Table>
        <thead className="bg-slate-50 text-left text-slate-500">
          <tr>
            <th className="px-4 py-3">App</th>
            <th className="px-4 py-3">Package</th>
            <th className="px-4 py-3">Auditor</th>
            <th className="px-4 py-3">Status</th>
          </tr>
        </thead>
        <tbody>
          {cases.map((item) => (
            <tr key={item.id} className={`cursor-pointer border-t border-slate-100 ${selectedCaseId === item.id ? "bg-sky-50" : "hover:bg-slate-50"}`} onClick={() => onSelect(item.id)}>
              <td className="px-4 py-3 font-semibold text-ink">{item.app_name}</td>
              <td className="px-4 py-3 text-slate-600">{item.package_name || "Unknown"}</td>
              <td className="px-4 py-3 text-slate-600">{item.auditor}</td>
              <td className="px-4 py-3"><Badge tone={item.status === "draft" ? "warning" : "success"}>{item.status}</Badge></td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}
