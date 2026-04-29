import { Card } from "../../components/ui/card";
import { Table } from "../../components/ui/table";
import type { MappingReference } from "../../types";

export function MappingCoverage({ items }: { items: MappingReference[] }) {
  return (
    <Card>
      <div className="mb-4">
        <h3 className="font-display text-xl">MASVS / MASWE / MASTG Traceability</h3>
        <p className="text-sm text-slate-500">Data-driven mapping output for collected evidence items.</p>
      </div>
      <Table>
        <thead className="bg-slate-50 text-left text-slate-500">
          <tr>
            <th className="px-4 py-3">Evidence</th>
            <th className="px-4 py-3">MASVS</th>
            <th className="px-4 py-3">MASWE</th>
            <th className="px-4 py-3">MASTG</th>
            <th className="px-4 py-3">Status</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id} className="border-t border-slate-100">
              <td className="px-4 py-3 text-xs text-slate-600">{item.evidence_item_id}</td>
              <td className="px-4 py-3 text-sm text-slate-700">{item.masvs_refs || "Unmapped"}</td>
              <td className="px-4 py-3 text-sm text-slate-700">{item.maswe_refs || "-"}</td>
              <td className="px-4 py-3 text-sm text-slate-700">{item.mastg_refs || "-"}</td>
              <td className="px-4 py-3 text-sm text-slate-600">{item.status}</td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}
