import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api } from "../../api/client";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";
import { Table } from "../../components/ui/table";
import type { AuditCase } from "../../types";

export function CasesTable({
  cases,
  selectedCaseId,
  onSelect,
}: {
  cases: AuditCase[];
  selectedCaseId?: string;
  onSelect: (caseId: string | undefined) => void;
}) {
  const queryClient = useQueryClient();
  const deleteMutation = useMutation({
    mutationFn: api.deleteCase,
    onSuccess: (_result, deletedCaseId) => {
      queryClient.invalidateQueries({ queryKey: ["cases"] });
      queryClient.removeQueries({ queryKey: ["case", deletedCaseId] });
      queryClient.removeQueries({ queryKey: ["case-insights", deletedCaseId] });
      queryClient.removeQueries({ queryKey: ["evidence", deletedCaseId] });
      queryClient.removeQueries({ queryKey: ["mapping", deletedCaseId] });
      queryClient.removeQueries({ queryKey: ["missing-evidence", deletedCaseId] });
      if (selectedCaseId === deletedCaseId) {
        onSelect(undefined);
      }
    },
  });

  const handleDelete = (caseId: string, appName: string) => {
    if (!window.confirm(`Delete audit case "${appName}"? This removes the case and its database evidence records.`)) {
      return;
    }
    deleteMutation.mutate(caseId);
  };

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
            <th className="px-4 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {cases.map((item) => (
            <tr key={item.id} className={`cursor-pointer border-t border-slate-100 ${selectedCaseId === item.id ? "bg-sky-50" : "hover:bg-slate-50"}`} onClick={() => onSelect(item.id)}>
              <td className="px-4 py-3 font-semibold text-ink">{item.app_name}</td>
              <td className="px-4 py-3 text-slate-600">{item.package_name || "Unknown"}</td>
              <td className="px-4 py-3 text-slate-600">{item.auditor}</td>
              <td className="px-4 py-3"><Badge tone={item.status === "draft" ? "warning" : "success"}>{item.status}</Badge></td>
              <td className="px-4 py-3 text-right">
                <Button
                  variant="secondary"
                  onClick={(event) => {
                    event.stopPropagation();
                    handleDelete(item.id, item.app_name);
                  }}
                  disabled={deleteMutation.isPending}
                >
                  Delete
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
      {deleteMutation.error ? <p className="mt-3 text-sm text-rose-600">{String(deleteMutation.error)}</p> : null}
    </Card>
  );
}
