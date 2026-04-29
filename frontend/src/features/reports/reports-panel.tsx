import { useMutation } from "@tanstack/react-query";

import { api } from "../../api/client";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";

export function ReportsPanel({ caseId }: { caseId?: string }) {
  const reportMutation = useMutation({ mutationFn: () => api.generateReport(caseId!) });
  const exportMutation = useMutation({ mutationFn: () => api.exportCase(caseId!) });

  return (
    <Card>
      <h3 className="font-display text-xl">Reports & Export</h3>
      <p className="mt-2 text-sm text-slate-500">Generate the HTML report and a ZIP evidence pack for delivery.</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <Button onClick={() => reportMutation.mutate()} disabled={!caseId || reportMutation.isPending}>Generate HTML Report</Button>
        <Button variant="secondary" onClick={() => exportMutation.mutate()} disabled={!caseId || exportMutation.isPending}>Build ZIP Pack</Button>
        {reportMutation.data ? <a className="rounded-xl bg-white px-4 py-2 text-sm font-semibold text-sky-700 ring-1 ring-sky-200" href={api.reportUrl(reportMutation.data.id)} target="_blank">Open Report</a> : null}
        {exportMutation.data ? <a className="rounded-xl bg-white px-4 py-2 text-sm font-semibold text-emerald-700 ring-1 ring-emerald-200" href={api.exportUrl(exportMutation.data.id)}>Download ZIP</a> : null}
      </div>
    </Card>
  );
}
