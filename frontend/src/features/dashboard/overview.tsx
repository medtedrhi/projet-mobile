import { useMemo } from "react";

import { Card } from "../../components/ui/card";
import type { AuditCase, EvidenceItem, MissingIssue } from "../../types";
import { EvidenceDistributionChart, MetricsGrid, MissingEvidenceChart } from "./charts";

export function DashboardOverview({ cases, evidence, missing }: { cases: AuditCase[]; evidence: EvidenceItem[]; missing: MissingIssue[] }) {
  const evidenceData = useMemo(() => {
    const counts = evidence.reduce<Record<string, number>>((acc, item) => {
      acc[item.evidence_type] = (acc[item.evidence_type] ?? 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [evidence]);

  const missingData = useMemo(() => {
    const counts = missing.reduce<Record<string, number>>((acc, item) => {
      acc[item.category] = (acc[item.category] ?? 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [missing]);

  const score = missing.length === 0 ? 100 : Math.max(0, 100 - missing.length * 10);

  return (
    <div className="space-y-6">
      <MetricsGrid score={score} evidenceCount={evidence.length} missingCount={missing.length} caseCount={cases.length} />
      <div className="grid gap-6 xl:grid-cols-[1.3fr_1fr]">
        <EvidenceDistributionChart data={evidenceData.length ? evidenceData : [{ name: "No data", value: 1 }]} />
        <MissingEvidenceChart data={missingData.length ? missingData : [{ name: "None", value: 0 }]} />
      </div>
      <Card>
        <h3 className="font-display text-xl">Audit Readiness</h3>
        <p className="mt-3 text-sm leading-6 text-slate-600">
          This workspace prioritizes defensive evidence collection, integrity verification, and traceability to MASVS, MASWE, and MASTG. Use the case panel to upload APKs and supporting artifacts, then generate a report and ZIP export once coverage looks healthy.
        </p>
      </Card>
    </div>
  );
}
