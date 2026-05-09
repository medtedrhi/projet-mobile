import { useMemo, useState } from "react";

import { Sidebar } from "./components/layout/sidebar";
import { CasesTable } from "./features/cases/cases-table";
import { NewCaseForm } from "./features/cases/new-case-form";
import { DashboardOverview } from "./features/dashboard/overview";
import { EvidenceExplorer } from "./features/evidence/explorer";
import { UploadPanel } from "./features/evidence/upload-panel";
import { MappingCoverage } from "./features/mapping/coverage";
import { AIInsightsPanel } from "./features/reports/ai-insights-panel";
import { MissingEvidencePanel } from "./features/reports/missing-evidence-panel";
import { ReportsPanel } from "./features/reports/reports-panel";
import { useCaseDetails, useCaseInsights, useCases, useEvidence, useMapping, useMissingEvidence } from "./hooks/use-api";
import { EmptyState } from "./pages/empty-state";

export default function App() {
  const [selectedCaseId, setSelectedCaseId] = useState<string | undefined>();
  const casesQuery = useCases();
  const caseDetailsQuery = useCaseDetails(selectedCaseId);
  const caseInsightsQuery = useCaseInsights(selectedCaseId);
  const evidenceQuery = useEvidence(selectedCaseId);
  const mappingQuery = useMapping(selectedCaseId);
  const missingQuery = useMissingEvidence(selectedCaseId);

  const cases = casesQuery.data ?? [];
  const evidence = evidenceQuery.data ?? [];
  const mapping = mappingQuery.data ?? [];
  const missing = missingQuery.data ?? [];

  const selectedSummary = useMemo(() => caseDetailsQuery.data?.summary, [caseDetailsQuery.data]);

  return (
    <div className="min-h-screen p-4 lg:p-6">
      <div className="mx-auto grid max-w-[1600px] gap-6 lg:grid-cols-[280px_1fr]">
        <Sidebar />
        <main className="space-y-6">
          <header className="rounded-[2rem] border border-white/70 bg-white/70 p-6 shadow-panel backdrop-blur">
            <p className="font-display text-3xl text-ink">Evidence Collector & Compliance Pack</p>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              Defensive audit tooling for Android APK assessments. Collect artifacts, normalize evidence, trace it to OWASP MASVS, MASWE, and MASTG, then export a compliance-ready pack.
            </p>
          </header>

          <DashboardOverview cases={cases} evidence={evidence} missing={missing} />
          <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
            <NewCaseForm onCreated={(auditCase) => setSelectedCaseId(auditCase.id)} />
            <CasesTable cases={cases} selectedCaseId={selectedCaseId} onSelect={setSelectedCaseId} />
          </div>

          {selectedCaseId ? (
            <div className="space-y-6">
              <section className="grid gap-4 md:grid-cols-4">
                <div className="rounded-3xl border border-white/70 bg-white/75 p-5 shadow-panel">
                  <p className="text-sm text-slate-500">Artifacts</p>
                  <p className="mt-3 font-display text-3xl">{selectedSummary?.total_artifacts ?? 0}</p>
                </div>
                <div className="rounded-3xl border border-white/70 bg-white/75 p-5 shadow-panel">
                  <p className="text-sm text-slate-500">Evidence Items</p>
                  <p className="mt-3 font-display text-3xl">{selectedSummary?.total_evidence_items ?? 0}</p>
                </div>
                <div className="rounded-3xl border border-white/70 bg-white/75 p-5 shadow-panel">
                  <p className="text-sm text-slate-500">Mappings</p>
                  <p className="mt-3 font-display text-3xl">{selectedSummary?.total_mappings ?? 0}</p>
                </div>
                <div className="rounded-3xl border border-white/70 bg-white/75 p-5 shadow-panel">
                  <p className="text-sm text-slate-500">Completeness</p>
                  <p className="mt-3 font-display text-3xl">{selectedSummary?.completeness_score ?? 0}%</p>
                </div>
              </section>
              <UploadPanel caseId={selectedCaseId} />
              <AIInsightsPanel insights={caseInsightsQuery.data} isLoading={caseInsightsQuery.isLoading} />
              <EvidenceExplorer caseId={selectedCaseId} evidence={evidence} />
              <MappingCoverage items={mapping} />
              <MissingEvidencePanel items={missing} />
              <ReportsPanel caseId={selectedCaseId} />
            </div>
          ) : (
            <EmptyState title="Select An Audit Case" description="Create a case or click an existing one to review evidence, traceability, and export actions." />
          )}
        </main>
      </div>
    </div>
  );
}
