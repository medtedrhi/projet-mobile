import { Card } from "../../components/ui/card";
import type { CaseInsights } from "../../types";

export function AIInsightsPanel({
  insights,
  isLoading,
}: {
  insights?: CaseInsights;
  isLoading: boolean;
}) {
  return (
    <Card>
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h3 className="font-display text-xl">AI Insights</h3>
          <p className="text-sm text-slate-500">Evidence summary and gap narratives generated from the current case evidence.</p>
        </div>
        <p className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600">
          {insights?.provider_label || "Loading provider status"}
        </p>
      </div>
      {isLoading ? <p className="text-sm text-slate-500">Generating AI insights...</p> : null}
      {!isLoading && insights ? (
        <div className="space-y-4">
          <div className="rounded-2xl border border-slate-200 bg-slate-50/70 p-4">
            <p className="text-sm font-medium text-slate-700">Collection Summary</p>
            <p className="mt-2 text-sm leading-6 text-slate-600">{insights.collection_summary}</p>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-white p-4">
            <p className="text-sm font-medium text-slate-700">Gap Narratives</p>
            {insights.missing_explanations.length > 0 ? (
              <div className="mt-3 space-y-3">
                {insights.missing_explanations.map((item, index) => (
                  <div key={`gap-explanation-${index}`} className="rounded-2xl border border-slate-200 bg-slate-50/70 p-4">
                    <p className="text-sm font-semibold text-slate-800">{item.title}</p>
                    <p className="mt-2 text-sm leading-6 text-slate-600">{item.narrative}</p>
                    {item.why_it_matters ? (
                      <p className="mt-3 text-xs leading-5 text-slate-500">
                        <span className="font-medium text-slate-700">Why it matters:</span> {item.why_it_matters}
                      </p>
                    ) : null}
                    <p className="mt-2 text-xs leading-5 text-slate-500">
                      <span className="font-medium text-slate-700">Next step:</span> {item.next_step}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-2 text-sm text-slate-500">No gap narratives were generated because no missing evidence issues are currently present.</p>
            )}
          </div>
        </div>
      ) : null}
    </Card>
  );
}
