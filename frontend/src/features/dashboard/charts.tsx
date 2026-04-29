import { Bar, BarChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell } from "recharts";

import { Card } from "../../components/ui/card";
import { formatCount } from "../../lib/utils";

export function MetricsGrid({ score, evidenceCount, missingCount, caseCount }: { score: number; evidenceCount: number; missingCount: number; caseCount: number }) {
  const items = [
    { label: "Cases", value: formatCount(caseCount) },
    { label: "Evidence Items", value: formatCount(evidenceCount) },
    { label: "Missing Issues", value: formatCount(missingCount) },
    { label: "Completeness", value: `${score}%` },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {items.map((item) => (
        <Card key={item.label}>
          <p className="text-sm text-slate-500">{item.label}</p>
          <p className="mt-3 font-display text-3xl text-ink">{item.value}</p>
        </Card>
      ))}
    </div>
  );
}

export function EvidenceDistributionChart({ data }: { data: { name: string; value: number }[] }) {
  const palette = ["#0ea5e9", "#f97316", "#16a34a", "#e11d48", "#8b5cf6"];
  return (
    <Card className="h-80">
      <h3 className="font-display text-xl">Evidence Type Distribution</h3>
      <div className="mt-4 h-60">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" outerRadius={88} innerRadius={40}>
              {data.map((entry, index) => <Cell key={entry.name} fill={palette[index % palette.length]} />)}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}

export function MissingEvidenceChart({ data }: { data: { name: string; value: number }[] }) {
  return (
    <Card className="h-80">
      <h3 className="font-display text-xl">Missing Evidence by Category</h3>
      <div className="mt-4 h-60">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <XAxis dataKey="name" />
            <YAxis allowDecimals={false} />
            <Tooltip />
            <Bar dataKey="value" fill="#f97316" radius={[10, 10, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
