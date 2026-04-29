import { FileArchive, FolderKanban, LayoutDashboard, ShieldCheck } from "lucide-react";

const items = [
  { label: "Dashboard", icon: LayoutDashboard },
  { label: "Audit Cases", icon: FolderKanban },
  { label: "Evidence", icon: ShieldCheck },
  { label: "Reports", icon: FileArchive },
];

export function Sidebar() {
  return (
    <aside className="rounded-[2rem] border border-white/70 bg-slate-950 px-5 py-6 text-white shadow-panel">
      <div className="mb-8">
        <p className="font-display text-xl">Evidence Collector</p>
        <p className="mt-2 text-sm text-slate-300">Defensive APK evidence and compliance workflows.</p>
      </div>
      <nav className="space-y-2">
        {items.map(({ label, icon: Icon }) => (
          <div key={label} className="flex items-center gap-3 rounded-2xl px-4 py-3 text-sm text-slate-200 transition hover:bg-white/10">
            <Icon className="h-4 w-4" />
            <span>{label}</span>
          </div>
        ))}
      </nav>
    </aside>
  );
}
