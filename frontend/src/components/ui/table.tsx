import { PropsWithChildren } from "react";

import { cn } from "../../lib/utils";

export function Table({ children, className }: PropsWithChildren<{ className?: string }>) {
  return <div className={cn("overflow-hidden rounded-2xl border border-slate-200 bg-white", className)}><table className="min-w-full divide-y divide-slate-200 text-sm">{children}</table></div>;
}
