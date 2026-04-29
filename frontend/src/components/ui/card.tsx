import { PropsWithChildren } from "react";

import { cn } from "../../lib/utils";

export function Card({ children, className }: PropsWithChildren<{ className?: string }>) {
  return <section className={cn("rounded-3xl border border-white/70 bg-white/75 p-5 shadow-panel backdrop-blur", className)}>{children}</section>;
}
