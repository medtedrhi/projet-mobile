import type { ComponentProps } from "react";
import { Search } from "lucide-react";

import { Input } from "../ui/input";

export function SearchInput(props: ComponentProps<typeof Input>) {
  return (
    <div className="relative">
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
      <Input className="pl-9" {...props} />
    </div>
  );
}
