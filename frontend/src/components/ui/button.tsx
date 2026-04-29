import { cva, type VariantProps } from "class-variance-authority";
import { type ButtonHTMLAttributes } from "react";

import { cn } from "../../lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center rounded-xl px-4 py-2 text-sm font-semibold transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-ink text-white hover:bg-slate-800",
        secondary: "bg-white/80 text-ink ring-1 ring-slate-200 hover:bg-white",
        outline: "bg-transparent text-ink ring-1 ring-slate-300 hover:bg-white/50",
        destructive: "bg-coral text-white hover:bg-red-600",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonVariants>;

export function Button({ className, variant, ...props }: ButtonProps) {
  return <button className={cn(buttonVariants({ variant }), className)} {...props} />;
}
