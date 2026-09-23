import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground shadow",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        destructive: "border-transparent bg-destructive text-destructive-foreground shadow",
        outline: "text-foreground",
        // Finding severity. Always rendered alongside the severity label so the
        // information is never conveyed by colour alone.
        critical: "border-transparent bg-severity-critical text-white shadow",
        high: "border-transparent bg-severity-high text-white shadow",
        medium: "border-transparent bg-severity-medium text-black shadow",
        low: "border-transparent bg-severity-low text-white shadow",
        info: "border-transparent bg-severity-info text-white",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

/** Props accepted by {@link Badge}. */
export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

/** Compact status or severity label. */
function Badge({ className, variant, ...props }: BadgeProps): React.JSX.Element {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
