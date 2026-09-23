import { CheckCircle2, Clock, Loader2, XCircle } from "lucide-react";
import type { JSX } from "react";

import { Badge } from "@/components/ui/badge";
import type { ScanStatus } from "@/lib/api/types";
import { cn } from "@/lib/utils";

/** Visual treatment for each lifecycle state. */
const PRESENTATION: Record<
  ScanStatus,
  { label: string; variant: "secondary" | "low" | "critical" | "medium"; spin: boolean }
> = {
  PENDING: { label: "Queued", variant: "secondary", spin: false },
  RUNNING: { label: "Scanning", variant: "medium", spin: true },
  COMPLETED: { label: "Completed", variant: "low", spin: false },
  FAILED: { label: "Failed", variant: "critical", spin: false },
};

const ICONS: Record<ScanStatus, typeof Clock> = {
  PENDING: Clock,
  RUNNING: Loader2,
  COMPLETED: CheckCircle2,
  FAILED: XCircle,
};

/**
 * Status of a scan, shown as an icon and a word.
 *
 * The state is never conveyed by colour alone: each badge carries a label and a
 * distinct icon, so it stays readable in monochrome and under the common forms
 * of colour vision deficiency.
 */
export function ScanStatusBadge({
  status,
  className,
}: {
  status: ScanStatus;
  className?: string;
}): JSX.Element {
  const { label, variant, spin } = PRESENTATION[status];
  const Icon = ICONS[status];

  return (
    <Badge variant={variant} className={cn("gap-1.5", className)}>
      <Icon className={cn("size-3.5", spin && "animate-spin")} aria-hidden="true" />
      {label}
    </Badge>
  );
}
