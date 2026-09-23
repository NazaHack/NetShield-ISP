import type { JSX } from "react";

import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/lib/api/types";

/** Spanish labels for each severity, so the report reads in one language. */
const LABELS: Record<Severity, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  info: "Info",
};

/**
 * A severity as a coloured, labelled badge.
 *
 * The Badge variant names match the severity levels, and each carries a text
 * label, so the level is never conveyed by colour alone.
 */
export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}): JSX.Element {
  return (
    <Badge variant={severity} className={className}>
      {LABELS[severity]}
    </Badge>
  );
}
