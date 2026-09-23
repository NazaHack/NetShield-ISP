import { ShieldAlert, ShieldCheck } from "lucide-react";
import type { JSX } from "react";

import { SeverityBadge } from "@/components/console/severity-badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SEVERITY_ORDER, type AssessmentSummary, type Severity } from "@/lib/api/types";

/**
 * The security headline of a report: counts by severity and the findings that
 * deserve attention, above the raw host table.
 *
 * The severities are a heuristic triage of what each open port exposes, not a
 * vulnerability scan; the copy says so, so an operator does not read a "low" as
 * a clean bill of health.
 */
export function AssessmentPanel({
  assessment,
}: {
  assessment: AssessmentSummary;
}): JSX.Element {
  const hasConcerns = assessment.notable.length > 0;

  return (
    <Card className={hasConcerns ? "border-severity-critical/50" : undefined}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {hasConcerns ? (
            <ShieldAlert className="size-5 text-severity-critical" aria-hidden="true" />
          ) : (
            <ShieldCheck className="size-5 text-severity-low" aria-hidden="true" />
          )}
          Evaluación de exposición
        </CardTitle>
        <CardDescription>
          Triage of what each open port exposes, worst first. A heuristic by service, not a
          vulnerability scan: a low rating means &ldquo;not obviously dangerous to expose&rdquo;,
          not &ldquo;safe&rdquo;.
        </CardDescription>
      </CardHeader>

      <CardContent className="flex flex-col gap-6">
        <div className="flex flex-wrap gap-2">
          {SEVERITY_ORDER.map((level) => {
            const count = assessment.counts[level] ?? 0;
            if (count === 0) {
              return null;
            }
            return (
              <span key={level} className="flex items-center gap-2 rounded-md border px-3 py-1.5">
                <SeverityBadge severity={level} />
                <span className="font-tabular text-sm font-semibold">{count}</span>
              </span>
            );
          })}
        </div>

        {hasConcerns ? (
          <div className="flex flex-col gap-2">
            <p className="text-sm font-medium">
              Findings to review ({assessment.notable.length})
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-28">Severity</TableHead>
                  <TableHead className="w-40">Host</TableHead>
                  <TableHead className="w-24">Port</TableHead>
                  <TableHead>Why</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assessment.notable.map((finding) => (
                  <TableRow key={`${finding.host_ip}-${finding.protocol}-${finding.port}`}>
                    <TableCell>
                      <SeverityBadge severity={finding.severity as Severity} />
                    </TableCell>
                    <TableCell className="font-mono font-tabular text-sm">
                      {finding.host_ip}
                    </TableCell>
                    <TableCell className="font-tabular text-sm">
                      {finding.port}/{finding.protocol}
                      {finding.service ? ` (${finding.service})` : ""}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {finding.reason}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            Nothing rated high or critical. The open ports found are expected or low-risk to
            expose, but review them against what each host is meant to offer.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
