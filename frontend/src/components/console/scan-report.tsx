import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import type { JSX } from "react";

import { AssessmentPanel } from "@/components/console/assessment-summary";
import { ChangeAlerts } from "@/components/console/change-alerts";
import { ExportButtons } from "@/components/console/export-buttons";
import { HostTable } from "@/components/console/host-table";
import { ScanStatusBadge } from "@/components/console/scan-status-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ScanDetail } from "@/lib/api/types";

/** One figure in the report summary. */
function Statistic({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-xs uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className="font-tabular text-lg font-semibold">{value}</dd>
    </div>
  );
}

/**
 * The detailed report for one scan.
 *
 * Shared by the per-client report page and the ad-hoc one, which differ only in
 * where "back" goes. A scan that has not finished shows its status rather than
 * a partial table: an incomplete picture on a page headed "report" is easy to
 * mistake for a final one.
 */
export function ScanReport({
  scan,
  backHref,
  backLabel,
}: {
  scan: ScanDetail;
  backHref: string;
  backLabel: string;
}): JSX.Element {
  const finished = scan.finished_at ? new Date(scan.finished_at).toLocaleString() : "—";

  return (
    <div className="flex flex-col gap-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Button asChild variant="ghost" size="sm" className="gap-2">
          <Link href={backHref}>
            <ArrowLeft className="size-4" aria-hidden="true" />
            {backLabel}
          </Link>
        </Button>

        {scan.status === "COMPLETED" ? <ExportButtons scan={scan} /> : null}
      </div>

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-col gap-1">
              <CardTitle>Reporte detallado</CardTitle>
              <CardDescription className="font-mono text-xs">{scan.id}</CardDescription>
            </div>
            <ScanStatusBadge status={scan.status} />
          </div>
        </CardHeader>

        <CardContent className="flex flex-col gap-6">
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Statistic label="Hosts" value={String(scan.host_count)} />
            <Statistic label="Open ports" value={String(scan.open_port_count)} />
            <Statistic label="Started" value={new Date(scan.created_at).toLocaleString()} />
            <Statistic label="Finished" value={finished} />
          </dl>

          {scan.status === "FAILED" ? (
            <Alert variant="destructive">
              <AlertTitle>This scan failed</AlertTitle>
              <AlertDescription>
                No findings were recorded. The worker logs the reason against this scan
                identifier.
              </AlertDescription>
            </Alert>
          ) : null}

          {scan.is_finished ? null : (
            <Alert>
              <AlertTitle>The scan is still running</AlertTitle>
              <AlertDescription>
                Results appear here once it finishes.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      <ChangeAlerts diff={scan.diff} />

      {scan.status === "COMPLETED" && scan.assessment ? (
        <AssessmentPanel assessment={scan.assessment} />
      ) : null}

      {scan.status === "COMPLETED" ? (
        <Card>
          <CardHeader>
            <CardTitle>Hosts y puertos abiertos</CardTitle>
            <CardDescription>
              Service and version strings are reported by the scanned host itself. Treat them as
              untrusted input when acting on them.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <HostTable results={scan.results} />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
