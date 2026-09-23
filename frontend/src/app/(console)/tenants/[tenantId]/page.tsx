import { History } from "lucide-react";
import Link from "next/link";
import type { JSX } from "react";

import { ScanLauncher } from "@/components/console/scan-launcher";
import { ScanStatusBadge } from "@/components/console/scan-status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { listScanHistory, listTargets } from "@/lib/api/console";
import { isTerminal } from "@/lib/api/types";

export const dynamic = "force-dynamic";

/** Format a timestamp for display, or a dash when absent. */
function formatMoment(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

/**
 * Client overview: the one-click scan panel and the scan history.
 */
export default async function TenantOverviewPage({
  params,
}: {
  params: Promise<{ tenantId: string }>;
}): Promise<JSX.Element> {
  const { tenantId } = await params;
  const [targets, history] = await Promise.all([
    listTargets(tenantId),
    listScanHistory(tenantId),
  ]);

  // A scan still in flight is picked up so that reloading the page keeps
  // showing the progress indicator rather than losing track of it.
  const active = history.items.find((scan) => !isTerminal(scan.status)) ?? null;

  return (
    <div className="flex flex-col gap-8">
      <Card>
        <CardHeader>
          <CardTitle>Panel de ejecución</CardTitle>
          <CardDescription>
            Runs a full audit of every range registered for this client. Nothing needs to be
            entered again.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScanLauncher
            tenantId={tenantId}
            targetCount={targets.total}
            activeScan={active ? { id: active.id, status: active.status } : null}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <History className="size-5 text-muted-foreground" aria-hidden="true" />
            Scan history
          </CardTitle>
          <CardDescription>
            {history.total === 0
              ? "This client has not been scanned yet."
              : `${history.total} scan${history.total === 1 ? "" : "s"}, newest first.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {history.items.length === 0 ? (
            <p className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              Run the first verification to build a baseline for change detection.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead className="hidden sm:table-cell">Finished</TableHead>
                  <TableHead className="text-right">Report</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {history.items.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell>
                      <ScanStatusBadge status={scan.status} />
                    </TableCell>
                    <TableCell className="font-tabular text-sm">
                      {formatMoment(scan.created_at)}
                    </TableCell>
                    <TableCell className="hidden font-tabular text-sm text-muted-foreground sm:table-cell">
                      {formatMoment(scan.finished_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button asChild variant="ghost" size="sm">
                        <Link href={`/tenants/${tenantId}/scans/${scan.id}`}>Open</Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
