import { Building2, History, Plus, RadioTower } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import type { JSX } from "react";

import { QuickScan } from "@/components/console/quick-scan";
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
import { ScanStatusBadge } from "@/components/console/scan-status-badge";
import { getCurrentUser, listOwnScans, listTenants } from "@/lib/api/console";

export const dynamic = "force-dynamic";

/**
 * Console home.
 *
 * A tenant user has exactly one client and goes straight to it. An operator
 * lands here, where the two things they actually came to do are both one click
 * away: scan a range, or set up a customer.
 *
 * Earlier this page redirected an operator into whichever client happened to be
 * first, which buried client administration behind a small link in the header
 * and made a one-off scan look impossible without setting up a customer first.
 */
export default async function ConsoleHome(): Promise<JSX.Element> {
  const user = await getCurrentUser();

  if (user.tenant_id) {
    redirect(`/tenants/${user.tenant_id}`);
  }

  const [tenants, recentScans] = await Promise.all([listTenants(), listOwnScans()]);

  return (
    <div className="container flex flex-col gap-8 py-8">
      <div className="flex flex-col gap-1">
        <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
          Verificación de red
        </h1>
        <p className="text-muted-foreground">
          Scan a range straight away, or open a client to audit the ranges registered for them.
        </p>
      </div>

      <Card className="border-primary/40">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <RadioTower className="size-5 text-primary" aria-hidden="true" />
            Verificación rápida
          </CardTitle>
          <CardDescription>
            No client needed. Type a network range and scan it.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <QuickScan />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <History className="size-5 text-muted-foreground" aria-hidden="true" />
            Verificaciones rápidas recientes
          </CardTitle>
          <CardDescription>
            {recentScans.total === 0
              ? "Scans run without a client appear here, with their reports and exports."
              : "Open a report to read the findings and export them as JSON or PDF."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {recentScans.items.length === 0 ? (
            <p className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              Nothing yet. Run a quick scan above and it will be listed here.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-40">Status</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead className="hidden sm:table-cell">Finished</TableHead>
                  <TableHead className="text-right">Report</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentScans.items.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell>
                      <ScanStatusBadge status={scan.status} />
                    </TableCell>
                    <TableCell className="font-tabular text-sm">
                      {new Date(scan.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="hidden font-tabular text-sm text-muted-foreground sm:table-cell">
                      {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : "—"}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button asChild variant="ghost" size="sm">
                        <Link href={`/scans/${scan.id}`}>Open report</Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-col gap-1">
              <CardTitle className="flex items-center gap-2">
                <Building2 className="size-5 text-muted-foreground" aria-hidden="true" />
                ISP clients
              </CardTitle>
              <CardDescription>
                {tenants.total === 0
                  ? "No customers registered yet. Register one to keep their ranges and scan history together."
                  : `${tenants.total} customer${tenants.total === 1 ? "" : "s"}, each with their own ranges, scans and sign-ins.`}
              </CardDescription>
            </div>

            <Button asChild className="gap-2">
              <Link href="/admin/clients">
                <Plus className="size-4" aria-hidden="true" />
                Add client
              </Link>
            </Button>
          </div>
        </CardHeader>

        <CardContent>
          {tenants.items.length === 0 ? (
            <p className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              A client groups the ranges you audit regularly, keeps their scan history, and gives
              their staff their own sign-in. One-off scans do not need one.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Client</TableHead>
                  <TableHead>Code name</TableHead>
                  <TableHead className="text-right">Open</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tenants.items.map((tenant) => (
                  <TableRow key={tenant.id}>
                    <TableCell className="font-medium">{tenant.name}</TableCell>
                    <TableCell className="font-mono text-sm">{tenant.code_name}</TableCell>
                    <TableCell className="text-right">
                      <Button asChild variant="ghost" size="sm">
                        <Link href={`/tenants/${tenant.id}`}>Open</Link>
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
