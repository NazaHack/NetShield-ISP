import { ScrollText } from "lucide-react";
import type { JSX } from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { listAuditEvents } from "@/lib/api/console";
import { requirePlatformAdmin } from "@/lib/api/guards";

export const dynamic = "force-dynamic";

/** Failed and rate-limited logins stand out; everything else is neutral. */
function actionVariant(action: string): "critical" | "medium" | "secondary" {
  if (action === "login.failed") {
    return "medium";
  }
  if (action === "login.rate_limited") {
    return "critical";
  }
  return "secondary";
}

/**
 * The audit trail.
 *
 * A read-only, newest-first view of security-relevant actions. Administrator
 * only, and the API enforces that regardless of this page.
 */
export default async function AuditPage(): Promise<JSX.Element> {
  await requirePlatformAdmin();
  const events = await listAuditEvents({ limit: 100 });

  return (
    <div className="container flex flex-col gap-8 py-8">
      <div className="flex flex-col gap-1">
        <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight sm:text-3xl">
          <ScrollText className="size-7 text-primary" aria-hidden="true" />
          Audit trail
        </h1>
        <p className="text-muted-foreground">
          Security-relevant actions across the platform: sign-ins, account and client changes,
          password resets and scan launches. Newest first.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent events</CardTitle>
          <CardDescription>
            {events.total === 0
              ? "Nothing recorded yet."
              : `${events.total} event${events.total === 1 ? "" : "s"} recorded; showing the most recent.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {events.items.length === 0 ? (
            <p className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              As soon as anyone signs in or changes something, it appears here.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-44">When</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead className="hidden md:table-cell">Client</TableHead>
                  <TableHead className="hidden lg:table-cell">Target</TableHead>
                  <TableHead className="hidden xl:table-cell">Source IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.items.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell className="font-tabular text-sm text-muted-foreground">
                      {new Date(event.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Badge variant={actionVariant(event.action)}>{event.action}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {event.actor_email ?? "—"}
                    </TableCell>
                    <TableCell className="hidden font-mono text-sm md:table-cell">
                      {event.tenant_code_name ?? "—"}
                    </TableCell>
                    <TableCell className="hidden max-w-xs truncate font-mono text-sm lg:table-cell">
                      {event.target ?? "—"}
                    </TableCell>
                    <TableCell className="hidden font-mono text-sm text-muted-foreground xl:table-cell">
                      {event.source_ip ?? "—"}
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
