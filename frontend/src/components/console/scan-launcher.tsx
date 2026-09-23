"use client";

import { Loader2, RadioTower } from "lucide-react";
import Link from "next/link";
import { useActionState, useEffect, type JSX } from "react";

import { CustomPorts } from "@/components/console/custom-ports";
import { ProfileSelect } from "@/components/console/profile-select";
import { ScanStatusBadge } from "@/components/console/scan-status-badge";
import { useScanProgress } from "@/components/console/use-scan-progress";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { launchScanAction, type LaunchResult } from "@/lib/actions";
import type { ScanStatus } from "@/lib/api/types";

const INITIAL: LaunchResult = { ok: false };

/**
 * One-click scan panel with a live progress indicator.
 *
 * The operator supplies nothing: the ranges already registered for the client
 * are what gets scanned. Once a scan is queued the component polls its status
 * and stops as soon as the scan reaches a terminal state, so a completed scan
 * does not keep a timer running.
 */
export function ScanLauncher({
  tenantId,
  targetCount,
  activeScan,
}: {
  tenantId: string;
  targetCount: number;
  activeScan: { id: string; status: ScanStatus } | null;
}): JSX.Element {
  const [state, formAction, isPending] = useActionState(launchScanAction, INITIAL);
  const { scanId: watchedScanId, status, snapshot, inFlight, watch } = useScanProgress(
    activeScan,
  );

  // A freshly queued scan becomes the one being watched.
  useEffect(() => {
    if (state.ok && state.scanId) {
      watch(state.scanId);
    }
  }, [state, watch]);

  const hasTargets = targetCount > 0;
  const scanInFlight = inFlight;
  const disabled = isPending || scanInFlight || !hasTargets;

  return (
    <div className="flex flex-col gap-4">
      <form action={formAction} className="flex flex-col gap-4">
        <input type="hidden" name="tenantId" value={tenantId} />

        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
          <ProfileSelect defaultValue="balanced" />

          <Button type="submit" size="lg" disabled={disabled} className="gap-2">
            {isPending || scanInFlight ? (
              <Loader2 className="size-4 animate-spin" aria-hidden="true" />
            ) : (
              <RadioTower className="size-4" aria-hidden="true" />
            )}
            Ejecutar Verificación de Red
          </Button>
        </div>

        <CustomPorts />

        <p className="text-sm text-muted-foreground">
          {hasTargets
            ? `Scans the ${targetCount} range${targetCount === 1 ? "" : "s"} registered for this client.`
            : "Register at least one range before scanning."}
        </p>
      </form>

      {status !== null && watchedScanId !== null ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border bg-muted/40 p-4">
          <ScanStatusBadge status={status} />
          <span className="font-tabular text-sm text-muted-foreground">
            {scanInFlight
              ? "Scanning the client's ranges. This page updates on its own."
              : snapshot
                ? `${snapshot.host_count} host${snapshot.host_count === 1 ? "" : "s"}, ${snapshot.open_port_count} open port${snapshot.open_port_count === 1 ? "" : "s"}.`
                : "Finished."}
          </span>
          {status === "COMPLETED" ? (
            <Button asChild variant="secondary" size="sm" className="ml-auto">
              <Link href={`/tenants/${tenantId}/scans/${watchedScanId}`}>View report</Link>
            </Button>
          ) : null}
        </div>
      ) : null}

      {state.message && !state.ok ? (
        <Alert variant="destructive">
          <AlertTitle>The scan was not queued</AlertTitle>
          <AlertDescription>{state.message}</AlertDescription>
        </Alert>
      ) : null}
    </div>
  );
}
