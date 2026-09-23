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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { launchAdhocScanAction, type AdhocLaunchResult } from "@/lib/actions";

const INITIAL: AdhocLaunchResult = { ok: false };

/**
 * Scan a network range without registering a client first.
 *
 * This is the shortest path through the product: type a range, press the
 * button, read the report. No customer, no target registration, no setup.
 *
 * The scan is still attributed to a tenant behind the scenes, because every
 * scan and result in the platform belongs to one, but the operator never sees
 * or manages that workspace.
 *
 * Validation is left to the API. It is the only place that can apply platform
 * policy, such as refusing link-local space or a prefix with host bits set, and
 * a second implementation here would drift out of step with it.
 */
export function QuickScan(): JSX.Element {
  const [state, formAction, isPending] = useActionState(launchAdhocScanAction, INITIAL);
  const { scanId, status, snapshot, inFlight, watch } = useScanProgress();

  useEffect(() => {
    if (state.ok && state.scanId) {
      watch(state.scanId);
    }
  }, [state, watch]);

  const disabled = isPending || inFlight;

  return (
    <div className="flex flex-col gap-4">
      <form action={formAction} className="flex flex-col gap-4">
        <div className="grid gap-4 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <div className="flex flex-col gap-2">
            <Label htmlFor="targets">Network range</Label>
            <Input
              id="targets"
              name="targets"
              placeholder="192.0.2.0/24"
              required
              className="font-mono"
              autoComplete="off"
              spellCheck={false}
            />
            <p className="text-xs text-muted-foreground">
              An address or CIDR block. Several may be separated by spaces or commas. A bare
              address is treated as a single host.
            </p>
          </div>

          <ProfileSelect defaultValue="fast" />
        </div>

        <CustomPorts />

        <div>
          <Button type="submit" size="lg" disabled={disabled} className="gap-2">
            {disabled ? (
              <Loader2 className="size-4 animate-spin" aria-hidden="true" />
            ) : (
              <RadioTower className="size-4" aria-hidden="true" />
            )}
            Ejecutar Verificación de Red
          </Button>
        </div>
      </form>

      {status !== null && scanId !== null ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border bg-muted/40 p-4">
          <ScanStatusBadge status={status} />
          <span className="font-tabular text-sm text-muted-foreground">
            {inFlight
              ? "Scanning. This panel updates on its own."
              : snapshot
                ? `${snapshot.host_count} host${snapshot.host_count === 1 ? "" : "s"}, ${snapshot.open_port_count} open port${snapshot.open_port_count === 1 ? "" : "s"}.`
                : "Finished."}
          </span>
          {status === "COMPLETED" ? (
            <Button asChild variant="secondary" size="sm" className="ml-auto">
              <Link href={`/scans/${scanId}`}>View report</Link>
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
