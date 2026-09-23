"use client";

import { Loader2, Plus, Trash2 } from "lucide-react";
import { useActionState, useEffect, useRef, type JSX } from "react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { addTargetAction, removeTargetAction, type ActionResult } from "@/lib/actions";
import type { NetworkTarget } from "@/lib/api/types";

const INITIAL: ActionResult = { ok: false };

/** Remove button for one range, with its own pending state. */
function RemoveTargetButton({
  tenantId,
  target,
}: {
  tenantId: string;
  target: NetworkTarget;
}): JSX.Element {
  const [state, formAction, isPending] = useActionState(removeTargetAction, INITIAL);

  useEffect(() => {
    if (state.message) {
      toast[state.ok ? "success" : "error"](state.message);
    }
  }, [state]);

  return (
    <form action={formAction}>
      <input type="hidden" name="tenantId" value={tenantId} />
      <input type="hidden" name="targetId" value={target.id} />
      <Button
        type="submit"
        variant="ghost"
        size="icon"
        disabled={isPending}
        aria-label={`Remove ${target.ip_address_or_cidr}`}
      >
        {isPending ? (
          <Loader2 className="size-4 animate-spin" aria-hidden="true" />
        ) : (
          <Trash2 className="size-4" aria-hidden="true" />
        )}
      </Button>
    </form>
  );
}

/**
 * View, add and remove the address ranges assigned to the active client.
 *
 * Validation is deliberately left to the API rather than duplicated here. The
 * server is the only place that can apply platform policy, such as refusing
 * link-local space or a prefix with host bits set, and a second implementation
 * in the browser would drift out of step with it.
 */
export function TargetManager({
  tenantId,
  targets,
}: {
  tenantId: string;
  targets: NetworkTarget[];
}): JSX.Element {
  const [state, formAction, isPending] = useActionState(addTargetAction, INITIAL);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    if (state.ok) {
      toast.success(state.message ?? "Range registered.");
      formRef.current?.reset();
    }
  }, [state]);

  return (
    <div className="flex flex-col gap-8">
      <form ref={formRef} action={formAction} className="flex flex-col gap-4">
        <input type="hidden" name="tenantId" value={tenantId} />

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="label">Label</Label>
            <Input
              id="label"
              name="label"
              placeholder="CGNAT customer pool"
              required
              maxLength={150}
            />
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="ip_address_or_cidr">Address or CIDR</Label>
            <Input
              id="ip_address_or_cidr"
              name="ip_address_or_cidr"
              placeholder="100.64.0.0/22"
              required
              maxLength={45}
              className="font-mono"
            />
          </div>

          <div className="flex flex-col gap-2 sm:col-span-2">
            <Label htmlFor="description">Description (optional)</Label>
            <Input
              id="description"
              name="description"
              placeholder="Residential pool audited for exposed management interfaces"
              maxLength={2000}
            />
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button type="submit" disabled={isPending} className="gap-2">
            {isPending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden="true" />
            ) : (
              <Plus className="size-4" aria-hidden="true" />
            )}
            Add range
          </Button>
          <p className="text-sm text-muted-foreground">
            A bare address is stored as a single host. A prefix with host bits set is rejected
            rather than widened.
          </p>
        </div>

        {state.message && !state.ok ? (
          <Alert variant="destructive">
            <AlertTitle>The range was not registered</AlertTitle>
            <AlertDescription>{state.message}</AlertDescription>
          </Alert>
        ) : null}
      </form>

      {targets.length === 0 ? (
        <p className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
          No ranges registered for this client yet. Scans need at least one.
        </p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Label</TableHead>
              <TableHead>Range</TableHead>
              <TableHead className="hidden md:table-cell">Description</TableHead>
              <TableHead className="w-16 text-right">Remove</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {targets.map((target) => (
              <TableRow key={target.id}>
                <TableCell className="font-medium">{target.label}</TableCell>
                <TableCell className="font-mono font-tabular">
                  {target.ip_address_or_cidr}
                </TableCell>
                <TableCell className="hidden max-w-md truncate text-muted-foreground md:table-cell">
                  {target.description ?? "—"}
                </TableCell>
                <TableCell className="text-right">
                  <RemoveTargetButton tenantId={tenantId} target={target} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}
