"use client";

import { Building2, Loader2, Plus, Trash2, Users } from "lucide-react";
import Link from "next/link";
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
import { createTenantAction, deleteTenantAction, type ActionResult } from "@/lib/actions";
import type { Tenant } from "@/lib/api/types";

const INITIAL: ActionResult = { ok: false };

/** Remove button for one client, with its own pending state. */
function RemoveClientButton({ tenant }: { tenant: Tenant }): JSX.Element {
  const [state, formAction, isPending] = useActionState(deleteTenantAction, INITIAL);

  useEffect(() => {
    if (state.message) {
      toast[state.ok ? "success" : "error"](state.message);
    }
  }, [state]);

  return (
    <form action={formAction}>
      <input type="hidden" name="tenantId" value={tenant.id} />
      <Button
        type="submit"
        variant="ghost"
        size="icon"
        disabled={isPending}
        aria-label={`Remove ${tenant.name}`}
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
 * Register and remove ISP customers.
 *
 * Removing a client is destructive in a way the table makes explicit: it takes
 * the client's ranges, scans, findings and sign-ins with it. Retaining a former
 * customer's network map is a liability rather than an asset, so the cascade is
 * intended, but the operator should not discover that afterwards.
 */
export function ClientManager({ tenants }: { tenants: Tenant[] }): JSX.Element {
  const [state, formAction, isPending] = useActionState(createTenantAction, INITIAL);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    if (state.ok) {
      toast.success(state.message ?? "Client registered.");
      formRef.current?.reset();
    }
  }, [state]);

  return (
    <div className="flex flex-col gap-8">
      <form ref={formRef} action={formAction} className="flex flex-col gap-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="flex flex-col gap-2">
            <Label htmlFor="name">Client name</Label>
            <Input id="name" name="name" placeholder="Acme ISP" required maxLength={200} />
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="code_name">Code name</Label>
            <Input
              id="code_name"
              name="code_name"
              placeholder="acme-isp"
              required
              maxLength={63}
              pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?"
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Lowercase letters, digits and single hyphens. This is the stable identifier other
              systems key on, and it cannot be changed later.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button type="submit" disabled={isPending} className="gap-2">
            {isPending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden="true" />
            ) : (
              <Plus className="size-4" aria-hidden="true" />
            )}
            Register client
          </Button>
        </div>

        {state.message && !state.ok ? (
          <Alert variant="destructive">
            <AlertTitle>The client was not registered</AlertTitle>
            <AlertDescription>{state.message}</AlertDescription>
          </Alert>
        ) : null}
      </form>

      {tenants.length === 0 ? (
        <p className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
          No ISP clients registered yet.
        </p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Client</TableHead>
              <TableHead>Code name</TableHead>
              <TableHead className="hidden sm:table-cell">Registered</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tenants.map((tenant) => (
              <TableRow key={tenant.id}>
                <TableCell className="font-medium">
                  <span className="flex items-center gap-2">
                    <Building2 className="size-4 text-muted-foreground" aria-hidden="true" />
                    {tenant.name}
                  </span>
                </TableCell>
                <TableCell className="font-mono text-sm">{tenant.code_name}</TableCell>
                <TableCell className="hidden font-tabular text-sm text-muted-foreground sm:table-cell">
                  {new Date(tenant.created_at).toLocaleDateString()}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    <Button asChild variant="ghost" size="sm" className="gap-1.5">
                      <Link href={`/admin/clients/${tenant.id}`}>
                        <Users className="size-4" aria-hidden="true" />
                        Sign-ins
                      </Link>
                    </Button>
                    <Button asChild variant="ghost" size="sm">
                      <Link href={`/tenants/${tenant.id}`}>Open</Link>
                    </Button>
                    <RemoveClientButton tenant={tenant} />
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}
