"use client";

import { Loader2, Trash2, UserPlus } from "lucide-react";
import { useActionState, useEffect, useRef, type JSX } from "react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
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
import {
  createTenantUserAction,
  deleteTenantUserAction,
  type ActionResult,
} from "@/lib/actions";
import type { User } from "@/lib/api/types";

const INITIAL: ActionResult = { ok: false };

/** Minimum password length, matching what the API enforces. */
const MIN_PASSWORD_LENGTH = 12;

/** Remove button for one sign-in. */
function RemoveUserButton({
  tenantId,
  user,
}: {
  tenantId: string;
  user: User;
}): JSX.Element {
  const [state, formAction, isPending] = useActionState(deleteTenantUserAction, INITIAL);

  useEffect(() => {
    if (state.message) {
      toast[state.ok ? "success" : "error"](state.message);
    }
  }, [state]);

  return (
    <form action={formAction}>
      <input type="hidden" name="tenantId" value={tenantId} />
      <input type="hidden" name="userId" value={user.id} />
      <Button
        type="submit"
        variant="ghost"
        size="icon"
        disabled={isPending}
        aria-label={`Remove ${user.email}`}
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
 * Create and remove the sign-ins belonging to one client.
 *
 * The password is set here and shown to nobody afterwards: the API stores only
 * an Argon2 hash, and no endpoint can return it. An operator who loses it
 * creates a new sign-in rather than recovering the old one.
 */
export function UserManager({
  tenantId,
  users,
}: {
  tenantId: string;
  users: User[];
}): JSX.Element {
  const [state, formAction, isPending] = useActionState(createTenantUserAction, INITIAL);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    if (state.ok) {
      toast.success(state.message ?? "Sign-in created.");
      formRef.current?.reset();
    }
  }, [state]);

  return (
    <div className="flex flex-col gap-8">
      <form ref={formRef} action={formAction} className="flex flex-col gap-4">
        <input type="hidden" name="tenantId" value={tenantId} />

        <div className="grid gap-4 sm:grid-cols-3">
          <div className="flex flex-col gap-2">
            <Label htmlFor="full_name">Full name</Label>
            <Input
              id="full_name"
              name="full_name"
              placeholder="Network Operations"
              required
              maxLength={200}
            />
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              placeholder="ops@acme-isp.example"
              required
              maxLength={254}
              autoComplete="off"
            />
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="password">Initial password</Label>
            <Input
              id="password"
              name="password"
              type="password"
              required
              minLength={MIN_PASSWORD_LENGTH}
              autoComplete="new-password"
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={isPending} className="gap-2">
            {isPending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden="true" />
            ) : (
              <UserPlus className="size-4" aria-hidden="true" />
            )}
            Create sign-in
          </Button>
          <p className="text-sm text-muted-foreground">
            At least {MIN_PASSWORD_LENGTH} characters. Only a hash is stored, so give the
            password to its owner now and have them change it.
          </p>
        </div>

        {state.message && !state.ok ? (
          <Alert variant="destructive">
            <AlertTitle>The sign-in was not created</AlertTitle>
            <AlertDescription>{state.message}</AlertDescription>
          </Alert>
        ) : null}
      </form>

      {users.length === 0 ? (
        <p className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
          This client has no sign-ins yet, so nobody from it can use the console.
        </p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Email</TableHead>
              <TableHead className="hidden sm:table-cell">Last sign-in</TableHead>
              <TableHead className="w-24">Status</TableHead>
              <TableHead className="w-16 text-right">Remove</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.map((user) => (
              <TableRow key={user.id}>
                <TableCell className="font-medium">{user.full_name}</TableCell>
                <TableCell className="font-mono text-sm">{user.email}</TableCell>
                <TableCell className="hidden font-tabular text-sm text-muted-foreground sm:table-cell">
                  {user.last_login_at
                    ? new Date(user.last_login_at).toLocaleString()
                    : "Never"}
                </TableCell>
                <TableCell>
                  <Badge variant={user.is_active ? "low" : "secondary"}>
                    {user.is_active ? "Active" : "Disabled"}
                  </Badge>
                </TableCell>
                <TableCell className="text-right">
                  <RemoveUserButton tenantId={tenantId} user={user} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}
