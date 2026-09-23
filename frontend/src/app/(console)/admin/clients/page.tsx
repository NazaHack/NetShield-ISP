import { Building2 } from "lucide-react";
import type { JSX } from "react";

import { ClientManager } from "@/components/console/client-manager";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { listTenants } from "@/lib/api/console";
import { requirePlatformAdmin } from "@/lib/api/guards";

export const dynamic = "force-dynamic";

/**
 * Client administration.
 *
 * Reachable only by a platform administrator: the console layout hides the link
 * from tenant users, and the API refuses the underlying calls regardless, which
 * is the check that actually matters.
 */
export default async function AdminClientsPage(): Promise<JSX.Element> {
  await requirePlatformAdmin();
  const tenants = await listTenants();

  return (
    <div className="container flex flex-col gap-8 py-8">
      <div className="flex flex-col gap-1">
        <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight sm:text-3xl">
          <Building2 className="size-7 text-primary" aria-hidden="true" />
          ISP clients
        </h1>
        <p className="text-muted-foreground">
          Register customers and manage who from each of them can sign in.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Alta de clientes</CardTitle>
          <CardDescription>
            {tenants.total === 0
              ? "No clients yet. Register the first one to start auditing."
              : `${tenants.total} client${tenants.total === 1 ? "" : "s"} registered.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ClientManager tenants={tenants.items} />
        </CardContent>
      </Card>
    </div>
  );
}
