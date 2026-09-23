import { ArrowLeft, Users } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import type { JSX } from "react";

import { UserManager } from "@/components/console/user-manager";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getTenant, listTenantUsers } from "@/lib/api/console";
import { requirePlatformAdmin } from "@/lib/api/guards";

export const dynamic = "force-dynamic";

/**
 * Sign-ins belonging to one client.
 */
export default async function ClientUsersPage({
  params,
}: {
  params: Promise<{ tenantId: string }>;
}): Promise<JSX.Element> {
  await requirePlatformAdmin();

  const { tenantId } = await params;
  const tenant = await getTenant(tenantId);

  if (tenant === null) {
    notFound();
  }

  const users = await listTenantUsers(tenantId);

  return (
    <div className="container flex flex-col gap-8 py-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Button asChild variant="ghost" size="sm" className="gap-2">
          <Link href="/admin/clients">
            <ArrowLeft className="size-4" aria-hidden="true" />
            Back to clients
          </Link>
        </Button>

        <Button asChild variant="outline" size="sm">
          <Link href={`/tenants/${tenantId}`}>Open this client&apos;s console</Link>
        </Button>
      </div>

      <div className="flex flex-col gap-1">
        <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">{tenant.name}</h1>
        <p className="font-mono text-sm text-muted-foreground">{tenant.code_name}</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="size-5 text-muted-foreground" aria-hidden="true" />
            Sign-ins
          </CardTitle>
          <CardDescription>
            Accounts that can sign in as this client. They see only this client&apos;s ranges,
            scans and reports.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <UserManager tenantId={tenantId} users={users.items} />
        </CardContent>
      </Card>
    </div>
  );
}
