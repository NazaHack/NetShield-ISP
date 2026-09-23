import type { JSX } from "react";

import { TargetManager } from "@/components/console/target-manager";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { listTargets } from "@/lib/api/console";

export const dynamic = "force-dynamic";

/**
 * Address ranges assigned to the active client.
 */
export default async function TargetsPage({
  params,
}: {
  params: Promise<{ tenantId: string }>;
}): Promise<JSX.Element> {
  const { tenantId } = await params;
  const targets = await listTargets(tenantId);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Configuración de IPs</CardTitle>
        <CardDescription>
          The public addresses and subnets this client has authorised for auditing. Every scan
          covers exactly these ranges.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <TargetManager tenantId={tenantId} targets={targets.items} />
      </CardContent>
    </Card>
  );
}
