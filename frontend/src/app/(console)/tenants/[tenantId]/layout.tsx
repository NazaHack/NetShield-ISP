import { notFound } from "next/navigation";
import Link from "next/link";
import type { JSX, ReactNode } from "react";

import { getTenant } from "@/lib/api/console";

/**
 * Layout for a single client.
 *
 * Resolving the client here means every page below it can assume the client
 * exists and is one the operator may see. A client that does not exist, or that
 * belongs to somebody else, produces the same 404 in both cases: the API does
 * not distinguish them, and neither does this console.
 */
export default async function TenantLayout({
  children,
  params,
}: {
  children: ReactNode;
  params: Promise<{ tenantId: string }>;
}): Promise<JSX.Element> {
  const { tenantId } = await params;
  const tenant = await getTenant(tenantId);

  if (tenant === null) {
    notFound();
  }

  return (
    <div className="container flex flex-col gap-8 py-8">
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">{tenant.name}</h1>
          <p className="font-mono text-sm text-muted-foreground">{tenant.code_name}</p>
        </div>

        <nav className="flex gap-1 border-b" aria-label="Client sections">
          <TabLink href={`/tenants/${tenantId}`}>Overview</TabLink>
          <TabLink href={`/tenants/${tenantId}/targets`}>Ranges</TabLink>
        </nav>
      </div>

      {children}
    </div>
  );
}

/** One tab in the client navigation. */
function TabLink({ href, children }: { href: string; children: ReactNode }): JSX.Element {
  return (
    <Link
      href={href}
      className="rounded-t-md px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
    >
      {children}
    </Link>
  );
}
