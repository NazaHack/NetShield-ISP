import { Building2, LogOut, RadioTower, ScrollText, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import type { JSX, ReactNode } from "react";

import { TenantSelector } from "@/components/console/tenant-selector";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { signOut } from "@/lib/actions";
import { ApiError } from "@/lib/api-client";
import { getCurrentUser, getTenant, listTenants } from "@/lib/api/console";
import type { Tenant, User } from "@/lib/api/types";

/**
 * Console shell.
 *
 * Which clients the selector offers depends on who is signed in. A platform
 * administrator sees every customer; a tenant user sees only their own, because
 * the API would refuse anything else anyway and offering a choice that fails is
 * worse than offering none.
 *
 * The visible navigation is a convenience, not the boundary. Every endpoint
 * behind it performs its own authorisation, so hiding a link never becomes the
 * only thing standing between a caller and an action.
 */
export default async function ConsoleLayout({
  children,
  params,
}: {
  children: ReactNode;
  params?: Promise<{ tenantId?: string }>;
}): Promise<JSX.Element> {
  let user: User;
  try {
    user = await getCurrentUser();
  } catch (error) {
    // A session the API rejects cannot drive the console. The redirect goes
    // through the sign-out handler rather than straight to the sign-in page: a
    // server component may not modify cookies, and leaving the stale one in
    // place would have the middleware bounce the operator back here forever.
    if (error instanceof ApiError && (error.isUnauthorized || error.status === 403)) {
      redirect("/api/console/sign-out");
    }
    throw error;
  }

  const isAdmin = user.role === "PLATFORM_ADMIN";

  let tenants: Tenant[];
  if (isAdmin) {
    tenants = (await listTenants()).items;
  } else {
    // A tenant user has exactly one client, and it is the one their account
    // names. Fetching it by identifier keeps the selector honest without
    // exposing an endpoint they are not allowed to call.
    const own = user.tenant_id ? await getTenant(user.tenant_id) : null;
    tenants = own ? [own] : [];
  }

  const resolved = params ? await params : undefined;

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b bg-card">
        <div className="container flex flex-col gap-4 py-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-4">
            <Link href="/" className="flex items-center gap-2 text-primary">
              <ShieldCheck className="size-6" aria-hidden="true" />
              <span className="text-sm font-semibold uppercase tracking-widest">
                NetShield-ISP
              </span>
            </Link>

            {isAdmin ? (
              <nav className="flex items-center gap-1" aria-label="Sections">
                <Button asChild variant="secondary" size="sm" className="gap-2">
                  <Link href="/">
                    <RadioTower className="size-4" aria-hidden="true" />
                    Scan
                  </Link>
                </Button>
                <Button asChild variant="secondary" size="sm" className="gap-2">
                  <Link href="/admin/clients">
                    <Building2 className="size-4" aria-hidden="true" />
                    Clients
                  </Link>
                </Button>
                <Button asChild variant="secondary" size="sm" className="gap-2">
                  <Link href="/admin/audit">
                    <ScrollText className="size-4" aria-hidden="true" />
                    Audit
                  </Link>
                </Button>
              </nav>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <TenantSelector
              tenants={tenants}
              activeTenantId={resolved?.tenantId ?? null}
            />

            <div className="flex items-center gap-2">
              <div className="hidden flex-col items-end sm:flex">
                <span className="text-sm font-medium leading-tight">{user.full_name}</span>
                <span className="text-xs text-muted-foreground">{user.email}</span>
              </div>
              <Badge variant={isAdmin ? "default" : "secondary"}>
                {isAdmin ? "Admin" : "Client"}
              </Badge>
              <form action={signOut}>
                <Button type="submit" variant="ghost" size="icon" aria-label="Sign out">
                  <LogOut className="size-4" aria-hidden="true" />
                </Button>
              </form>
            </div>
          </div>
        </div>
      </header>

      <div className="flex-1">{children}</div>
    </div>
  );
}
