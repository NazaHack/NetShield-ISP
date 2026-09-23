"use client";

import { Building2, Check, ChevronsUpDown } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, type JSX } from "react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { Tenant } from "@/lib/api/types";
import { cn } from "@/lib/utils";

/**
 * Picks the ISP customer the console is acting for.
 *
 * Switching navigates rather than setting client state, so the active client is
 * part of the URL. That keeps a link shareable, makes the browser's back button
 * behave, and means every server component below renders for exactly the client
 * in the path.
 */
export function TenantSelector({
  tenants,
  activeTenantId,
}: {
  tenants: Tenant[];
  activeTenantId: string | null;
}): JSX.Element {
  const router = useRouter();
  const [open, setOpen] = useState(false);

  const active = tenants.find((tenant) => tenant.id === activeTenantId) ?? null;

  function select(tenantId: string): void {
    setOpen(false);
    router.push(`/tenants/${tenantId}`);
  }

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          className="w-full justify-between gap-2 sm:w-72"
          aria-label="Select the active ISP client"
        >
          <span className="flex min-w-0 items-center gap-2">
            <Building2 className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <span className="truncate">{active ? active.name : "Select a client"}</span>
          </span>
          <ChevronsUpDown className="size-4 shrink-0 opacity-50" aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="start" className="w-[--radix-dropdown-menu-trigger-width]">
        <DropdownMenuLabel>ISP clients</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {tenants.length === 0 ? (
          <DropdownMenuItem disabled>No clients registered</DropdownMenuItem>
        ) : (
          tenants.map((tenant) => (
            <DropdownMenuItem
              key={tenant.id}
              onSelect={() => select(tenant.id)}
              className="flex items-center justify-between gap-2"
            >
              <span className="flex min-w-0 flex-col">
                <span className="truncate">{tenant.name}</span>
                <span className="truncate font-mono text-xs text-muted-foreground">
                  {tenant.code_name}
                </span>
              </span>
              <Check
                className={cn(
                  "size-4 shrink-0",
                  tenant.id === activeTenantId ? "opacity-100" : "opacity-0",
                )}
                aria-hidden="true"
              />
            </DropdownMenuItem>
          ))
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
