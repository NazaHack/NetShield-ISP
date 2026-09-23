import "server-only";

import { serverApiRequest, serverApiRequestOrNull } from "@/lib/server/api";

import type {
  NetworkTarget,
  Page,
  Scan,
  ScanDetail,
  ScanLaunchResponse,
  ScanProfile,
  Tenant,
  User,
} from "./types";

/**
 * Read and write operations the console performs against the API.
 *
 * Every function runs on the server. The tenant identifier passed here is only
 * ever used to build a path: the API decides what the operator's token may
 * reach, so a wrong identifier produces a 404 rather than another tenant's data.
 */

/** Read the signed-in account. */
export async function getCurrentUser(): Promise<User> {
  return serverApiRequest<User>("/api/v1/auth/me");
}

/** List the ISP customers the operator administers. */
export async function listTenants(limit = 200): Promise<Page<Tenant>> {
  return serverApiRequest<Page<Tenant>>(`/api/v1/tenants?limit=${limit}`);
}

/** Read one tenant, or `null` when the operator cannot see it. */
export async function getTenant(tenantId: string): Promise<Tenant | null> {
  return serverApiRequestOrNull<Tenant>(`/api/v1/tenants/${tenantId}`);
}

/** List a tenant's registered ranges. */
export async function listTargets(tenantId: string): Promise<Page<NetworkTarget>> {
  return serverApiRequest<Page<NetworkTarget>>(
    `/api/v1/tenants/${tenantId}/targets?limit=200`,
  );
}

/** Register a range for a tenant. */
export async function createTarget(
  tenantId: string,
  body: { label: string; ip_address_or_cidr: string; description: string | null },
): Promise<NetworkTarget> {
  return serverApiRequest<NetworkTarget>(`/api/v1/tenants/${tenantId}/targets`, {
    method: "POST",
    body,
  });
}

/** Remove a range from a tenant. */
export async function deleteTarget(tenantId: string, targetId: string): Promise<void> {
  await serverApiRequest<undefined>(`/api/v1/tenants/${tenantId}/targets/${targetId}`, {
    method: "DELETE",
  });
}

/** Queue a scan of ranges given directly, with no client involved.
 *
 * `portRange`, when given, overrides the profile's own port selection.
 */
export async function launchAdhocScan(body: {
  targets: string[];
  profile: ScanProfile;
  portRange?: string;
}): Promise<ScanLaunchResponse> {
  return serverApiRequest<ScanLaunchResponse>("/api/v1/scans/launch", {
    method: "POST",
    body: {
      targets: body.targets,
      profile: body.profile,
      ...(body.portRange ? { port_range: body.portRange } : {}),
    },
  });
}

/** Queue a scan of every range the tenant has registered.
 *
 * `portRange`, when given, overrides the profile's own port selection.
 */
export async function launchScan(
  tenantId: string,
  profile: ScanProfile,
  portRange?: string,
): Promise<ScanLaunchResponse> {
  return serverApiRequest<ScanLaunchResponse>("/api/v1/scans/launch", {
    method: "POST",
    body: {
      tenant_id: tenantId,
      profile,
      ...(portRange ? { port_range: portRange } : {}),
    },
  });
}

/** List the scans the signed-in account owns directly, newest first.
 *
 * For an operator these are their ad-hoc scans, whose workspace is hidden from
 * the customer list and therefore has no history page of its own.
 */
export async function listOwnScans(limit = 10): Promise<Page<Scan>> {
  return serverApiRequest<Page<Scan>>(`/api/v1/scans?limit=${limit}`);
}

/** Read a tenant's scan history, newest first. */
export async function listScanHistory(tenantId: string, limit = 20): Promise<Page<Scan>> {
  return serverApiRequest<Page<Scan>>(
    `/api/v1/tenants/${tenantId}/scans/history?limit=${limit}`,
  );
}

/** Read one scan with its findings, or `null` when it is not the operator's. */
export async function getScan(scanId: string): Promise<ScanDetail | null> {
  return serverApiRequestOrNull<ScanDetail>(`/api/v1/scans/${scanId}`);
}

/** Register an ISP customer. */
export async function createTenant(body: {
  name: string;
  code_name: string;
}): Promise<Tenant> {
  return serverApiRequest<Tenant>("/api/v1/tenants", { method: "POST", body });
}

/** Remove an ISP customer and everything it owns. */
export async function deleteTenant(tenantId: string): Promise<void> {
  await serverApiRequest<undefined>(`/api/v1/tenants/${tenantId}`, { method: "DELETE" });
}

/** List the sign-ins belonging to one client. */
export async function listTenantUsers(tenantId: string): Promise<Page<User>> {
  return serverApiRequest<Page<User>>(`/api/v1/tenants/${tenantId}/users?limit=200`);
}

/** Create a sign-in for one client. */
export async function createTenantUser(
  tenantId: string,
  body: { email: string; full_name: string; password: string },
): Promise<User> {
  return serverApiRequest<User>(`/api/v1/tenants/${tenantId}/users`, {
    method: "POST",
    body,
  });
}

/** Remove a sign-in belonging to one client. */
export async function deleteTenantUser(tenantId: string, userId: string): Promise<void> {
  await serverApiRequest<undefined>(`/api/v1/tenants/${tenantId}/users/${userId}`, {
    method: "DELETE",
  });
}

/** Reset the password of one of a client's sign-ins. */
export async function resetTenantUserPassword(
  tenantId: string,
  userId: string,
  newPassword: string,
): Promise<void> {
  await serverApiRequest<undefined>(
    `/api/v1/tenants/${tenantId}/users/${userId}/reset-password`,
    { method: "POST", body: { new_password: newPassword } },
  );
}
