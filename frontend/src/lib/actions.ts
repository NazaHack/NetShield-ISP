"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { ApiError, apiRequest } from "@/lib/api-client";
import {
  createTarget,
  createTenant,
  createTenantUser,
  deleteTarget,
  deleteTenant,
  deleteTenantUser,
  launchAdhocScan,
  resetTenantUserPassword,
  launchScan,
} from "@/lib/api/console";
import type { LoginResponse, ScanProfile } from "@/lib/api/types";
import { NotAuthenticatedError } from "@/lib/server/api";
import { clearSessionToken, setSessionToken } from "@/lib/session";

/**
 * End the request with a redirect to sign-out when the session is no longer good.
 *
 * The access token can expire while the session cookie is still present, which
 * would otherwise leave every action returning a dead-end "Not authenticated"
 * message. Detecting that here sends the operator to a clean re-login instead.
 *
 * ``redirect`` throws, so this never returns when it fires; callers put it at
 * the top of their catch block, before building an error result.
 */
function redirectIfSignedOut(error: unknown): void {
  const expired =
    error instanceof NotAuthenticatedError ||
    (error instanceof ApiError && error.isUnauthorized);
  if (expired) {
    redirect("/api/console/sign-out");
  }
}

/** Valid scan profiles, so a tampered form field cannot become a bad payload. */
const SCAN_PROFILE_VALUES: readonly ScanProfile[] = ["fast", "balanced", "thorough"];

/** Read a scan profile from a form, falling back to balanced when absent or odd. */
function readProfile(formData: FormData): ScanProfile {
  const raw = String(formData.get("profile") ?? "");
  return SCAN_PROFILE_VALUES.includes(raw as ScanProfile) ? (raw as ScanProfile) : "balanced";
}

/** Ports may only be digits, commas and hyphens, matching what the API accepts. */
const PORT_RANGE_PATTERN = /^[0-9,\-]+$/;

/** Read an optional custom port range from a form.
 *
 * Returns undefined when the field is blank, so the scan uses the profile's own
 * ports. A malformed value is returned as-is: the API validates it and answers
 * with a 422 the operator sees, rather than being silently dropped here.
 */
function readPortRange(formData: FormData): string | undefined {
  const raw = String(formData.get("port_range") ?? "").trim();
  return raw.length > 0 ? raw : undefined;
}

/** Message for a rejected custom port range, shared by both launch actions. */
const BAD_PORT_RANGE = "Custom ports must be digits, commas and hyphens, e.g. 22,80,443 or 1-1024.";

/**
 * Server actions for every mutation the console performs.
 *
 * They run on the server, so the operator's token stays out of the browser
 * bundle, and they return a plain result object rather than throwing: a form
 * needs to render the reason a submission failed, not a stack trace.
 */

/** Outcome of an action, as rendered by a form. */
export interface ActionResult {
  ok: boolean;
  message?: string;
}

/** Translate an API failure into something an operator can act on. */
function describe(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    if (error.fieldErrors?.length) {
      return error.fieldErrors.map((entry) => entry.message).join("; ");
    }
    return error.message;
  }
  return fallback;
}

/**
 * Sign in with an email and password.
 *
 * The API returns a bearer token, which is stored in an `httpOnly` cookie and
 * never handed to the browser. The failure message is the API's own, which is
 * deliberately the same whether the address is unknown or the password wrong.
 */
export async function signIn(_previous: ActionResult, formData: FormData): Promise<ActionResult> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");

  if (!email || !password) {
    return { ok: false, message: "Enter your email and password." };
  }

  let session: LoginResponse;
  try {
    session = await apiRequest<LoginResponse>("/api/v1/auth/login", {
      method: "POST",
      body: { email, password },
    });
  } catch (error) {
    if (error instanceof ApiError && error.isUnauthorized) {
      return { ok: false, message: "Invalid email or password." };
    }
    return { ok: false, message: describe(error, "Could not reach the NetShield-ISP API.") };
  }

  await setSessionToken(session.access_token);
  redirect("/");
}

/** End the session and return to the sign-in page. */
export async function signOut(): Promise<void> {
  await clearSessionToken();
  redirect("/login");
}

/** Register a range for the active tenant. */
export async function addTargetAction(
  _previous: ActionResult,
  formData: FormData,
): Promise<ActionResult> {
  const tenantId = String(formData.get("tenantId") ?? "");
  const label = String(formData.get("label") ?? "").trim();
  const network = String(formData.get("ip_address_or_cidr") ?? "").trim();
  const description = String(formData.get("description") ?? "").trim();

  if (!tenantId || !label || !network) {
    return { ok: false, message: "A label and an address range are both required." };
  }

  try {
    await createTarget(tenantId, {
      label,
      ip_address_or_cidr: network,
      description: description || null,
    });
  } catch (error) {
    redirectIfSignedOut(error);
    return { ok: false, message: describe(error, "The range could not be registered.") };
  }

  revalidatePath(`/tenants/${tenantId}/targets`);
  return { ok: true, message: `${network} registered.` };
}

/** Remove a range from the active tenant. */
export async function removeTargetAction(
  _previous: ActionResult,
  formData: FormData,
): Promise<ActionResult> {
  const tenantId = String(formData.get("tenantId") ?? "");
  const targetId = String(formData.get("targetId") ?? "");

  if (!tenantId || !targetId) {
    return { ok: false, message: "Nothing to remove." };
  }

  try {
    await deleteTarget(tenantId, targetId);
  } catch (error) {
    redirectIfSignedOut(error);
    return { ok: false, message: describe(error, "The range could not be removed.") };
  }

  revalidatePath(`/tenants/${tenantId}/targets`);
  return { ok: true, message: "Range removed." };
}

/** Outcome of queueing a scan. */
export interface LaunchResult extends ActionResult {
  scanId?: string;
}

/**
 * Queue a scan for the active tenant.
 *
 * The operator supplies nothing: the ranges already registered for the tenant
 * are what gets scanned, which is the whole point of the one-click panel.
 */
export async function launchScanAction(
  _previous: LaunchResult,
  formData: FormData,
): Promise<LaunchResult> {
  const tenantId = String(formData.get("tenantId") ?? "");
  if (!tenantId) {
    return { ok: false, message: "No active client." };
  }

  const portRange = readPortRange(formData);
  if (portRange !== undefined && !PORT_RANGE_PATTERN.test(portRange)) {
    return { ok: false, message: BAD_PORT_RANGE };
  }

  try {
    const launched = await launchScan(tenantId, readProfile(formData), portRange);
    revalidatePath(`/tenants/${tenantId}`);
    return { ok: true, scanId: launched.scan_id, message: "Scan queued." };
  } catch (error) {
    redirectIfSignedOut(error);
    if (error instanceof ApiError && error.status === 409) {
      return {
        ok: false,
        message: "This client already has the maximum number of scans queued or running.",
      };
    }
    if (error instanceof ApiError && error.status === 422) {
      return {
        ok: false,
        message:
          "This client has no scannable range registered. Add one on the Ranges page first.",
      };
    }
    return { ok: false, message: describe(error, "The scan could not be queued.") };
  }
}


/** Register an ISP customer. */
export async function createTenantAction(
  _previous: ActionResult,
  formData: FormData,
): Promise<ActionResult> {
  const name = String(formData.get("name") ?? "").trim();
  const codeName = String(formData.get("code_name") ?? "").trim();

  if (!name || !codeName) {
    return { ok: false, message: "A name and a code name are both required." };
  }

  try {
    await createTenant({ name, code_name: codeName });
  } catch (error) {
    redirectIfSignedOut(error);
    if (error instanceof ApiError && error.status === 409) {
      return { ok: false, message: `The code name "${codeName}" is already taken.` };
    }
    return { ok: false, message: describe(error, "The client could not be registered.") };
  }

  revalidatePath("/admin/clients");
  return { ok: true, message: `${name} registered.` };
}

/** Remove an ISP customer and everything it owns. */
export async function deleteTenantAction(
  _previous: ActionResult,
  formData: FormData,
): Promise<ActionResult> {
  const tenantId = String(formData.get("tenantId") ?? "");
  if (!tenantId) {
    return { ok: false, message: "Nothing to remove." };
  }

  try {
    await deleteTenant(tenantId);
  } catch (error) {
    redirectIfSignedOut(error);
    return { ok: false, message: describe(error, "The client could not be removed.") };
  }

  revalidatePath("/admin/clients");
  return { ok: true, message: "Client removed, along with its ranges, scans and sign-ins." };
}

/** Create a sign-in for a client. */
export async function createTenantUserAction(
  _previous: ActionResult,
  formData: FormData,
): Promise<ActionResult> {
  const tenantId = String(formData.get("tenantId") ?? "");
  const email = String(formData.get("email") ?? "").trim();
  const fullName = String(formData.get("full_name") ?? "").trim();
  const password = String(formData.get("password") ?? "");

  if (!tenantId || !email || !fullName || !password) {
    return { ok: false, message: "Every field is required." };
  }

  try {
    await createTenantUser(tenantId, { email, full_name: fullName, password });
  } catch (error) {
    redirectIfSignedOut(error);
    if (error instanceof ApiError && error.status === 409) {
      return { ok: false, message: `An account already exists for ${email}.` };
    }
    return { ok: false, message: describe(error, "The sign-in could not be created.") };
  }

  revalidatePath(`/admin/clients/${tenantId}`);
  return { ok: true, message: `${email} can now sign in.` };
}

/** Remove a client's sign-in. */
export async function deleteTenantUserAction(
  _previous: ActionResult,
  formData: FormData,
): Promise<ActionResult> {
  const tenantId = String(formData.get("tenantId") ?? "");
  const userId = String(formData.get("userId") ?? "");

  if (!tenantId || !userId) {
    return { ok: false, message: "Nothing to remove." };
  }

  try {
    await deleteTenantUser(tenantId, userId);
  } catch (error) {
    redirectIfSignedOut(error);
    return { ok: false, message: describe(error, "The sign-in could not be removed.") };
  }

  revalidatePath(`/admin/clients/${tenantId}`);
  return { ok: true, message: "Sign-in removed." };
}

/** Reset the password of a client's sign-in.
 *
 * The new password is validated for length the same way creation is; the API
 * enforces the real rule and answers 422 if it is too weak.
 */
export async function resetTenantUserPasswordAction(
  _previous: ActionResult,
  formData: FormData,
): Promise<ActionResult> {
  const tenantId = String(formData.get("tenantId") ?? "");
  const userId = String(formData.get("userId") ?? "");
  const newPassword = String(formData.get("new_password") ?? "");

  if (!tenantId || !userId || !newPassword) {
    return { ok: false, message: "A new password is required." };
  }

  try {
    await resetTenantUserPassword(tenantId, userId, newPassword);
  } catch (error) {
    redirectIfSignedOut(error);
    return { ok: false, message: describe(error, "The password could not be reset.") };
  }

  revalidatePath(`/admin/clients/${tenantId}`);
  return { ok: true, message: "Password reset. Give the new one to its owner." };
}


/** Outcome of queueing an ad-hoc scan. */
export interface AdhocLaunchResult extends LaunchResult {
  targets?: string[];
}

/**
 * Queue a scan of a range typed in directly, with no client involved.
 *
 * This is the "just scan this network" path. The range is validated by the API,
 * which is the only place that can apply platform policy, and the scan is
 * attributed to the platform's own workspace.
 */
export async function launchAdhocScanAction(
  _previous: AdhocLaunchResult,
  formData: FormData,
): Promise<AdhocLaunchResult> {
  const raw = String(formData.get("targets") ?? "").trim();

  // Accept one per line, comma separated, or space separated: an operator
  // pasting from a spreadsheet or a terminal should not have to reformat.
  const targets = raw
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  if (targets.length === 0) {
    return { ok: false, message: "Enter at least one address or CIDR range." };
  }

  const portRange = readPortRange(formData);
  if (portRange !== undefined && !PORT_RANGE_PATTERN.test(portRange)) {
    return { ok: false, message: BAD_PORT_RANGE };
  }

  try {
    const launched = await launchAdhocScan({
      targets,
      profile: readProfile(formData),
      portRange,
    });
    revalidatePath("/");
    return {
      ok: true,
      scanId: launched.scan_id,
      targets: launched.targets,
      message: `Scanning ${launched.targets.join(", ")}.`,
    };
  } catch (error) {
    redirectIfSignedOut(error);
    if (error instanceof ApiError && error.status === 409) {
      return {
        ok: false,
        message: "There are already as many scans queued or running as the limit allows.",
      };
    }
    return { ok: false, message: describe(error, "The scan could not be queued.") };
  }
}
