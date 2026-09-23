import "server-only";

import { ApiError, apiRequest, type ApiRequestOptions } from "@/lib/api-client";
import { getSessionToken } from "@/lib/session";

/**
 * Server-side access to the NetShield-ISP API.
 *
 * Every call originates on the Next.js server and carries the operator's token
 * from the session cookie. No component ever receives the credential, so it
 * cannot be forwarded to the browser by accident.
 */

/** Raised when the console has no usable session. */
export class NotAuthenticatedError extends Error {
  public constructor() {
    super("No operator session.");
    this.name = "NotAuthenticatedError";
  }
}

/**
 * Perform an authenticated request against the API.
 *
 * @typeParam TResponse - Expected shape of the decoded response body.
 * @param path - API path, for example `/api/v1/tenants`.
 * @param options - Request configuration, minus the token.
 * @throws {NotAuthenticatedError} When no session cookie is present.
 * @throws {ApiError} On any non-2xx response or transport failure.
 */
export async function serverApiRequest<TResponse>(
  path: string,
  options: Omit<ApiRequestOptions, "accessToken"> = {},
): Promise<TResponse> {
  const token = await getSessionToken();
  if (!token) {
    throw new NotAuthenticatedError();
  }
  return apiRequest<TResponse>(path, { ...options, accessToken: token });
}

/**
 * Perform a request and return `null` instead of throwing on a 404.
 *
 * The API answers a cross-tenant or absent resource identically, so a 404 is a
 * normal outcome the console renders as "not found" rather than an error.
 */
export async function serverApiRequestOrNull<TResponse>(
  path: string,
  options: Omit<ApiRequestOptions, "accessToken"> = {},
): Promise<TResponse | null> {
  try {
    return await serverApiRequest<TResponse>(path, options);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return null;
    }
    throw error;
  }
}
