/**
 * Typed HTTP client for the NetShield-ISP API.
 *
 * Design notes:
 *
 * - **No implicit tenant.** The tenant a request belongs to is derived server
 *   side from the bearer token. The client never sends a tenant identifier that
 *   a user could tamper with, because a client-supplied tenant header is an
 *   authorisation bypass waiting to happen.
 * - **Every request is time-bounded.** A hung API call must not leave the
 *   dashboard spinning forever, so an AbortSignal timeout is always attached.
 * - **Errors are normalised.** Callers catch a single `ApiError` carrying the
 *   status, the server's message and the correlation id needed to find the
 *   matching backend log line.
 */

import { env, getServerApiBaseUrl } from "@/lib/env";

/** Shape of the uniform error envelope returned by the API. */
export interface ApiErrorPayload {
  /** Human-readable description of the failure. */
  detail: string;
  /** Correlation id matching the backend log entry, when available. */
  request_id?: string | null;
  /** Field-level validation failures, present on 422 responses. */
  errors?: Array<{ field: string; message: string; type: string }>;
}

/** Error thrown for any non-2xx API response or transport failure. */
export class ApiError extends Error {
  /** HTTP status code, or 0 when the request never reached the server. */
  public readonly status: number;

  /** Backend correlation id, used to locate the corresponding server log. */
  public readonly requestId: string | null;

  /** Field-level validation errors, when the API returned any. */
  public readonly fieldErrors: ApiErrorPayload["errors"];

  public constructor(
    message: string,
    status: number,
    requestId: string | null = null,
    fieldErrors: ApiErrorPayload["errors"] = undefined,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.requestId = requestId;
    this.fieldErrors = fieldErrors;
  }

  /** True when the failure is a client-side problem the user can correct. */
  public get isClientError(): boolean {
    return this.status >= 400 && this.status < 500;
  }

  /** True when the caller is unauthenticated or their session expired. */
  public get isUnauthorized(): boolean {
    return this.status === 401;
  }
}

/** Options accepted by {@link apiRequest}. */
export interface ApiRequestOptions {
  /** HTTP method. Defaults to `GET`. */
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** JSON-serialisable request body. */
  body?: unknown;
  /** Bearer token. Supplied explicitly so server components stay stateless. */
  accessToken?: string;
  /** Additional headers merged over the defaults. */
  headers?: Record<string, string>;
  /** Abort the request after this many milliseconds. Defaults to 30 seconds. */
  timeoutMs?: number;
  /** Next.js fetch cache behaviour. Defaults to `no-store`. */
  cache?: RequestCache;
  /** Force a specific base URL. Defaults to the correct one for the runtime. */
  baseUrl?: string;
}

/** Default request timeout. Scans run asynchronously, so no call should be slow. */
const DEFAULT_TIMEOUT_MS = 30_000;

/** True when this module is executing on the server rather than in a browser. */
const isServerRuntime = typeof window === "undefined";

function resolveBaseUrl(explicit?: string): string {
  if (explicit) {
    return explicit;
  }
  return isServerRuntime ? getServerApiBaseUrl() : env.apiBaseUrl;
}

function buildUrl(baseUrl: string, path: string): string {
  const normalisedBase = baseUrl.replace(/\/+$/, "");
  const normalisedPath = path.startsWith("/") ? path : `/${path}`;
  return `${normalisedBase}${normalisedPath}`;
}

async function parseErrorResponse(response: Response): Promise<ApiError> {
  const requestId = response.headers.get("X-Request-ID");

  let payload: ApiErrorPayload | null = null;
  try {
    payload = (await response.json()) as ApiErrorPayload;
  } catch {
    // A non-JSON error body (a proxy 502 page, for instance) is not worth
    // surfacing verbatim; the status line already says what happened.
    payload = null;
  }

  return new ApiError(
    payload?.detail ?? `Request failed with status ${response.status}`,
    response.status,
    payload?.request_id ?? requestId,
    payload?.errors,
  );
}

/**
 * Perform a typed JSON request against the NetShield-ISP API.
 *
 * @typeParam TResponse - Expected shape of the decoded response body.
 * @param path - API path, for example `/api/v1/scans`.
 * @param options - Request configuration.
 * @returns The decoded response body, or `undefined` for a 204 response.
 * @throws {ApiError} On any non-2xx response, timeout or network failure.
 */
export async function apiRequest<TResponse>(
  path: string,
  options: ApiRequestOptions = {},
): Promise<TResponse> {
  const {
    method = "GET",
    body,
    accessToken,
    headers = {},
    timeoutMs = DEFAULT_TIMEOUT_MS,
    cache = "no-store",
    baseUrl,
  } = options;

  const requestHeaders: Record<string, string> = {
    Accept: "application/json",
    ...headers,
  };

  if (body !== undefined) {
    requestHeaders["Content-Type"] = "application/json";
  }
  if (accessToken) {
    requestHeaders["Authorization"] = `Bearer ${accessToken}`;
  }

  let response: Response;
  try {
    response = await fetch(buildUrl(resolveBaseUrl(baseUrl), path), {
      method,
      headers: requestHeaders,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache,
      signal: AbortSignal.timeout(timeoutMs),
      credentials: "omit",
    });
  } catch (error) {
    const reason =
      error instanceof DOMException && error.name === "TimeoutError"
        ? `Request timed out after ${timeoutMs}ms`
        : "Unable to reach the NetShield-ISP API";
    throw new ApiError(reason, 0);
  }

  if (!response.ok) {
    throw await parseErrorResponse(response);
  }

  if (response.status === 204) {
    return undefined as TResponse;
  }

  return (await response.json()) as TResponse;
}
