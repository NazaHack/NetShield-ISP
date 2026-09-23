/**
 * Validated access to the public runtime environment.
 *
 * Only `NEXT_PUBLIC_*` variables are readable in the browser bundle. Reading
 * them through this module rather than `process.env` directly means a missing
 * value surfaces as a clear error at module load instead of as `undefined`
 * concatenated into a request URL.
 */

/**
 * Read a required public environment variable.
 *
 * @param key - Name of the variable.
 * @param value - Its value, passed explicitly so Next.js can inline it at build time.
 * @param fallback - Value used when the variable is unset.
 * @throws When neither a value nor a fallback is available.
 */
function requirePublic(key: string, value: string | undefined, fallback?: string): string {
  const resolved = value ?? fallback;
  if (!resolved) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return resolved;
}

/** Public configuration available to both server and browser code. */
export const env = {
  /** Base URL the browser uses to reach the NetShield-ISP API. */
  apiBaseUrl: requirePublic(
    "NEXT_PUBLIC_API_BASE_URL",
    process.env.NEXT_PUBLIC_API_BASE_URL,
    "http://localhost:8000",
  ),

  /** Product name rendered in the shell and document title. */
  appName: requirePublic(
    "NEXT_PUBLIC_APP_NAME",
    process.env.NEXT_PUBLIC_APP_NAME,
    "NetShield-ISP",
  ),
} as const;

/**
 * Base URL for server-side calls.
 *
 * Server components run inside the Compose network and should reach the API by
 * its service name, avoiding a pointless round trip through the host.
 * Never exported to the browser bundle.
 */
export function getServerApiBaseUrl(): string {
  return process.env.INTERNAL_API_BASE_URL ?? env.apiBaseUrl;
}
