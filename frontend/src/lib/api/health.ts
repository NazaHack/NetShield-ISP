/**
 * Health resource bindings for the NetShield-ISP API.
 */

import { ApiError, apiRequest } from "@/lib/api-client";

/** Health state of a single dependency. */
export type ComponentStatus = "up" | "down";

/** Result of probing one downstream dependency. */
export interface DependencyHealth {
  name: string;
  status: ComponentStatus;
  latency_ms: number;
  detail?: string | null;
}

/** Response returned by the API readiness probe. */
export interface ReadinessReport {
  status: ComponentStatus;
  service: string;
  version: string;
  environment: string;
  timestamp: string;
  dependencies: DependencyHealth[];
}

/** Outcome of a platform health lookup, including the unreachable case. */
export type PlatformHealth =
  | { reachable: true; report: ReadinessReport }
  | { reachable: false; reason: string };

/**
 * Fetch the API readiness report.
 *
 * A 503 response is a valid, informative answer rather than a failure: it means
 * the API is running but a dependency is down, and the body names which one.
 * Only a transport failure counts as unreachable.
 *
 * @returns The readiness report, or the reason the API could not be reached.
 */
export async function fetchPlatformHealth(): Promise<PlatformHealth> {
  try {
    const report = await apiRequest<ReadinessReport>("/health/ready", { timeoutMs: 5_000 });
    return { reachable: true, report };
  } catch (error) {
    if (error instanceof ApiError && error.status === 503) {
      // The API answered with a degraded report; surface it as-is.
      return { reachable: false, reason: "One or more platform dependencies are unavailable." };
    }
    const reason =
      error instanceof ApiError ? error.message : "Unexpected error contacting the API.";
    return { reachable: false, reason };
  }
}
