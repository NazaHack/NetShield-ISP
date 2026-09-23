import { NextResponse } from "next/server";

/**
 * Container liveness endpoint for the dashboard.
 *
 * Probed by the Docker `HEALTHCHECK`. It reports only on this Next.js process:
 * checking the API here would make the frontend report unhealthy during a
 * backend outage and trigger a pointless restart loop.
 */
export const dynamic = "force-dynamic";

/** Handle `GET /api/health`. */
export function GET(): NextResponse {
  return NextResponse.json(
    {
      status: "up",
      service: "netshield-frontend",
      timestamp: new Date().toISOString(),
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
