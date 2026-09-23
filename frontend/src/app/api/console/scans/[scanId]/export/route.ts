import { NextResponse } from "next/server";

import { ApiError } from "@/lib/api-client";
import { getScan } from "@/lib/api/console";
import { NotAuthenticatedError } from "@/lib/server/api";

/**
 * JSON export of a scan report.
 *
 * Served from the server so the export carries the same authorisation as every
 * other read: a scan belonging to another client is not found, exactly as it is
 * in the console itself.
 */
export const dynamic = "force-dynamic";

/** Handle `GET /api/console/scans/{scanId}/export`. */
export async function GET(
  _request: Request,
  { params }: { params: Promise<{ scanId: string }> },
): Promise<NextResponse> {
  const { scanId } = await params;

  try {
    const scan = await getScan(scanId);
    if (scan === null) {
      return NextResponse.json({ detail: "Not found." }, { status: 404 });
    }

    const report = {
      generated_at: new Date().toISOString(),
      scan: {
        id: scan.id,
        tenant_id: scan.tenant_id,
        status: scan.status,
        created_at: scan.created_at,
        finished_at: scan.finished_at,
        host_count: scan.host_count,
        open_port_count: scan.open_port_count,
      },
      // The exposure triage, so the exported file carries the same headline the
      // console shows. Each port under `hosts` already carries its own severity.
      assessment: scan.assessment,
      hosts: scan.results.map((result) => ({
        host_ip: result.host_ip,
        open_ports: result.open_ports,
      })),
      changes: scan.diff,
    };

    const filename = `netshield-scan-${scan.id}.json`;
    return new NextResponse(JSON.stringify(report, null, 2), {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        // `filename` is derived from a UUID, so it cannot carry a path or a
        // quote into the header.
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Cache-Control": "no-store",
      },
    });
  } catch (error) {
    if (error instanceof NotAuthenticatedError) {
      return NextResponse.json({ detail: "Not authenticated." }, { status: 401 });
    }
    if (error instanceof ApiError) {
      return NextResponse.json({ detail: error.message }, { status: error.status || 502 });
    }
    return NextResponse.json({ detail: "Unexpected error." }, { status: 500 });
  }
}
