import { NextResponse } from "next/server";

import { ApiError } from "@/lib/api-client";
import { getScan } from "@/lib/api/console";
import { NotAuthenticatedError } from "@/lib/server/api";

/**
 * Scan status, polled by the progress indicator.
 *
 * The browser cannot call the API directly because it does not hold the token.
 * This handler runs on the server, reads the session cookie and forwards the
 * request, returning only the fields the indicator needs.
 */
export const dynamic = "force-dynamic";

/** Handle `GET /api/console/scans/{scanId}`. */
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

    return NextResponse.json(
      {
        id: scan.id,
        status: scan.status,
        is_finished: scan.is_finished,
        host_count: scan.host_count,
        open_port_count: scan.open_port_count,
        finished_at: scan.finished_at,
      },
      { headers: { "Cache-Control": "no-store" } },
    );
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
