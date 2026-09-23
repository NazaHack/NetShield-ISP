import { notFound } from "next/navigation";
import type { JSX } from "react";

import { ScanReport } from "@/components/console/scan-report";
import { getScan } from "@/lib/api/console";

export const dynamic = "force-dynamic";

/**
 * Detailed report for a scan reached without going through a client.
 *
 * Used by the quick-scan panel, whose scans belong to the platform's own
 * workspace rather than to a customer. Authorisation is unchanged: the API
 * decides whether this session may read the scan, and answers 404 when not.
 */
export default async function AdhocScanReportPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}): Promise<JSX.Element> {
  const { scanId } = await params;
  const scan = await getScan(scanId);

  if (scan === null) {
    notFound();
  }

  return (
    <div className="container py-8">
      <ScanReport scan={scan} backHref="/" backLabel="Back to the console" />
    </div>
  );
}
