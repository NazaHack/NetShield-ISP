import { notFound } from "next/navigation";
import type { JSX } from "react";

import { ScanReport } from "@/components/console/scan-report";
import { getScan } from "@/lib/api/console";

export const dynamic = "force-dynamic";

/**
 * Detailed report for one of a client's scans.
 *
 * The scan is checked against the client in the path as well as fetched by
 * identifier, so a report reached through the wrong client is not found rather
 * than quietly rendered under the wrong heading.
 */
export default async function ScanReportPage({
  params,
}: {
  params: Promise<{ tenantId: string; scanId: string }>;
}): Promise<JSX.Element> {
  const { tenantId, scanId } = await params;
  const scan = await getScan(scanId);

  if (scan === null || scan.tenant_id !== tenantId) {
    notFound();
  }

  return (
    <ScanReport
      scan={scan}
      backHref={`/tenants/${tenantId}`}
      backLabel="Back to overview"
    />
  );
}
