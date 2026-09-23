"use client";

import { FileDown, FileJson, Loader2 } from "lucide-react";
import { useState, type JSX } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import type { ScanDetail } from "@/lib/api/types";

/**
 * Export the report as JSON or PDF.
 *
 * JSON is produced by the server so the download carries the same authorisation
 * as the page itself. The PDF is generated in the browser from data already on
 * screen: rendering it server-side would mean either a headless browser in the
 * image or a second templating language to keep in step with this view.
 *
 * `jspdf` is imported dynamically. It is several hundred kilobytes and only
 * matters to an operator who actually clicks the button, so it must not sit in
 * the bundle every page load pays for.
 */
export function ExportButtons({ scan }: { scan: ScanDetail }): JSX.Element {
  const [building, setBuilding] = useState(false);

  async function exportPdf(): Promise<void> {
    setBuilding(true);
    try {
      const [{ jsPDF }, autoTableModule] = await Promise.all([
        import("jspdf"),
        import("jspdf-autotable"),
      ]);
      const autoTable = autoTableModule.default;

      const document_ = new jsPDF({ orientation: "landscape", unit: "pt", format: "a4" });
      const finished = scan.finished_at ? new Date(scan.finished_at).toLocaleString() : "—";

      document_.setFontSize(16);
      document_.text("NetShield-ISP network audit report", 40, 44);

      document_.setFontSize(10);
      document_.text(
        [
          `Scan: ${scan.id}`,
          `Status: ${scan.status}`,
          `Finished: ${finished}`,
          `Hosts with open ports: ${scan.host_count}    Open ports: ${scan.open_port_count}`,
        ],
        40,
        66,
      );

      const rows = scan.results.flatMap((result) =>
        result.open_ports.map((port) => [
          result.host_ip,
          String(port.port),
          port.protocol,
          port.service ?? "—",
          port.version ?? "—",
        ]),
      );

      autoTable(document_, {
        startY: 124,
        head: [["Host", "Port", "Protocol", "Service", "Version"]],
        body: rows.length > 0 ? rows : [["No host answered with an open port", "", "", "", ""]],
        styles: { fontSize: 9, cellPadding: 5 },
        headStyles: { fillColor: [30, 64, 175] },
      });

      if (scan.diff?.has_changes) {
        const changeRows = scan.diff.host_diffs.flatMap((hostDiff) => [
          ...hostDiff.opened_ports.map((port) => [
            hostDiff.host_ip,
            "Opened",
            `${port.port}/${port.protocol}`,
            port.service ?? "—",
          ]),
          ...hostDiff.closed_ports.map((port) => [
            hostDiff.host_ip,
            "Closed",
            `${port.port}/${port.protocol}`,
            port.service ?? "—",
          ]),
          ...hostDiff.changed_ports.map((change) => [
            hostDiff.host_ip,
            "Changed",
            `${change.port}/${change.protocol}`,
            `${change.previous_version ?? "—"} to ${change.current_version ?? "—"}`,
          ]),
        ]);

        if (changeRows.length > 0) {
          autoTable(document_, {
            head: [["Host", "Change", "Port", "Detail"]],
            body: changeRows,
            styles: { fontSize: 9, cellPadding: 5 },
            headStyles: { fillColor: [153, 27, 27] },
          });
        }
      }

      document_.save(`netshield-scan-${scan.id}.pdf`);
    } catch {
      toast.error("The PDF could not be generated.");
    } finally {
      setBuilding(false);
    }
  }

  return (
    <div className="flex flex-wrap gap-2">
      <Button asChild variant="outline" size="sm" className="gap-2">
        <a href={`/api/console/scans/${scan.id}/export`} download>
          <FileJson className="size-4" aria-hidden="true" />
          Export JSON
        </a>
      </Button>

      <Button
        type="button"
        variant="outline"
        size="sm"
        className="gap-2"
        onClick={() => void exportPdf()}
        disabled={building}
      >
        {building ? (
          <Loader2 className="size-4 animate-spin" aria-hidden="true" />
        ) : (
          <FileDown className="size-4" aria-hidden="true" />
        )}
        Export PDF
      </Button>
    </div>
  );
}
