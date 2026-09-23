import type { JSX } from "react";

import { SeverityBadge } from "@/components/console/severity-badge";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { ScanResult } from "@/lib/api/types";

/**
 * Hosts found by a scan, with their open ports, protocols and service versions.
 *
 * Service and version strings are banner text returned by the scanned host.
 * They are rendered as text, never as markup: React escapes them, and the API
 * has already stripped control characters and bounded their length.
 */
export function HostTable({ results }: { results: ScanResult[] }): JSX.Element {
  if (results.length === 0) {
    return (
      <p className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
        No host answered with an open port in the scanned range.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-28">Severity</TableHead>
          <TableHead className="w-48">Host</TableHead>
          <TableHead className="w-24">Port</TableHead>
          <TableHead className="w-24">Protocol</TableHead>
          <TableHead className="w-40">Service</TableHead>
          <TableHead>Version</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.flatMap((result) =>
          result.open_ports.map((port, index) => (
            <TableRow key={`${result.id}-${port.protocol}-${port.port}`}>
              <TableCell>
                <SeverityBadge severity={port.severity} />
              </TableCell>
              <TableCell className="font-mono font-tabular">
                {/* The address is printed once per host, not once per port. */}
                {index === 0 ? result.host_ip : ""}
              </TableCell>
              <TableCell className="font-tabular font-medium">{port.port}</TableCell>
              <TableCell>
                <Badge variant="outline" className="uppercase">
                  {port.protocol}
                </Badge>
              </TableCell>
              <TableCell>{port.service ?? "—"}</TableCell>
              <TableCell className="text-muted-foreground">{port.version ?? "—"}</TableCell>
            </TableRow>
          )),
        )}
      </TableBody>
    </Table>
  );
}
