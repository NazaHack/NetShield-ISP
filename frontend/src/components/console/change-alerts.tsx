import { ArrowDownRight, ArrowUpRight, Info, ServerCrash, ServerOff, ShieldAlert } from "lucide-react";
import type { JSX } from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ScanDiff } from "@/lib/api/types";

/**
 * Changes since the client's previous completed scan.
 *
 * A newly opened port is the finding an ISP audit exists to surface: a port that
 * has been open for a year is a known condition, while one that opened since
 * Tuesday is news. Opened ports are therefore given the strongest treatment,
 * and everything else is reported without competing for attention.
 */
export function ChangeAlerts({ diff }: { diff: ScanDiff | null }): JSX.Element {
  if (diff === null) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Info className="size-5 text-muted-foreground" aria-hidden="true" />
            Alertas / Cambios
          </CardTitle>
          <CardDescription>
            Comparison becomes available once the scan finishes.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  if (!diff.has_baseline) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Info className="size-5 text-muted-foreground" aria-hidden="true" />
            Alertas / Cambios
          </CardTitle>
          <CardDescription>
            This is the client&apos;s first completed scan, so there is nothing to compare
            against. It becomes the baseline for the next one.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  if (!diff.has_changes) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Info className="size-5 text-severity-low" aria-hidden="true" />
            Alertas / Cambios
          </CardTitle>
          <CardDescription>
            Nothing changed since the previous scan: the same hosts answered on the same ports,
            running the same versions.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const hasOpenedPorts = diff.opened_port_count > 0;

  return (
    <Card className={hasOpenedPorts ? "border-severity-critical/60" : undefined}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert
            className={hasOpenedPorts ? "size-5 text-severity-critical" : "size-5 text-severity-medium"}
            aria-hidden="true"
          />
          Alertas / Cambios
        </CardTitle>
        <CardDescription>
          Compared against the previous completed scan for this client.
        </CardDescription>
      </CardHeader>

      <CardContent className="flex flex-col gap-6">
        <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Summary label="Newly open ports" value={diff.opened_port_count} emphasis={hasOpenedPorts} />
          <Summary label="Ports now closed" value={diff.closed_port_count} />
          <Summary label="New hosts" value={diff.new_hosts.length} />
          <Summary label="Hosts gone" value={diff.disappeared_hosts.length} />
        </dl>

        {diff.host_diffs.length > 0 ? (
          <ul className="flex flex-col gap-4">
            {diff.host_diffs.map((hostDiff) => (
              <li key={hostDiff.host_ip} className="rounded-lg border p-4">
                <p className="font-mono font-tabular text-sm font-semibold">
                  {hostDiff.host_ip}
                </p>

                <div className="mt-3 flex flex-col gap-2 text-sm">
                  {hostDiff.opened_ports.map((port) => (
                    <p
                      key={`opened-${port.protocol}-${port.port}`}
                      className="flex flex-wrap items-center gap-2"
                    >
                      <Badge variant="critical" className="gap-1">
                        <ArrowUpRight className="size-3" aria-hidden="true" />
                        Opened
                      </Badge>
                      <span className="font-tabular font-medium">
                        {port.port}/{port.protocol}
                      </span>
                      <span className="text-muted-foreground">
                        {port.service ?? "unidentified service"}
                        {port.version ? ` · ${port.version}` : ""}
                      </span>
                    </p>
                  ))}

                  {hostDiff.closed_ports.map((port) => (
                    <p
                      key={`closed-${port.protocol}-${port.port}`}
                      className="flex flex-wrap items-center gap-2"
                    >
                      <Badge variant="low" className="gap-1">
                        <ArrowDownRight className="size-3" aria-hidden="true" />
                        Closed
                      </Badge>
                      <span className="font-tabular font-medium">
                        {port.port}/{port.protocol}
                      </span>
                      <span className="text-muted-foreground">{port.service ?? "—"}</span>
                    </p>
                  ))}

                  {hostDiff.changed_ports.map((change) => (
                    <p
                      key={`changed-${change.protocol}-${change.port}`}
                      className="flex flex-wrap items-center gap-2"
                    >
                      <Badge variant="medium">Changed</Badge>
                      <span className="font-tabular font-medium">
                        {change.port}/{change.protocol}
                      </span>
                      <span className="text-muted-foreground">
                        {change.previous_version ?? change.previous_service ?? "unknown"} →{" "}
                        {change.current_version ?? change.current_service ?? "unknown"}
                      </span>
                    </p>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        ) : null}

        {diff.new_hosts.length > 0 ? (
          <HostList
            icon={<ServerCrash className="size-4 text-severity-high" aria-hidden="true" />}
            title="Hosts that answered for the first time"
            hosts={diff.new_hosts}
          />
        ) : null}

        {diff.disappeared_hosts.length > 0 ? (
          <HostList
            icon={<ServerOff className="size-4 text-muted-foreground" aria-hidden="true" />}
            title="Hosts that stopped answering"
            hosts={diff.disappeared_hosts}
          />
        ) : null}
      </CardContent>
    </Card>
  );
}

/** One figure in the change summary. */
function Summary({
  label,
  value,
  emphasis = false,
}: {
  label: string;
  value: number;
  emphasis?: boolean;
}): JSX.Element {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-xs uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd
        className={
          emphasis
            ? "font-tabular text-2xl font-bold text-severity-critical"
            : "font-tabular text-2xl font-semibold"
        }
      >
        {value}
      </dd>
    </div>
  );
}

/** A labelled list of host addresses. */
function HostList({
  icon,
  title,
  hosts,
}: {
  icon: JSX.Element;
  title: string;
  hosts: string[];
}): JSX.Element {
  return (
    <div className="flex flex-col gap-2">
      <p className="flex items-center gap-2 text-sm font-medium">
        {icon}
        {title}
      </p>
      <ul className="flex flex-wrap gap-2">
        {hosts.map((host) => (
          <li key={host}>
            <Badge variant="outline" className="font-mono font-tabular">
              {host}
            </Badge>
          </li>
        ))}
      </ul>
    </div>
  );
}
