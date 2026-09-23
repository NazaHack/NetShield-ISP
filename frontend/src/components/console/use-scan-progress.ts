"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

import { isTerminal, type ScanStatus } from "@/lib/api/types";

/** How often the progress indicator asks the server for a status update. */
const POLL_INTERVAL_MS = 3000;

/** Give up polling after this long, so a wedged scan cannot poll forever. */
const POLL_TIMEOUT_MS = 30 * 60 * 1000;

/** What the console's status route reports. */
export interface StatusSnapshot {
  id: string;
  status: ScanStatus;
  is_finished: boolean;
  host_count: number;
  open_port_count: number;
}

/** What {@link useScanProgress} exposes to a component. */
export interface ScanProgress {
  scanId: string | null;
  status: ScanStatus | null;
  snapshot: StatusSnapshot | null;
  /** True while a scan is queued or running. */
  inFlight: boolean;
  /** Begin following a scan, replacing whatever was being followed. */
  watch: (scanId: string, initialStatus?: ScanStatus) => void;
}

/**
 * Follow a scan until it reaches a terminal state.
 *
 * Polling stops as soon as the scan finishes, so a completed scan does not
 * leave a timer running, and it stops unconditionally after a long timeout so
 * that a wedged job cannot poll forever.
 *
 * The browser cannot call the API directly, since it does not hold the token,
 * so this goes through the console's own status route.
 *
 * @param initial - A scan already in flight when the page rendered.
 */
export function useScanProgress(
  initial: { id: string; status: ScanStatus } | null = null,
): ScanProgress {
  const router = useRouter();
  const [scanId, setScanId] = useState<string | null>(initial?.id ?? null);
  const [status, setStatus] = useState<ScanStatus | null>(initial?.status ?? null);
  const [snapshot, setSnapshot] = useState<StatusSnapshot | null>(null);
  const startedAt = useRef<number>(Date.now());

  const watch = useCallback((nextScanId: string, initialStatus: ScanStatus = "PENDING") => {
    setScanId(nextScanId);
    setStatus(initialStatus);
    setSnapshot(null);
    startedAt.current = Date.now();
  }, []);

  const poll = useCallback(async (id: string): Promise<boolean> => {
    const response = await fetch(`/api/console/scans/${id}`, { cache: "no-store" });
    if (!response.ok) {
      // A status route that will not answer is treated as terminal rather than
      // polled forever; the page reload will show the real state.
      return true;
    }
    const data = (await response.json()) as StatusSnapshot;
    setStatus(data.status);
    setSnapshot(data);
    return data.is_finished;
  }, []);

  useEffect(() => {
    if (!scanId || (status !== null && isTerminal(status))) {
      return;
    }

    let cancelled = false;
    const timer = setInterval(() => {
      if (Date.now() - startedAt.current > POLL_TIMEOUT_MS) {
        clearInterval(timer);
        return;
      }
      void poll(scanId).then((finished) => {
        if (finished && !cancelled) {
          clearInterval(timer);
          // Refresh the server components so history and reports pick up the
          // finished scan without a manual reload.
          router.refresh();
        }
      });
    }, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [scanId, status, poll, router]);

  return {
    scanId,
    status,
    snapshot,
    inFlight: status !== null && !isTerminal(status),
    watch,
  };
}
