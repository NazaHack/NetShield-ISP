/**
 * Shapes returned by the NetShield-ISP API.
 *
 * Kept in one module so a change to the API contract surfaces as a type error
 * at every use site rather than as a runtime surprise in one component.
 */

/** What a signed-in account is allowed to do. */
export type UserRole = "PLATFORM_ADMIN" | "TENANT_USER";

/** A signed-in account. */
export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  tenant_id: string | null;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

/** A successful sign-in. */
export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in_seconds: number;
  user: User;
}

/** Lifecycle state of a scan. */
export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";

/** How thorough, and therefore how slow, a scan runs. */
export type ScanProfile = "fast" | "balanced" | "thorough";

/** The profiles in the order they should appear in a chooser, fastest first. */
export const SCAN_PROFILES: ReadonlyArray<{
  value: ScanProfile;
  label: string;
  hint: string;
}> = [
  { value: "fast", label: "Rápido", hint: "1000 puertos comunes, sin versiones. Segundos." },
  {
    value: "balanced",
    label: "Balanceado",
    hint: "1000 puertos comunes con detección de versión. Recomendado.",
  },
  {
    value: "thorough",
    label: "Exhaustivo",
    hint: "Puertos 1-10000 con versión. El más completo y lento.",
  },
];

/** A page of results. */
export interface Page<TItem> {
  items: TItem[];
  total: number;
  limit: number;
  offset: number;
}

/** An ISP customer account. */
export interface Tenant {
  id: string;
  name: string;
  code_name: string;
  /** True for a workspace the platform provisions for itself, not a customer. */
  is_system: boolean;
  created_at: string;
  updated_at: string;
}

/** An address range the tenant is authorised to audit. */
export interface NetworkTarget {
  id: string;
  tenant_id: string;
  label: string;
  ip_address_or_cidr: string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * One open port found on a host.
 *
 * `service` and `version` are banner text returned by the scanned host. The API
 * strips control characters and bounds their length, but they remain
 * attacker-influenced content: render them as text, never as markup.
 */
/** Exposure severity assigned to a finding. */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface OpenPort {
  port: number;
  protocol: string;
  service: string | null;
  version: string | null;
  /** The platform's triage of what exposing this port implies. */
  severity: Severity;
  severity_reason: string;
}

/** One high- or critical-severity finding, tied to its host. */
export interface NotableFinding {
  host_ip: string;
  port: number;
  protocol: string;
  service: string | null;
  severity: Severity;
  reason: string;
}

/** Scan-level rollup of the exposure assessment. */
export interface AssessmentSummary {
  counts: Record<Severity, number>;
  highest_severity: Severity;
  notable: NotableFinding[];
}

/** Findings for one host within a scan. */
export interface ScanResult {
  id: string;
  host_ip: string;
  open_ports: OpenPort[];
  created_at: string;
}

/** A scan as listed in the history. */
export interface Scan {
  id: string;
  tenant_id: string;
  status: ScanStatus;
  created_at: string;
  finished_at: string | null;
}

/** A port whose service or version moved between two scans. */
export interface PortChange {
  protocol: string;
  port: number;
  previous_service: string | null;
  current_service: string | null;
  previous_version: string | null;
  current_version: string | null;
}

/** How one host changed between two scans. */
export interface HostDiff {
  host_ip: string;
  opened_ports: OpenPort[];
  closed_ports: OpenPort[];
  changed_ports: PortChange[];
}

/** Comparison against the tenant's previous completed scan. */
export interface ScanDiff {
  has_baseline: boolean;
  has_changes: boolean;
  previous_scan_id: string | null;
  new_hosts: string[];
  disappeared_hosts: string[];
  opened_port_count: number;
  closed_port_count: number;
  host_diffs: HostDiff[];
}

/** A scan with its findings. */
export interface ScanDetail {
  id: string;
  tenant_id: string;
  status: ScanStatus;
  created_at: string;
  finished_at: string | null;
  is_finished: boolean;
  host_count: number;
  open_port_count: number;
  results: ScanResult[];
  assessment: AssessmentSummary | null;
  diff: ScanDiff | null;
}

/** Order severities from most to least concerning, for display. */
export const SEVERITY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Acknowledgement that a scan was queued. */
export interface ScanLaunchResponse {
  scan_id: string;
  tenant_id: string;
  status: ScanStatus;
  task_id: string;
  created_at: string;
  /** The canonical ranges this scan will cover. */
  targets: string[];
  /** True when the scan was launched without naming a client. */
  is_adhoc: boolean;
}

/** True when the scan has reached a terminal state. */
export function isTerminal(status: ScanStatus): boolean {
  return status === "COMPLETED" || status === "FAILED";
}

/** True when the account administers the platform rather than one client. */
export function isPlatformAdmin(user: User): boolean {
  return user.role === "PLATFORM_ADMIN";
}

/** One entry in the audit trail. */
export interface AuditEvent {
  id: string;
  created_at: string;
  action: string;
  actor_user_id: string | null;
  actor_email: string | null;
  actor_role: string | null;
  tenant_id: string | null;
  tenant_code_name: string | null;
  target: string | null;
  detail: Record<string, unknown> | null;
  source_ip: string | null;
}
