import type { ProviderId } from "./audit";
import type { CleanProfileStatus, CleanRoomProfile, CleanRoomState } from "./state";

export type { CleanProfileStatus, CleanRoomProfile, CleanRoomState };

export type TraceSeverity = "ok" | "warning" | "critical";

export type CleanRoomCategory =
  | "desktop_traces"
  | "ip_collision"
  | "network_leak"
  | "os_tz_locale"
  | "browser"
  | (string & {});

export type BrowserEngine = "chrome" | "edge" | "brave" | (string & {});

export type CleanRoomFixAction =
  | { kind: "clean_app_cache"; provider: string }
  | { kind: "sync_os_timezone"; target_iana: string }
  | { kind: "switch_route_or_vpn" }
  | { kind: "close_running_app"; process_name: string }
  | { kind: "acknowledge_sandbox_isolation" };

export interface CleanRoomFinding {
  id: string;
  category: CleanRoomCategory;
  title: string;
  detail: string;
  severity: TraceSeverity;
  path_hint: string | null;
  fix_action: CleanRoomFixAction | null;
}

export interface CleanRoomAuditReport {
  checked_at: number;
  exit_ip: string | null;
  exit_country: string | null;
  exit_timezone: string | null;
  ip_is_tainted: boolean;
  os_tz_matches_exit: boolean;
  findings: CleanRoomFinding[];
  critical_count: number;
  warning_count: number;
  /** Hard Readiness Gate: true только когда critical_count === 0. */
  ready_to_launch: boolean;
}

export interface DetectedBrowser {
  engine: BrowserEngine;
  display_name: string;
  executable_path: string;
  available: boolean;
}

export interface CreateCleanProfileInput {
  label: string;
  provider: ProviderId | (string & {});
  browser_engine: BrowserEngine;
  bound_route_id?: string | null;
}

export interface LaunchCleanBrowserResult {
  profile_id: string;
  browser_engine: BrowserEngine;
  pid: number | null;
  alias_port: number;
  target_url: string | null;
  tz_applied: string | null;
  profile_dir: string;
}

export interface CleanRoomTzCheck {
  platform: string;
  exit_timezone: string | null;
  os_timezone: string | null;
  matches_exit: boolean;
  requires_os_sync: boolean;
  synced_by_zastava: boolean;
}
