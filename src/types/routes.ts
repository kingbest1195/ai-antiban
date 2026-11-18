export type EntryProto = "https" | "socks5" | "http";

export interface EntryView {
  proto: EntryProto;
  host: string;
  port: number;
  username?: string | null;
  has_password: boolean;
  sni?: string | null;
}

export type RouteStatus =
  | "active"
  | "disabled"
  | "expired"
  | "unreachable"
  | "exit_ip_mismatch";

export type RouteHealthStatus = RouteStatus;

export interface RouteHealth {
  reachable?: boolean | null;
  last_error?: string | null;
  observed_exit_ip?: string | null;
  observed_country?: string | null;
  exit_ip_matches?: boolean | null;
  latency_ms?: number | null;
  checked_at: number;
}

export interface RouteView {
  id: string;
  label: string;
  country?: string | null;
  exit_ip?: string | null;
  expires_at?: number | null;
  enabled: boolean;
  added_at: number;
  entries: EntryView[];
  status: RouteStatus;
  is_default: boolean;
  bound_providers: string[];
  is_profile_route: boolean;
  health?: RouteHealth | null;
}

export interface DanglingBinding {
  kind: "provider" | "default" | "profile" | string;
  provider?: string | null;
  route_id: string;
}

export interface RoutesSnapshot {
  routes: RouteView[];
  provider_routes: Record<string, string>;
  default_route_id?: string | null;
  profile_route_id?: string | null;
  effective: Record<string, string | null>;
  profile_route_error?: string | null;
  dangling: DanglingBinding[];
}

export interface RouteTestResult {
  ok: boolean;
  exit_ip?: string | null;
  country?: string | null;
  latency_ms?: number | null;
  exit_ip_matches?: boolean | null;
  error?: string | null;
}

export interface RouteUnavailablePayload {
  route_id: string;
  provider: string;
  reason: string;
  message: string;
}
