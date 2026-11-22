import type {
  AppStateData,
  ClaudeProfile,
  CliMode,
  ProviderId,
  RoutesSnapshot,
} from "../../../types";

export const DIRECT_ROUTE_ID = "__direct__";
export const PROVIDERS_FOR_MOCK: ProviderId[] = ["anthropic", "openai", "gemini"];

export type MockScenario = "clean" | "turkey" | "ru";

export const mockState: AppStateData = {
  schema_version: 3,
  pinned_ip: "185.212.102.40",
  pinned_ips: { default: "185.212.102.40" },
  strict_pinning_enabled: true,
  onboarding_v2_2_done: false,
  onboarding_v3_done: false,
  whats_new_v3_seen: false,
  dismissed_hints: [],
  ip_history: {},
  session_allowed_providers: [],
  blocked_providers: [],
  trusted_exceptions: {},
  disabled_providers: [],
  upstream_proxy: null,
  warmup_started_at: null,
  synced_ai_timezone: null,
  auto_update_enabled: true,
  interception_behavior: "ask_popup",
  popup_position: "top_right",
  custom_ai_domains: [],
  // Как в шлюзе: подмена включена по умолчанию, применяется только при известной зоне.
  sync_ai_tz_enabled: true,
  keep_system_tz_on_exit: false,
  cli_mode: "ai_only",
  split_tunnel_mode: false,
  hide_ip_mode: false,
  ip_change_cooldown_until: null,
  last_safe_logout_at: null,
  clean_room: {
    profiles: [],
    active_profile_id: null,
    tainted_ips: {},
  },
  bunker: {
    auto_backup_enabled: true,
    interval_hours: 24,
    retention_count: 7,
    last_backup_at: null,
    last_backup_size_bytes: null,
  },
  persona_self_check: {
    bought_or_grey_account: false,
    virtual_sms_used: false,
    reseller_payment_used: false,
    multi_account_same_browser: false,
  },
};

export const mockFlags = {
  killswitchStatus: false,
  cliProtection: true,
  cliMode: "ai_only" as CliMode,
  syncAiTz: true,
  keepSystemTzOnExit: false,
  splitTunnelMode: false,
  osTzCurrent: "Europe/Moscow",
  osTzOriginal: null as string | null,
  osTzTarget: null as string | null,
  sysproxyActive: true,
  countryOverride: null as string | null,
  scenario: "clean" as MockScenario,
  crashTestStep: 0,
  crashTestDropped: false,
  autostartEnabled: false,
  coworkTaskInstalled: false,
  pendingDeepLink: null as string | null,
  onboardingDone: false,
};

export const mockRoutesSnapshot: RoutesSnapshot = {
  routes: [],
  provider_routes: {},
  default_route_id: null,
  profile_route_id: null,
  effective: {
    anthropic: null,
    openai: null,
    gemini: null,
  },
  profile_route_error: null,
  dangling: [],
};

export let mockProfiles: ClaudeProfile[] = [
  {
    id: "default",
    name: "Основной аккаунт (Pro)",
    bound_ip: "185.212.102.40",
    bound_country: "NL",
    isolated_device_id: "7f4c9a81-e32a-4a22-921a-969421fb3101",
    created_at: Math.floor(Date.now() / 1000) - 86400 * 14,
    last_used_at: Math.floor(Date.now() / 1000),
    is_active: true,
    has_saved_session: true,
  },
  {
    id: "backup-dev",
    name: "Рабочий профиль (Dev)",
    bound_ip: "145.241.12.8",
    bound_country: "DE",
    isolated_device_id: "2d1b829c-fa14-4903-883a-4817a0224b55",
    created_at: Math.floor(Date.now() / 1000) - 86400 * 3,
    last_used_at: Math.floor(Date.now() / 1000) - 3600 * 8,
    is_active: false,
    has_saved_session: true,
  },
];

export function setMockProfilesList(next: ClaudeProfile[]): void {
  mockProfiles = next;
}

export function setBrowserMockCountry(country: string | null) {
  mockFlags.countryOverride = country;
  if (country === "TR") mockFlags.scenario = "turkey";
  else if (country === "RU") mockFlags.scenario = "ru";
  else mockFlags.scenario = "clean";
}

export function getMockScenario(): MockScenario {
  return mockFlags.scenario;
}

export function setMockScenario(scenario: MockScenario) {
  mockFlags.scenario = scenario;
  if (scenario === "turkey") {
    mockFlags.countryOverride = "TR";
  } else if (scenario === "ru") {
    mockFlags.countryOverride = "RU";
  } else {
    mockFlags.countryOverride = "NL";
  }
}

export function setMockPendingDeepLink(link: string | null): void {
  mockFlags.pendingDeepLink = link;
}

export function snapshotMockState(): AppStateData {
  const clonedExceptions: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(mockState.trusted_exceptions ?? {})) {
    clonedExceptions[k] = [...v];
  }
  return {
    ...mockState,
    pinned_ips: { ...(mockState.pinned_ips ?? {}) },
    session_allowed_providers: [...mockState.session_allowed_providers],
    blocked_providers: [...mockState.blocked_providers],
    trusted_exceptions: clonedExceptions,
    disabled_providers: [...(mockState.disabled_providers ?? [])],
    custom_ai_domains: [...(mockState.custom_ai_domains ?? [])],
    dismissed_hints: [...(mockState.dismissed_hints ?? [])],
    clean_room: mockState.clean_room
      ? {
          profiles: mockState.clean_room.profiles.map((p) => ({
            ...p,
            completed_checklist: [...p.completed_checklist],
            post_payment_quarantine: p.post_payment_quarantine ? { ...p.post_payment_quarantine } : null,
          })),
          active_profile_id: mockState.clean_room.active_profile_id,
          tainted_ips: { ...mockState.clean_room.tainted_ips },
          global_post_payment_quarantine: mockState.clean_room.global_post_payment_quarantine
            ? { ...mockState.clean_room.global_post_payment_quarantine }
            : null,
        }
      : undefined,
    bunker: mockState.bunker ? { ...mockState.bunker } : undefined,
    persona_self_check: mockState.persona_self_check ? { ...mockState.persona_self_check } : undefined,
  };
}

export function recomputeMockEffective() {
  for (const r of mockRoutesSnapshot.routes) {
    r.bound_providers = Object.entries(mockRoutesSnapshot.provider_routes)
      .filter(([_, rid]) => rid === r.id)
      .map(([p]) => p);
  }
  for (const p of PROVIDERS_FOR_MOCK) {
    if (p === "anthropic" && mockRoutesSnapshot.profile_route_id) {
      mockRoutesSnapshot.effective[p] = mockRoutesSnapshot.profile_route_id;
      continue;
    }
    const bound = mockRoutesSnapshot.provider_routes[p];
    if (bound === DIRECT_ROUTE_ID) {
      mockRoutesSnapshot.effective[p] = null;
    } else {
      mockRoutesSnapshot.effective[p] =
        bound ?? mockRoutesSnapshot.default_route_id ?? null;
    }
  }
}

/** Параметры адреса для превью без Tauri: `?startup=slow` и `?dns=cloudflare|disagree|fake|single`. */
export function mockOption(name: string): string | null {
  if (typeof window === "undefined") return null;
  try {
    return new URLSearchParams(window.location.search).get(name);
  } catch {
    return null;
  }
}

export const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

export function emitMock(name: string, detail: unknown) {
  window.dispatchEvent(new CustomEvent(name, { detail }));
}
