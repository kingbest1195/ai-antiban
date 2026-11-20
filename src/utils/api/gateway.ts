import type {
  AppStateData,
  CleanResult,
  GatewayStatsSnapshot,
  ProviderId,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";
import { mockFlags, mockState, snapshotMockState } from "./mocks/state";

export async function fetchAppState(): Promise<AppStateData> {
  if (isTauri()) {
    return await tauriInvoke<AppStateData>("get_state");
  }
  return snapshotMockState();
}

export async function toggleAutoUpdate(enabled: boolean): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("toggle_auto_update", { enabled });
  }
  mockState.auto_update_enabled = enabled;
}

export async function getOnboardingV22Done(): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("get_onboarding_v2_2_done");
  }
  return mockFlags.onboardingDone;
}

export async function setOnboardingV22Done(done: boolean): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke<void>("set_onboarding_v2_2_done", { done });
  }
  mockFlags.onboardingDone = done;
}

export async function pinCurrentIp(ip: string, provider?: string): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("pin_current_ip", { ip, provider: provider ?? null });
  }
  const key = provider || "default";
  mockState.pinned_ips = { ...(mockState.pinned_ips ?? {}), [key]: ip };
  if (key === "default" || !mockState.pinned_ip) {
    mockState.pinned_ip = ip;
  }
}

export async function unpinIp(provider?: string): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("unpin_ip", { provider: provider ?? null });
  }
  if (!provider) {
    mockState.pinned_ip = null;
    mockState.pinned_ips = {};
    return;
  }
  const next = { ...(mockState.pinned_ips ?? {}) };
  delete next[provider];
  mockState.pinned_ips = next;
  if (provider === "default") {
    mockState.pinned_ip = null;
  }
}

export async function getPinnedIps(): Promise<Record<string, string>> {
  if (isTauri()) {
    return await tauriInvoke<Record<string, string>>("get_pinned_ips");
  }
  return { ...(mockState.pinned_ips ?? {}) };
}

export async function getHideIpMode(): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("get_hide_ip_mode");
  }
  return Boolean(mockState.hide_ip_mode);
}

export async function setHideIpMode(enabled: boolean): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("set_hide_ip_mode", { enabled });
  }
  mockState.hide_ip_mode = enabled;
}

export async function toggleStrictPinning(enabled: boolean): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("toggle_strict_pinning", { enabled });
  }
  mockState.strict_pinning_enabled = enabled;
}

export async function allowProviderSession(provider: ProviderId): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("allow_provider_session", { provider });
  }
  if (!mockState.session_allowed_providers.includes(provider)) {
    mockState.session_allowed_providers.push(provider);
  }
  mockState.blocked_providers = mockState.blocked_providers.filter((p) => p !== provider);
  const currentIp =
    mockFlags.scenario === "turkey"
      ? "185.220.101.5"
      : mockFlags.scenario === "ru"
      ? "95.165.10.22"
      : mockState.pinned_ip || "185.212.102.40";
  const nextExceptions = { ...(mockState.trusted_exceptions ?? {}) };
  const list = [...(nextExceptions[provider] ?? [])];
  if (!list.includes(currentIp)) {
    list.push(currentIp);
  }
  nextExceptions[provider] = list;
  mockState.trusted_exceptions = nextExceptions;
}

export async function unblockProvider(provider: ProviderId): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("unblock_provider_cmd", { provider });
  }
  mockState.blocked_providers = mockState.blocked_providers.filter((p) => p !== provider);
}

/** Включает или отключает мониторинг, PAC-перехват, проверки и алерты для отдельного провайдера. */
export async function setProviderMonitoring(
  provider: string,
  enabled: boolean,
): Promise<AppStateData> {
  if (isTauri()) {
    return await tauriInvoke<AppStateData>("set_provider_monitoring", { provider, enabled });
  }
  const key = provider.trim().toLowerCase();
  if (key) {
    const disabled = new Set((mockState.disabled_providers ?? []).map((p) => p.toLowerCase()));
    if (enabled) {
      disabled.delete(key);
    } else {
      disabled.add(key);
      mockState.blocked_providers = mockState.blocked_providers.filter((p) => p.toLowerCase() !== key);
    }
    mockState.disabled_providers = Array.from(disabled);
  }
  return snapshotMockState();
}

/** Удаляет одно сохранённое исключение (провайдер + IP выхода). */
export async function removeTrustedException(
  provider: string,
  ip: string,
): Promise<AppStateData> {
  if (isTauri()) {
    return await tauriInvoke<AppStateData>("remove_trusted_exception", { provider, ip });
  }
  const key = provider.trim().toLowerCase();
  const normIp = ip.trim();
  const next: Record<string, string[]> = {};
  for (const [k, list] of Object.entries(mockState.trusted_exceptions ?? {})) {
    if (k.toLowerCase() === key) {
      const filtered = list.filter((item) => item.trim() !== normIp);
      if (filtered.length > 0) next[k] = filtered;
    } else {
      next[k] = [...list];
    }
  }
  mockState.trusted_exceptions = next;
  mockState.session_allowed_providers = mockState.session_allowed_providers.filter(
    (p) => p.toLowerCase() !== key,
  );
  return snapshotMockState();
}

/** Очищает сохранённые исключения (для одного провайдера или все сразу). */
export async function clearTrustedExceptions(provider?: string): Promise<AppStateData> {
  if (isTauri()) {
    return await tauriInvoke<AppStateData>("clear_trusted_exceptions", { provider: provider ?? null });
  }
  const clean = provider?.trim().toLowerCase();
  if (clean) {
    const next: Record<string, string[]> = {};
    for (const [k, list] of Object.entries(mockState.trusted_exceptions ?? {})) {
      if (k.toLowerCase() !== clean) next[k] = [...list];
    }
    mockState.trusted_exceptions = next;
    mockState.session_allowed_providers = mockState.session_allowed_providers.filter(
      (p) => p.toLowerCase() !== clean,
    );
  } else {
    mockState.trusted_exceptions = {};
    mockState.session_allowed_providers = [];
  }
  return snapshotMockState();
}

/**
 * Проверить текущую сеть и снять ручной блок с провайдера без добавления в session_allowed_providers.
 * Возвращает true, если сеть безопасна и блок снят; false — если риск сохраняется и нужно принудительное решение.
 */
export async function verifyAndUnblockProvider(provider: ProviderId): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("verify_and_unblock_provider", { provider });
  }
  if (mockFlags.scenario === "ru") {
    return false;
  }
  mockState.blocked_providers = mockState.blocked_providers.filter((p) => p !== provider);
  return true;
}

export async function setWarmupTimer(timestamp: number | null): Promise<number | null> {
  if (isTauri()) {
    return await tauriInvoke<number | null>("set_warmup_timer", { timestamp });
  }
  mockState.warmup_started_at = timestamp;
  return timestamp;
}

export async function getGatewayStats(): Promise<GatewayStatsSnapshot> {
  if (isTauri()) {
    return await tauriInvoke<GatewayStatsSnapshot>("get_gateway_stats");
  }
  return {
    protected_ai_requests: 142,
    intercepted_leaks: 0,
    direct_bypassed_requests: 864,
    active_ai_tunnels: 0,
    uptime_seconds: 1840,
    last_protected_host: "api.anthropic.com",
    recent_events: [
      {
        timestamp: Math.floor(Date.now() / 1000) - 24,
        host: "api.anthropic.com",
        provider: "anthropic",
        action: "PROTECTED",
        country: "NL",
      },
      {
        timestamp: Math.floor(Date.now() / 1000) - 52,
        host: "github.com",
        provider: "non-ai",
        action: "DIRECT",
        country: "DIRECT",
      },
    ],
  };
}

export async function cleanAppCache(provider: ProviderId): Promise<CleanResult> {
  if (isTauri()) {
    return await tauriInvoke<CleanResult>("clean_app_cache", { provider });
  }
  return {
    provider,
    cleaned_targets: ["Cookies", "Cache", "ant-device-registry.json"],
    files_removed: 18,
    bytes_freed: 14200000,
    success: true,
    message: "Локальные реестры и кэш успешно сброшены.",
    found_dir: true,
    locked_targets: [],
  };
}
