import type {
  ClaudeExportResult,
  ClaudeLocalDataSummary,
  ClaudeProfile,
  ClaudeProfileListResponse,
  ProfileSwitchResult,
  SafeLogoutResult,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";
import {
  mockProfiles,
  mockRoutesSnapshot,
  mockState,
  recomputeMockEffective,
  setMockProfilesList,
} from "./mocks/state";
import { upsertRoute } from "./routes";

export async function scanClaudeLocalData(): Promise<ClaudeLocalDataSummary> {
  if (isTauri()) {
    return await tauriInvoke<ClaudeLocalDataSummary>("scan_claude_data_cmd");
  }
  return {
    exists: true,
    claude_dir_path: "~/.claude",
    projects_count: 3,
    sessions_count: 14,
    plans_count: 2,
    memory_files_count: 5,
    total_size_bytes: 4200000,
    projects: [
      {
        slug: "zastava-desktop",
        decoded_path: "~/local-projects/zastava",
        sessions_count: 8,
        has_memory: true,
        total_bytes: 2800000,
      },
      {
        slug: "finance-bot",
        decoded_path: "~/projects/finance-bot",
        sessions_count: 4,
        has_memory: true,
        total_bytes: 1100000,
      },
    ],
    has_claude_md: true,
    has_history: true,
    has_settings: true,
    has_desktop_config: true,
    has_claude_json: true,
  };
}

export async function exportClaudeLocalData(): Promise<ClaudeExportResult> {
  if (isTauri()) {
    return await tauriInvoke<ClaudeExportResult>("export_claude_data_cmd");
  }
  return {
    export_dir_path: "~/Desktop/Claude_Export_20261109",
    zip_archive_path: "~/Desktop/Claude_Export_20261109.zip",
    index_summary_path: "~/Desktop/Claude_Export_20261109/INDEX_SUMMARY.md",
    restore_prompt_path: "~/Desktop/Claude_Export_20261109/RESTORE_PROMPT.txt",
    restore_prompt_text:
      "Вы — AI-ассистент, продолжающий разработку проектов. Вот контекст и история всех сессий...",
    projects_exported: 3,
    sessions_exported: 14,
    total_bytes: 4200000,
  };
}

export async function listClaudeProfiles(): Promise<ClaudeProfileListResponse> {
  if (isTauri()) {
    return await tauriInvoke<ClaudeProfileListResponse>("list_claude_profiles_cmd");
  }
  return {
    profiles: [...mockProfiles],
    active_profile_id: mockProfiles.find((p) => p.is_active)?.id || "default",
    claude_desktop_installed: true,
    storage_dir: "~/.zastava/claude_profiles",
  };
}

export async function createClaudeProfile(
  name: string,
  bindIpOrEmail?: string | null,
  bindCountryOrIp?: string | boolean | null,
  bindUpstreamKeyOrCurrentIp?: string | null,
  bindUpstreamKeyParam?: string | null,
): Promise<ClaudeProfileListResponse> {
  let bindIp: string | null = null;
  let bindCountry: string | null = null;
  let upstreamKey: string | null = null;

  if (typeof bindCountryOrIp === "boolean") {
    bindIp = bindCountryOrIp && bindUpstreamKeyOrCurrentIp ? bindUpstreamKeyOrCurrentIp : null;
    bindCountry = null;
    upstreamKey = bindUpstreamKeyParam || null;
  } else {
    bindIp = bindIpOrEmail || null;
    bindCountry = bindCountryOrIp || null;
    upstreamKey = bindUpstreamKeyOrCurrentIp || bindUpstreamKeyParam || null;
  }

  if (isTauri()) {
    return await tauriInvoke<ClaudeProfileListResponse>("create_claude_profile_cmd", {
      name,
      bindIp: bindIp ?? null,
      bindCountry: bindCountry ?? null,
      bindUpstreamKey: upstreamKey ?? null,
    });
  }
  const newProfile: ClaudeProfile = {
    id: "profile-" + Date.now().toString(36),
    name: name.trim(),
    bound_ip: bindIp || null,
    bound_country: bindCountry || null,
    bound_upstream_key: upstreamKey || null,
    isolated_device_id:
      typeof crypto !== "undefined" && crypto.randomUUID
        ? crypto.randomUUID()
        : "iso-" + Math.random().toString(36).slice(2),
    created_at: Math.floor(Date.now() / 1000),
    last_used_at: Math.floor(Date.now() / 1000),
    is_active: false,
    has_saved_session: false,
  };
  setMockProfilesList([...mockProfiles, newProfile]);
  return await listClaudeProfiles();
}

export async function switchClaudeProfile(targetId: string): Promise<ProfileSwitchResult> {
  if (isTauri()) {
    return await tauriInvoke<ProfileSwitchResult>("switch_claude_profile_cmd", { targetId });
  }
  const prevActive = mockProfiles.find((p) => p.is_active)?.id || "default";
  const nextProfiles = mockProfiles.map((p) => ({
    ...p,
    is_active: p.id === targetId,
    last_used_at: p.id === targetId ? Math.floor(Date.now() / 1000) : p.last_used_at,
  }));
  setMockProfilesList(nextProfiles);
  const activeProf = nextProfiles.find((p) => p.id === targetId)!;
  const nextPinned = { ...(mockState.pinned_ips ?? {}) };
  if (activeProf.bound_ip) {
    nextPinned.anthropic = activeProf.bound_ip;
  } else {
    delete nextPinned.anthropic;
  }
  mockState.pinned_ips = nextPinned;
  mockRoutesSnapshot.profile_route_id = activeProf.bound_route_id ?? null;
  recomputeMockEffective();
  return {
    previous_profile_id: prevActive,
    active_profile: activeProf,
    cleaned_cache_items: 7,
    restored_files: 5,
    pinned_ip_updated: activeProf.bound_ip || null,
    bound_upstream_key_updated: activeProf.bound_upstream_key || null,
    message: `Очищено кэшей: 7, восстановлен изолированный Device ID: #${activeProf.isolated_device_id.slice(0, 8)}`,
  };
}

export async function deleteClaudeProfile(profileId: string): Promise<ClaudeProfileListResponse> {
  if (isTauri()) {
    return await tauriInvoke<ClaudeProfileListResponse>("delete_claude_profile_cmd", { profileId });
  }
  if (mockProfiles.length > 1) {
    const filtered = mockProfiles.filter((p) => p.id !== profileId);
    if (!filtered.some((p) => p.is_active)) {
      filtered[0].is_active = true;
    }
    setMockProfilesList(filtered);
  }
  return await listClaudeProfiles();
}

export async function bindIpToClaudeProfile(
  profileId: string,
  ip: string,
  country?: string | null,
): Promise<ClaudeProfileListResponse> {
  if (isTauri()) {
    return await tauriInvoke<ClaudeProfileListResponse>("bind_ip_to_claude_profile_cmd", {
      profileId,
      bindIp: ip,
      bindCountry: country ?? null,
    });
  }
  setMockProfilesList(
    mockProfiles.map((p) =>
      p.id === profileId ? { ...p, bound_ip: ip, bound_country: country || null } : p,
    ),
  );
  return await listClaudeProfiles();
}

export async function bindUpstreamToClaudeProfile(
  profileId: string,
  upstreamKey: string | null,
): Promise<ClaudeProfileListResponse> {
  if (isTauri()) {
    return await tauriInvoke<ClaudeProfileListResponse>("bind_upstream_to_claude_profile_cmd", {
      profileId,
      upstreamKey: upstreamKey || null,
    });
  }
  const route = upstreamKey ? await upsertRoute(upstreamKey, null, false) : null;
  setMockProfilesList(
    mockProfiles.map((p) =>
      p.id === profileId
        ? {
            ...p,
            bound_upstream_key: upstreamKey || null,
            bound_route_id: route ? route.id : null,
          }
        : p,
    ),
  );
  return await listClaudeProfiles();
}

export async function bindRouteToClaudeProfile(
  profileId: string,
  routeId: string | null,
): Promise<ClaudeProfileListResponse> {
  if (isTauri()) {
    return await tauriInvoke<ClaudeProfileListResponse>("bind_route_to_claude_profile", {
      profileId,
      routeId: routeId || null,
    });
  }
  const route = routeId ? mockRoutesSnapshot.routes.find((r) => r.id === routeId) : null;
  const next = mockProfiles.map((p) =>
    p.id === profileId
      ? {
          ...p,
          bound_upstream_key: route ? `zastava://mock-${route.id}` : null,
          bound_route_id: route ? route.id : null,
        }
      : p,
  );
  setMockProfilesList(next);
  const active = next.find((p) => p.is_active);
  if (active?.id === profileId) {
    mockRoutesSnapshot.profile_route_id = route ? route.id : null;
    recomputeMockEffective();
  }
  return await listClaudeProfiles();
}

export async function safeLogoutClaude(): Promise<SafeLogoutResult> {
  if (isTauri()) {
    return await tauriInvoke<SafeLogoutResult>("safe_logout_claude_cmd");
  }
  const now = Math.floor(Date.now() / 1000);
  const cooldownSecs = 4 * 3600;
  const cooldownUntil = now + cooldownSecs;
  mockState.last_safe_logout_at = now;
  mockState.ip_change_cooldown_until = cooldownUntil;
  return {
    closed_processes: 2,
    cleared_items: ["Cookies", "Local Storage", "Session Storage", "IndexedDB"],
    preserved_device_id: true,
    cooldown_until: cooldownUntil,
    cooldown_secs: cooldownSecs,
  };
}

export async function clearIpChangeCooldown(): Promise<void> {
  if (isTauri()) {
    await tauriInvoke<void>("clear_ip_change_cooldown_cmd");
    return;
  }
  mockState.ip_change_cooldown_until = null;
}
