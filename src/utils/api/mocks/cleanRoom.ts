import type {
  CleanRoomAuditReport,
  CleanRoomFinding,
  CleanRoomProfile,
  CleanRoomState,
  CleanRoomTzCheck,
  CreateCleanProfileInput,
  DetectedBrowser,
  LaunchCleanBrowserResult,
} from "../../../types";
import { DIRECT_ROUTE_ID, mockFlags, mockRoutesSnapshot, mockState } from "./state";

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function ensureCleanRoomState(): CleanRoomState {
  if (!mockState.clean_room) {
    mockState.clean_room = {
      profiles: [],
      active_profile_id: null,
      tainted_ips: {},
    };
  }
  return mockState.clean_room;
}

function cloneProfile(profile: CleanRoomProfile): CleanRoomProfile {
  return {
    ...profile,
    completed_checklist: [...profile.completed_checklist],
  };
}

function cloneCleanRoomState(cr: CleanRoomState): CleanRoomState {
  return {
    profiles: cr.profiles.map(cloneProfile),
    active_profile_id: cr.active_profile_id,
    tainted_ips: { ...cr.tainted_ips },
  };
}

export function currentMockExitInfo(routeId?: string | null): {
  ip: string;
  country: string;
  timezone: string;
} {
  if (routeId && routeId !== DIRECT_ROUTE_ID) {
    const found = mockRoutesSnapshot.routes.find((r) => r.id === routeId && r.enabled);
    if (found?.exit_ip) {
      const country = found.country || "NL";
      const tz = country === "US" ? "America/New_York" : country === "DE" ? "Europe/Berlin" : "Europe/Amsterdam";
      return { ip: found.exit_ip, country, timezone: tz };
    }
  }
  if (mockFlags.scenario === "turkey") {
    return { ip: "185.220.101.5", country: "TR", timezone: "Europe/Istanbul" };
  }
  if (mockFlags.scenario === "ru") {
    return { ip: "95.165.10.22", country: "RU", timezone: "Europe/Moscow" };
  }
  return {
    ip: mockState.pinned_ip || "185.212.102.40",
    country: "NL",
    timezone: "Europe/Amsterdam",
  };
}

export function mockDiscoverCleanBrowsers(): DetectedBrowser[] {
  return [
    {
      engine: "chrome",
      display_name: "Google Chrome",
      executable_path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      available: true,
    },
    {
      engine: "edge",
      display_name: "Microsoft Edge",
      executable_path: "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
      available: true,
    },
    {
      engine: "brave",
      display_name: "Brave Browser",
      executable_path: "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
      available: false,
    },
  ];
}

export function mockRunCleanRoomAudit(profileId?: string, routeId?: string): CleanRoomAuditReport {
  const cr = ensureCleanRoomState();
  const targetProfile = profileId ? cr.profiles.find((p) => p.id === profileId) : undefined;
  const resolvedRouteId =
    routeId !== undefined
      ? routeId
      : (targetProfile?.bound_route_id ?? mockRoutesSnapshot.default_route_id);
  const exit = currentMockExitInfo(resolvedRouteId);
  const ipIsTainted = Boolean(cr.tainted_ips[exit.ip]);
  const osTzMatchesExit = mockFlags.osTzCurrent === exit.timezone;
  const findings: CleanRoomFinding[] = [];

  if (mockFlags.killswitchStatus) {
    findings.push({
      id: "killswitch_active",
      category: "network_leak",
      title: "Сеть для ИИ остановлена вручную",
      detail: "При активном Kill-Switch запуск изолированного окна заблокирован.",
      severity: "critical",
      path_hint: null,
      fix_action: { kind: "switch_route_or_vpn" },
    });
  }

  if (mockFlags.scenario === "ru") {
    findings.push({
      id: "exit_ip_sanctioned",
      category: "network_leak",
      title: "Выходной IP находится в РФ",
      detail: `Текущий IP ${exit.ip} (${exit.country}) заблокирован ИИ-провайдерами.`,
      severity: "critical",
      path_hint: null,
      fix_action: { kind: "switch_route_or_vpn" },
    });
  }

  if (ipIsTainted) {
    findings.push({
      id: "exit_ip_tainted",
      category: "ip_collision",
      title: "Выходной IP помечен как скомпрометированный",
      detail: `На адресе ${exit.ip} ранее был зафиксирован бан или запрос Persona. Смените ключ/сервер.`,
      severity: "critical",
      path_hint: null,
      fix_action: { kind: "switch_route_or_vpn" },
    });
  }

  if (targetProfile?.status === "tainted") {
    findings.push({
      id: "profile_tainted",
      category: "browser",
      title: "Выбранный профиль помечен как скомпрометированный",
      detail: "Создайте новый чистый профиль вместо повторного использования забаненного.",
      severity: "critical",
      path_hint: `clean-profiles/${targetProfile.id}`,
      fix_action: { kind: "acknowledge_sandbox_isolation" },
    });
  }

  if (!osTzMatchesExit) {
    findings.push({
      id: "os_tz_mismatch",
      category: "os_tz_locale",
      title: "Часовой пояс ОС не совпадает с IP выхода",
      detail: `ОС: ${mockFlags.osTzCurrent}, выход: ${exit.timezone}. Для браузерной песочницы на Windows рекомендуется синхронизировать TZ ОС.`,
      severity: "warning",
      path_hint: null,
      fix_action: { kind: "sync_os_timezone", target_iana: exit.timezone },
    });
  }

  if (findings.length === 0) {
    findings.push({
      id: "clean_ready",
      category: "browser",
      title: "Следов прошлых банов и утечек не обнаружено",
      detail: "Выходной IP чист, изолированное окно готово к запуску.",
      severity: "ok",
      path_hint: null,
      fix_action: null,
    });
  }

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const warningCount = findings.filter((f) => f.severity === "warning").length;

  return {
    checked_at: nowSec(),
    exit_ip: exit.ip,
    exit_country: exit.country,
    exit_timezone: exit.timezone,
    ip_is_tainted: ipIsTainted,
    os_tz_matches_exit: osTzMatchesExit,
    findings,
    critical_count: criticalCount,
    warning_count: warningCount,
    ready_to_launch: criticalCount === 0,
  };
}

export function mockListCleanProfiles(): CleanRoomState {
  return cloneCleanRoomState(ensureCleanRoomState());
}

export function mockCreateCleanProfile(input: CreateCleanProfileInput): CleanRoomProfile {
  const cr = ensureCleanRoomState();
  const label = input.label.trim();
  if (!label) {
    throw new Error("Укажите название чистого профиля.");
  }
  const profile: CleanRoomProfile = {
    id: `cr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    label,
    provider: input.provider || "anthropic",
    browser_engine: input.browser_engine || "chrome",
    bound_route_id: input.bound_route_id ?? null,
    last_exit_ip: null,
    last_exit_country: null,
    status: "active",
    created_at: nowSec(),
    last_opened_at: null,
    warmup_started_at: null,
    launchpad_step: 1,
    completed_checklist: [],
  };
  cr.profiles.push(profile);
  cr.active_profile_id = profile.id;
  return cloneProfile(profile);
}

function findProfileOrThrow(cr: CleanRoomState, profileId: string): CleanRoomProfile {
  const found = cr.profiles.find((p) => p.id === profileId);
  if (!found) {
    throw new Error(`Профиль «${profileId}» не найден.`);
  }
  return found;
}

export function mockUpdateCleanProfileStep(
  profileId: string,
  step: number,
  completedChecklist?: string[],
): CleanRoomProfile {
  const cr = ensureCleanRoomState();
  const profile = findProfileOrThrow(cr, profileId);
  profile.launchpad_step = Math.min(4, Math.max(1, Math.trunc(step)));
  if (completedChecklist !== undefined) {
    profile.completed_checklist = [...completedChecklist];
  }
  if (profile.launchpad_step === 4 && profile.status === "active") {
    profile.status = "ready";
  }
  return cloneProfile(profile);
}

export function mockStartCleanProfileWarmup(profileId: string): CleanRoomProfile {
  const cr = ensureCleanRoomState();
  const profile = findProfileOrThrow(cr, profileId);
  const ts = nowSec();
  profile.status = "warming_up";
  profile.warmup_started_at = ts;
  profile.launchpad_step = Math.max(profile.launchpad_step, 3);
  mockState.warmup_started_at = ts;
  return cloneProfile(profile);
}

export function mockLaunchCleanBrowser(
  profileId: string,
  targetUrl?: string,
): LaunchCleanBrowserResult {
  const cr = ensureCleanRoomState();
  const profile = findProfileOrThrow(cr, profileId);
  const audit = mockRunCleanRoomAudit(profileId);
  if (!audit.ready_to_launch) {
    throw new Error(
      "Запуск песочницы заблокирован: устраните критические замечания в «Детекторе хвостов».",
    );
  }
  const exit = currentMockExitInfo(profile.bound_route_id);
  profile.last_opened_at = nowSec();
  profile.last_exit_ip = exit.ip;
  profile.last_exit_country = exit.country;
  cr.active_profile_id = profile.id;

  return {
    profile_id: profile.id,
    browser_engine: profile.browser_engine,
    pid: 42000 + (cr.profiles.indexOf(profile) % 1000),
    alias_port: 41200 + (cr.profiles.indexOf(profile) % 500),
    target_url: targetUrl ?? null,
    tz_applied: exit.timezone,
    profile_dir: `~/.zastava/clean-profiles/${profile.id}`,
  };
}

export function mockMarkCleanProfileTainted(
  profileId: string,
  _reason?: string,
): CleanRoomProfile {
  const cr = ensureCleanRoomState();
  const profile = findProfileOrThrow(cr, profileId);
  profile.status = "tainted";
  const ipToTaint = profile.last_exit_ip || currentMockExitInfo().ip;
  cr.tainted_ips[ipToTaint] = nowSec();
  return cloneProfile(profile);
}

export function mockUpdateCleanProfileRoute(
  profileId: string,
  routeId: string | null,
): CleanRoomProfile {
  const cr = ensureCleanRoomState();
  const profile = findProfileOrThrow(cr, profileId);
  profile.bound_route_id = routeId && routeId !== DIRECT_ROUTE_ID ? routeId : null;
  return cloneProfile(profile);
}

export function mockDeleteCleanProfile(
  profileId: string,
  taintExitIp = false,
): CleanRoomState {
  const cr = ensureCleanRoomState();
  const removed = cr.profiles.find((p) => p.id === profileId);
  if (taintExitIp && removed?.last_exit_ip) {
    cr.tainted_ips[removed.last_exit_ip] = nowSec();
  }
  cr.profiles = cr.profiles.filter((p) => p.id !== profileId);
  if (cr.active_profile_id === profileId) {
    cr.active_profile_id = cr.profiles[0]?.id ?? null;
  }
  return cloneCleanRoomState(cr);
}

export function mockMarkIpTainted(ip?: string): CleanRoomState {
  const cr = ensureCleanRoomState();
  const targetIp = ip?.trim() || currentMockExitInfo().ip;
  cr.tainted_ips[targetIp] = nowSec();
  return cloneCleanRoomState(cr);
}

export function mockUntaintCleanRoomIp(ip: string): CleanRoomState {
  const cr = ensureCleanRoomState();
  const targetIp = ip.trim();
  if (targetIp) {
    delete cr.tainted_ips[targetIp];
  }
  return cloneCleanRoomState(cr);
}

export function mockGetCleanRoomTzCheck(): CleanRoomTzCheck {
  const exit = currentMockExitInfo();
  return {
    platform: "macos",
    exit_timezone: exit.timezone,
    os_timezone: mockFlags.osTzCurrent,
    matches_exit: mockFlags.osTzCurrent === exit.timezone,
    requires_os_sync: false,
    synced_by_zastava: Boolean(mockFlags.osTzOriginal),
  };
}
