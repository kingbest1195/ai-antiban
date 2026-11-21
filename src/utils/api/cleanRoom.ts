import type {
  CleanRoomAuditReport,
  CleanRoomProfile,
  CleanRoomState,
  CreateCleanProfileInput,
  DetectedBrowser,
  LaunchCleanBrowserResult,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";
import {
  mockCreateCleanProfile,
  mockDeleteCleanProfile,
  mockDiscoverCleanBrowsers,
  mockLaunchCleanBrowser,
  mockListCleanProfiles,
  mockMarkCleanProfileTainted,
  mockMarkIpTainted,
  mockRunCleanRoomAudit,
  mockStartCleanProfileWarmup,
  mockUntaintCleanRoomIp,
  mockUpdateCleanProfileRoute,
  mockUpdateCleanProfileStep,
} from "./mocks/cleanRoom";

// Переиспользуем существующие команды системного TZ из sysproxy.ts без дублирования invoke-обёрток.
export { getOsTimezoneSyncStatus as getOsTzStatus } from "./sysproxy";

/** Запустить pre-flight аудит «Чистой комнаты» (проверка следов и маршрута без чтения секретов). */
export async function runCleanRoomAudit(
  profileId?: string | null,
  routeId?: string | null,
): Promise<CleanRoomAuditReport> {
  if (isTauri()) {
    return await tauriInvoke<CleanRoomAuditReport>("run_clean_room_audit", {
      profileId: profileId ?? null,
      routeId: routeId ?? null,
    });
  }
  return mockRunCleanRoomAudit(profileId ?? undefined, routeId ?? undefined);
}

/** Найти установленные поддерживаемые движки Chromium (Chrome / Edge / Brave). */
export async function discoverCleanBrowsers(): Promise<DetectedBrowser[]> {
  if (isTauri()) {
    return await tauriInvoke<DetectedBrowser[]>("discover_clean_browsers");
  }
  return mockDiscoverCleanBrowsers();
}

/** Получить список профилей «Чистой комнаты», активный профиль и tainted_ips. */
export async function listCleanProfiles(): Promise<CleanRoomState> {
  if (isTauri()) {
    return await tauriInvoke<CleanRoomState>("list_clean_profiles");
  }
  return mockListCleanProfiles();
}

/** Создать новый изолированный профиль браузерной песочницы. */
export async function createCleanProfile(
  input: CreateCleanProfileInput,
): Promise<CleanRoomProfile> {
  if (isTauri()) {
    return await tauriInvoke<CleanRoomProfile>("create_clean_profile", { input });
  }
  return mockCreateCleanProfile(input);
}

/** Сохранить текущий шаг 4-шагового Launchpad и прогресс чек-листа профиля. */
export async function updateCleanProfileStep(
  profileId: string,
  step: number,
  completedChecklist?: string[],
): Promise<CleanRoomProfile> {
  if (isTauri()) {
    return await tauriInvoke<CleanRoomProfile>("update_clean_profile_step", {
      profileId,
      step,
      completedChecklist: completedChecklist ?? null,
    });
  }
  return mockUpdateCleanProfileStep(profileId, step, completedChecklist);
}

/** Запустить 96-часовой прогрев профиля (синхронизирует profile.warmup_started_at и legacy warmup_started_at). */
export async function startCleanProfileWarmup(profileId: string): Promise<CleanRoomProfile> {
  if (isTauri()) {
    return await tauriInvoke<CleanRoomProfile>("start_clean_profile_warmup", { profileId });
  }
  return mockStartCleanProfileWarmup(profileId);
}

/** Запустить изолированное окно браузера с hardened-флагами и привязанным loopback-алиасом. */
export async function launchCleanBrowser(
  profileId: string,
  targetUrl?: string,
): Promise<LaunchCleanBrowserResult> {
  if (isTauri()) {
    return await tauriInvoke<LaunchCleanBrowserResult>("launch_clean_browser", {
      profileId,
      targetUrl: targetUrl ?? null,
    });
  }
  return mockLaunchCleanBrowser(profileId, targetUrl);
}

/** Пометить профиль как скомпрометированный (tainted) и занести его exit IP в tainted_ips. */
export async function markCleanProfileTainted(
  profileId: string,
  reason?: string,
): Promise<CleanRoomProfile> {
  if (isTauri()) {
    return await tauriInvoke<CleanRoomProfile>("mark_clean_profile_tainted", {
      profileId,
      reason: reason ?? null,
    });
  }
  return mockMarkCleanProfileTainted(profileId, reason);
}

/** Обновить привязанный маршрут профиля «Чистой комнаты». */
export async function updateCleanProfileRoute(
  profileId: string,
  routeId: string | null,
): Promise<CleanRoomProfile> {
  if (isTauri()) {
    return await tauriInvoke<CleanRoomProfile>("update_clean_profile_route", {
      profileId,
      routeId,
    });
  }
  return mockUpdateCleanProfileRoute(profileId, routeId);
}

/** Удалить изолированный профиль и его каталог данных (с явной опцией пометки IP). */
export async function deleteCleanProfile(
  profileId: string,
  taintExitIp = false,
): Promise<CleanRoomState> {
  if (isTauri()) {
    return await tauriInvoke<CleanRoomState>("delete_clean_profile", {
      profileId,
      taintExitIp,
    });
  }
  return mockDeleteCleanProfile(profileId, taintExitIp);
}

/** Пометить указанный (или текущий) выходной IP как скомпрометированный. */
export async function markIpTainted(ip?: string): Promise<CleanRoomState> {
  if (isTauri()) {
    return await tauriInvoke<CleanRoomState>("mark_ip_tainted", { ip: ip ?? null });
  }
  return mockMarkIpTainted(ip);
}

/** Снять отметку о компрометации (tainted) с указанного IP-адреса. */
export async function untaintCleanRoomIp(ip: string): Promise<CleanRoomState> {
  if (isTauri()) {
    return await tauriInvoke<CleanRoomState>("untaint_clean_room_ip", { ip });
  }
  return mockUntaintCleanRoomIp(ip);
}
