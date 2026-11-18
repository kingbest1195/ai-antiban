import type {
  CoverageSnapshot,
  PolicyApplyReport,
  RelaunchBrowsersResult,
  RestartOutcome,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";
import {
  bumpMockCoverageStage,
  currentMockRestartOutcome,
  mockCoverageSnapshot,
  setMockPacPolicyApplied,
} from "./mocks/coverage";
import { mockFlags } from "./mocks/state";

export async function getCoverageSnapshot(): Promise<CoverageSnapshot> {
  if (isTauri()) {
    return await tauriInvoke<CoverageSnapshot>("get_coverage_snapshot");
  }
  return mockCoverageSnapshot();
}

/** Принудительная перепроверка: шлюз заново читает ОС и файлы и отдаёт свежий снимок. */
export async function recheckCoverage(): Promise<CoverageSnapshot> {
  if (isTauri()) {
    return await tauriInvoke<CoverageSnapshot>("recheck_coverage");
  }
  bumpMockCoverageStage();
  return mockCoverageSnapshot();
}

/** Принудительно применяет управляемые политики браузеров (Chrome/Edge/Brave/Firefox) на локальный PAC. */
export async function reapplyBrowserPolicies(): Promise<PolicyApplyReport> {
  if (isTauri()) {
    return await tauriInvoke<PolicyApplyReport>("reapply_browser_policies_cmd");
  }
  setMockPacPolicyApplied(true);
  return {
    applied: 1,
    unchanged: 0,
    skipped: 0,
    failed: 0,
    pac_policy_active: true,
  };
}

/** Закрывает запущенные браузеры без PAC, патчит их профили и перезапускает с `--proxy-pac-url`. */
export async function relaunchBrowsersWithPac(): Promise<RelaunchBrowsersResult> {
  if (isTauri()) {
    return await tauriInvoke<RelaunchBrowsersResult>("relaunch_browsers_with_pac_cmd");
  }
  await new Promise((resolve) => setTimeout(resolve, 600));
  setMockPacPolicyApplied(true);
  return {
    restarted: ["Google Chrome"],
    skipped: [],
    failed: [],
    needs_automation_permission: false,
    unsupported: false,
    snapshot: mockCoverageSnapshot(),
  };
}

/**
 * Закрывает Antigravity и открывает заново с адресом шлюза. Передаётся только id: путь, процесс и адрес определяет шлюз.
 * Ошибка команды (в том числе отказ из белого списка) — как неудачный запуск.
 */
export async function restartAppWithGateway(appId: "antigravity"): Promise<RestartOutcome> {
  if (isTauri()) {
    try {
      return await tauriInvoke<RestartOutcome>("restart_app_with_gateway", { appId });
    } catch {
      return "launch_failed";
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 1200));
  return currentMockRestartOutcome();
}

export async function takePendingDeepLink(): Promise<string | null> {
  if (isTauri()) {
    return await tauriInvoke<string | null>("take_pending_deep_link");
  }

  if (typeof window !== "undefined" && window.location.hash.startsWith("#zastava://")) {
    const link = decodeURIComponent(window.location.hash.slice(1));
    try {
      history.replaceState(null, "", window.location.pathname + window.location.search);
    } catch {
      window.location.hash = "";
    }
    return link;
  }

  const pending = mockFlags.pendingDeepLink;
  mockFlags.pendingDeepLink = null;
  return pending;
}
