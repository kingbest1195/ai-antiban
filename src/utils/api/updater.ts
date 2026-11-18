import type {
  InstallUpdateResult,
  RollbackReleaseInfo,
  UpdateCheckResult,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";

export async function checkForUpdates(): Promise<UpdateCheckResult> {
  if (isTauri()) {
    return await tauriInvoke<UpdateCheckResult>("check_for_updates");
  }
  return {
    current_version: "1.2.0",
    latest_version: "1.2.0",
    update_available: false,
    release_name: "Zastava v1.2.0: Multi-Account Isolator & Live VPN Crash-Test",
    release_notes:
      "Релиз v1.2.0: изоляция мульти-аккаунтов Claude, боевой краш-тест VPN, исправление мигания окон Windows 11.",
    release_url: "https://github.com/kingbest1195/ai-antiban/releases",
  };
}

/** Установка подписанного обновления. Ничего не принимает: адрес и подпись бэкенд берёт из latest.json. */
export async function installUpdate(): Promise<InstallUpdateResult> {
  if (isTauri()) {
    return await tauriInvoke<InstallUpdateResult>("install_update");
  }
  return {
    success: true,
    message: "Обновление готово к установке.",
    will_restart: true,
  };
}

/** Список предыдущих стабильных релизов на GitHub, доступных для отката. */
export async function listRollbackVersions(): Promise<RollbackReleaseInfo[]> {
  if (isTauri()) {
    return await tauriInvoke<RollbackReleaseInfo[]>("list_rollback_versions");
  }
  return [
    {
      version: "2.1.2",
      tag: "v2.1.2",
      name: "Zastava v2.1.2",
      published_at: "2026-11-10T12:00:00Z",
      notes_url: "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.1.2",
    },
    {
      version: "2.1.1",
      tag: "v2.1.1",
      name: "Zastava v2.1.1",
      published_at: "2026-11-05T12:00:00Z",
      notes_url: "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.1.1",
    },
  ];
}

/** Установка выбранной предыдущей версии (откат через подписанный latest.json релиза). */
export async function installRollbackVersion(
  version: string,
): Promise<InstallUpdateResult> {
  if (isTauri()) {
    return await tauriInvoke<InstallUpdateResult>("install_rollback_version", { version });
  }
  return {
    success: true,
    message: `Откат на v${version} готов к установке.`,
    will_restart: true,
  };
}
