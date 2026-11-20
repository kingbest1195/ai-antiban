import type {
  BunkerBackupResult,
  BunkerSettings,
  BunkerSettingsPatch,
  BunkerSnapshotMeta,
  BunkerStatus,
  WebExportConvertResult,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";
import {
  mockConvertWebExport,
  mockGenerateBunkerRestorePrompt,
  mockGetBunkerStatus,
  mockListBunkerSnapshots,
  mockRunBunkerBackupNow,
  mockUpdateBunkerSettings,
} from "./mocks/bunker";

/** Получить сводку локального «Бункера данных»: настройки, источники и последний снапшот. */
export async function getBunkerStatus(): Promise<BunkerStatus> {
  if (isTauri()) {
    return await tauriInvoke<BunkerStatus>("get_bunker_status");
  }
  return mockGetBunkerStatus();
}

/** Обновить настройки автобэкапа и ротации снапшотов Бункера. */
export async function updateBunkerSettings(
  settings: BunkerSettingsPatch,
): Promise<BunkerSettings> {
  if (isTauri()) {
    return await tauriInvoke<BunkerSettings>("update_bunker_settings", { settings });
  }
  return mockUpdateBunkerSettings(settings);
}

/** Немедленно создать локальный снапшот Бункера (и опционально скопировать в destinationDir). */
export async function runBunkerBackupNow(
  destinationDir?: string,
): Promise<BunkerBackupResult> {
  if (isTauri()) {
    return await tauriInvoke<BunkerBackupResult>("run_bunker_backup_now", {
      destinationDir: destinationDir ?? null,
    });
  }
  return mockRunBunkerBackupNow(destinationDir);
}

/** Получить список локальных снапшотов Бункера (от новых к старым). */
export async function listBunkerSnapshots(): Promise<BunkerSnapshotMeta[]> {
  if (isTauri()) {
    return await tauriInvoke<BunkerSnapshotMeta[]>("list_bunker_snapshots");
  }
  return mockListBunkerSnapshots();
}

/** Открыть папку снапшотов Бункера в системном файловом менеджере. */
export async function openBunkerFolder(): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke<void>("open_bunker_folder");
  }
}

/** Локально сконвертировать официальный экспорт Claude / ChatGPT (`conversations.json` / `.zip`) в Markdown + `RESTORE_PROMPT.md`. */
export async function convertWebExport(
  sourcePath: string,
  outputDir?: string,
): Promise<WebExportConvertResult> {
  if (isTauri()) {
    return await tauriInvoke<WebExportConvertResult>("convert_web_export", {
      sourcePath,
      outputDir: outputDir ?? null,
    });
  }
  return mockConvertWebExport(sourcePath, outputDir);
}

/** Сгенерировать актуальный текст `RESTORE_PROMPT.md` для быстрого переноса контекста (Claude Code + Cursor + MCP). */
export async function generateBunkerRestorePrompt(): Promise<string> {
  if (isTauri()) {
    return await tauriInvoke<string>("generate_bunker_restore_prompt");
  }
  return mockGenerateBunkerRestorePrompt();
}
