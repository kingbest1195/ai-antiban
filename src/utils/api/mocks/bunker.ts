import type {
  BunkerBackupResult,
  BunkerSettings,
  BunkerSettingsPatch,
  BunkerSnapshotMeta,
  BunkerSourceSummary,
  BunkerStatus,
  WebExportConvertResult,
} from "../../../types";
import { mockState } from "./state";

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function ensureBunkerSettings(): BunkerSettings {
  if (!mockState.bunker) {
    mockState.bunker = {
      auto_backup_enabled: true,
      interval_hours: 24,
      retention_count: 7,
      max_total_mb: 500,
      last_backup_at: null,
      last_backup_size_bytes: null,
    };
  }
  if (mockState.bunker.max_total_mb === undefined) {
    mockState.bunker.max_total_mb = 500;
  }
  return mockState.bunker;
}

let mockSnapshots: BunkerSnapshotMeta[] = [
  {
    id: "2026-11-20_053000",
    created_at: nowSec() - 3600,
    snapshot_dir: "~/.zastava/bunker/snapshots/2026-11-20_053000",
    total_bytes: 2_450_000,
    files_count: 42,
    sources: ["claude_code", "claude_desktop", "cursor"],
    has_restore_prompt: true,
    trigger: "auto",
  },
];

export function setMockBunkerSnapshots(next: BunkerSnapshotMeta[]): void {
  mockSnapshots = next.map((s) => ({ ...s, sources: [...s.sources] }));
}

function mockSourcesSummary(): BunkerSourceSummary[] {
  return [
    {
      kind: "claude_code",
      available: true,
      label: "Claude Code (~/.claude)",
      path_hint: "~/.claude",
      items_count: 14,
      total_bytes: 1_850_000,
    },
    {
      kind: "claude_desktop",
      available: true,
      label: "Claude Desktop (MCP & config)",
      path_hint: "~/Library/Application Support/Claude/claude_desktop_config.json",
      items_count: 1,
      total_bytes: 4_200,
    },
    {
      kind: "cursor",
      available: true,
      label: "Cursor IDE (settings & MCP)",
      path_hint: "~/Library/Application Support/Cursor/User/settings.json",
      items_count: 6,
      total_bytes: 595_800,
    },
  ];
}

export function mockListBunkerSnapshots(): BunkerSnapshotMeta[] {
  return mockSnapshots.map((s) => ({ ...s, sources: [...s.sources] }));
}

export function mockGetBunkerStatus(): BunkerStatus {
  const settings = { ...ensureBunkerSettings() };
  const snapshots = mockListBunkerSnapshots();
  const latest = snapshots[0] ?? null;
  if (latest && settings.last_backup_at === null) {
    settings.last_backup_at = latest.created_at;
    settings.last_backup_size_bytes = latest.total_bytes;
  }
  const sources = mockSourcesSummary();
  return {
    settings,
    bunker_dir: "~/.zastava/bunker/snapshots",
    snapshots_count: snapshots.length,
    total_snapshots_bytes: snapshots.reduce((sum, s) => sum + s.total_bytes, 0),
    latest_snapshot: latest,
    sources,
    has_any_local_data: sources.some((s) => s.available),
  };
}

export function mockUpdateBunkerSettings(patch: BunkerSettingsPatch): BunkerSettings {
  const current = ensureBunkerSettings();
  if (patch.auto_backup_enabled !== undefined) {
    current.auto_backup_enabled = patch.auto_backup_enabled;
  }
  if (patch.interval_hours !== undefined) {
    current.interval_hours = Math.max(1, Math.trunc(patch.interval_hours));
  }
  if (patch.retention_count !== undefined) {
    current.retention_count = Math.max(1, Math.trunc(patch.retention_count));
  }
  if (patch.max_total_mb !== undefined) {
    current.max_total_mb = Math.max(50, Math.trunc(patch.max_total_mb));
  }
  return { ...current };
}

export function mockClearBunkerSnapshots(): BunkerStatus {
  mockSnapshots = mockSnapshots.length > 1 ? mockSnapshots.slice(0, 1) : [];
  return mockGetBunkerStatus();
}

export function mockRunBunkerBackupNow(destinationDir?: string): BunkerBackupResult {
  const settings = ensureBunkerSettings();
  const ts = nowSec();
  const id = new Date(ts * 1000).toISOString().replace(/[-:]/g, "").slice(0, 15);
  const snapshot: BunkerSnapshotMeta = {
    id,
    created_at: ts,
    snapshot_dir: `~/.zastava/bunker/snapshots/${id}`,
    total_bytes: 2_520_000,
    files_count: 45,
    sources: ["claude_code", "claude_desktop", "cursor"],
    has_restore_prompt: true,
    trigger: "manual",
  };
  mockSnapshots = [snapshot, ...mockSnapshots];
  const retention = Math.max(1, settings.retention_count);
  let pruned = 0;
  if (mockSnapshots.length > retention) {
    pruned = mockSnapshots.length - retention;
    mockSnapshots = mockSnapshots.slice(0, retention);
  }
  settings.last_backup_at = ts;
  settings.last_backup_size_bytes = snapshot.total_bytes;

  return {
    snapshot: { ...snapshot, sources: [...snapshot.sources] },
    restore_prompt_path: `${snapshot.snapshot_dir}/RESTORE_PROMPT.md`,
    exported_copy_dir: destinationDir?.trim() ? `${destinationDir.trim()}/${id}` : null,
    pruned_snapshots: pruned,
  };
}

export function mockConvertWebExport(
  sourcePath: string,
  outputDir?: string,
): WebExportConvertResult {
  const cleanSource = sourcePath.trim();
  if (!cleanSource) {
    throw new Error("Укажите путь к файлу экспорта conversations.json или export.zip.");
  }
  const isChatGpt = /chatgpt|openai/i.test(cleanSource);
  const targetDir = outputDir?.trim() || "~/.zastava/bunker/web-exports/latest";
  return {
    source_path: cleanSource,
    detected_provider: isChatGpt ? "chatgpt" : "claude",
    output_dir: targetDir,
    markdown_files: [
      `${targetDir}/01-project-architecture.md`,
      `${targetDir}/02-billing-notes.md`,
    ],
    conversations_count: 12,
    restore_prompt_path: `${targetDir}/RESTORE_PROMPT.md`,
    restore_prompt_preview: mockGenerateBunkerRestorePrompt(),
  };
}

export function mockGenerateBunkerRestorePrompt(): string {
  return [
    "# Контекст восстановления (Zastava Data Bunker)",
    "",
    "## Активные проекты Claude Code",
    "- `zastava` (`~/local-projects/zastava`): Zastava v3.0.0 Desktop Gateway",
    "",
    "## Конфигурация Cursor IDE и MCP",
    "- Настройки: `~/.cursor/mcp.json`, `settings.json`",
    "- Продолжи работу с последнего зафиксированного состояния без потери контекста.",
  ].join("\n");
}
