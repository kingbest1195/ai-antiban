import type { BunkerSettings } from "./state";

export type { BunkerSettings };

export type BunkerSourceKind =
  | "claude_code"
  | "claude_desktop"
  | "cursor"
  | "web_export"
  | (string & {});

export type BunkerTrigger = "auto" | "manual" | "emergency" | (string & {});

export interface BunkerSourceSummary {
  kind: BunkerSourceKind;
  available: boolean;
  label: string;
  path_hint: string | null;
  items_count: number;
  total_bytes: number;
}

export interface BunkerSnapshotMeta {
  id: string;
  created_at: number;
  snapshot_dir: string;
  total_bytes: number;
  files_count: number;
  sources: BunkerSourceKind[];
  has_restore_prompt: boolean;
  trigger: BunkerTrigger;
}

export interface BunkerStatus {
  settings: BunkerSettings;
  bunker_dir: string;
  snapshots_count: number;
  total_snapshots_bytes: number;
  latest_snapshot: BunkerSnapshotMeta | null;
  sources: BunkerSourceSummary[];
  has_any_local_data: boolean;
}

export interface BunkerBackupResult {
  snapshot: BunkerSnapshotMeta;
  restore_prompt_path: string;
  exported_copy_dir: string | null;
  pruned_snapshots: number;
}

export interface WebExportConvertResult {
  source_path: string;
  detected_provider: "claude" | "chatgpt" | "unknown" | (string & {});
  output_dir: string;
  markdown_files: string[];
  conversations_count: number;
  restore_prompt_path: string;
  restore_prompt_preview: string;
}

export interface BunkerSettingsPatch {
  auto_backup_enabled?: boolean;
  interval_hours?: number;
  retention_count?: number;
}
