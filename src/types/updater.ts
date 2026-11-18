export interface UpdateCheckResult {
  current_version: string;
  latest_version: string;
  update_available: boolean;
  release_name: string;
  release_notes: string;
  release_url: string;
  published_at?: string | null;
}

/** Код ошибки проверки/установки обновления; приходит из Rust как { kind, message? }. */
export type UpdateFailureKind = "network" | "signature" | "no-release" | "install" | "install-restored";

export interface UpdateProgressPayload {
  downloaded_bytes: number;
  total_bytes: number;
  percent: number;
  phase: string;
}

export interface UpdateStatusPayload {
  /** downloading | installing | restarting из Rust; "failed" выставляет сам фронт при ошибке установки. */
  stage: string;
  message: string;
  /** Только при stage === "failed". */
  error?: UpdateFailureKind;
}

export interface InstallUpdateResult {
  success: boolean;
  message: string;
  will_restart: boolean;
}

export interface RollbackReleaseInfo {
  version: string;
  tag: string;
  name: string | null;
  published_at: string | null;
  notes_url: string | null;
}
