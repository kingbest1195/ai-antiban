export interface ClaudeProjectBrief {
  slug: string;
  decoded_path: string;
  sessions_count: number;
  has_memory: boolean;
  total_bytes: number;
  last_modified?: number | null;
}

export interface ClaudeLocalDataSummary {
  exists: boolean;
  claude_dir_path: string;
  projects_count: number;
  sessions_count: number;
  plans_count: number;
  memory_files_count: number;
  total_size_bytes: number;
  projects: ClaudeProjectBrief[];
  has_claude_md: boolean;
  has_history: boolean;
  has_settings: boolean;
  has_desktop_config: boolean;
  has_claude_json: boolean;
}

export interface ClaudeExportResult {
  export_dir_path: string;
  zip_archive_path?: string | null;
  index_summary_path: string;
  restore_prompt_path: string;
  restore_prompt_text: string;
  projects_exported: number;
  sessions_exported: number;
  total_bytes: number;
}

export interface ClaudeProfile {
  id: string;
  name: string;
  bound_ip?: string | null;
  bound_country?: string | null;
  bound_upstream_key?: string | null;
  bound_route_id?: string | null;
  isolated_device_id: string;
  created_at: number;
  last_used_at: number;
  is_active: boolean;
  has_saved_session: boolean;
}

export interface ClaudeProfileListResponse {
  profiles: ClaudeProfile[];
  active_profile_id: string;
  claude_desktop_installed: boolean;
  storage_dir: string;
}

export interface ProfileSwitchResult {
  previous_profile_id: string;
  active_profile: ClaudeProfile;
  cleaned_cache_items: number;
  restored_files: number;
  pinned_ip_updated?: string | null;
  bound_upstream_key_updated?: string | null;
  message: string;
}

export interface SafeLogoutResult {
  closed_processes: number;
  cleared_items: string[];
  preserved_device_id: boolean;
  cooldown_until: number;
  cooldown_secs: number;
}
