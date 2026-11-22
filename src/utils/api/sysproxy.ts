import type {
  AutostartStatus,
  CliMode,
  CliProtectionReport,
  CliSettings,
  CoworkGuardStatus,
  OsTzSyncStatus,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";
import { currentMockStartup } from "./mocks/audit";
import { mockFlags, mockOption, mockState } from "./mocks/state";

export async function toggleSysproxy(enable: boolean): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("toggle_sysproxy", { enable });
  }
  if (enable && mockOption("mockAdminAuth") === "1") {
    throw new Error("ADMIN_AUTH_REQUIRED:Для включения системного прокси на macOS требуются права администратора.");
  }
  mockFlags.sysproxyActive = enable;
  mockFlags.cliProtection = enable;
  return mockFlags.sysproxyActive;
}

export async function toggleSysproxyPrivileged(): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("toggle_sysproxy_privileged");
  }
  mockFlags.sysproxyActive = true;
  mockFlags.cliProtection = true;
  return mockFlags.sysproxyActive;
}

export async function getSysproxyStatus(): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("get_sysproxy_status");
  }
  return mockFlags.sysproxyActive && currentMockStartup().phase === "ready";
}

export async function forceCleanOsProxy(): Promise<string[]> {
  if (isTauri()) {
    return await tauriInvoke<string[]>("force_clean_os_proxy_cmd");
  }
  return [
    "Системный прокси macOS/Windows очищен",
    "Сетевые переменные окружения HTTP_PROXY/HTTPS_PROXY сброшены",
    "Служебные DNS-записи восстановлены",
  ];
}

export async function enableCliProtection(): Promise<CliProtectionReport> {
  if (isTauri()) {
    return await tauriInvoke<CliProtectionReport>("enable_cli_protection");
  }
  mockFlags.cliProtection = true;
  return {
    enabled: true,
    proxy_url: "http://127.0.0.1:40111",
    configured_targets: ["~/.zshrc", "~/.bashrc", "VS Code Settings", "Cursor Settings"],
    shell_command:
      'export HTTP_PROXY="http://127.0.0.1:40111" HTTPS_PROXY="http://127.0.0.1:40111" ALL_PROXY="http://127.0.0.1:40111"',
  };
}

export async function disableCliProtection(): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("disable_cli_protection");
  }
  mockFlags.cliProtection = false;
  return false;
}

export async function checkCliProtectionStatus(): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("check_cli_protection_status");
  }
  return mockFlags.cliProtection && currentMockStartup().phase === "ready";
}

export async function syncAiAgentsTimezone(timezone: string): Promise<string> {
  if (isTauri()) {
    return await tauriInvoke<string>("sync_ai_agents_timezone", { timezone });
  }
  mockState.synced_ai_timezone = timezone;
  if (!mockFlags.syncAiTz) {
    return `Зона ${timezone} сохранена, но подмена часового пояса и локали выключена.`;
  }
  return `Таймзона ${timezone} и английская локаль (en_US.UTF-8) синхронизированы для: терминала и редакторов кода (браузеры и Claude Desktop используют системный пояс ОС).`;
}

function currentMockOsTzStatus(): OsTzSyncStatus {
  return {
    synced: Boolean(mockFlags.osTzOriginal),
    current_os_tz: mockFlags.osTzCurrent,
    original_os_tz: mockFlags.osTzOriginal,
    synced_target_tz: mockFlags.osTzTarget,
    auto_restore_pending: Boolean(mockFlags.osTzOriginal),
  };
}

export async function getOsTimezoneSyncStatus(): Promise<OsTzSyncStatus> {
  if (isTauri()) {
    return await tauriInvoke<OsTzSyncStatus>("get_os_timezone_sync_status_cmd");
  }
  return currentMockOsTzStatus();
}

export async function syncOsTimezone(targetTz?: string): Promise<OsTzSyncStatus> {
  if (isTauri()) {
    return await tauriInvoke<OsTzSyncStatus>("sync_os_timezone_cmd", {
      targetTz: targetTz ?? null,
    });
  }
  const cleanTarget =
    targetTz?.trim() ||
    (mockFlags.scenario === "turkey"
      ? "Europe/Istanbul"
      : mockFlags.scenario === "ru"
      ? ""
      : "Europe/Amsterdam");
  if (!cleanTarget) {
    throw new Error(
      "Текущий выходной IP относится к заблокированной стране (RU). Подключите безопасный VPN перед синхронизацией системного часового пояса.",
    );
  }
  if (!mockFlags.osTzOriginal && mockFlags.osTzCurrent !== cleanTarget) {
    mockFlags.osTzOriginal = mockFlags.osTzCurrent;
  }
  if (mockFlags.osTzOriginal) {
    mockFlags.osTzCurrent = cleanTarget;
    mockFlags.osTzTarget = cleanTarget;
  }
  return currentMockOsTzStatus();
}

export async function restoreOsTimezone(): Promise<OsTzSyncStatus> {
  if (isTauri()) {
    return await tauriInvoke<OsTzSyncStatus>("restore_os_timezone_cmd");
  }
  if (mockFlags.osTzOriginal) {
    mockFlags.osTzCurrent = mockFlags.osTzOriginal;
  }
  mockFlags.osTzOriginal = null;
  mockFlags.osTzTarget = null;
  return currentMockOsTzStatus();
}

export async function getSplitTunnelMode(): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("get_split_tunnel_mode");
  }
  return mockFlags.splitTunnelMode;
}

export async function setSplitTunnelMode(enabled: boolean): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke<void>("set_split_tunnel_mode", { enabled });
  }
  mockFlags.splitTunnelMode = enabled;
  mockState.split_tunnel_mode = enabled;
}

export async function getKeepSystemTzOnExit(): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("get_keep_system_tz_on_exit");
  }
  return mockFlags.keepSystemTzOnExit;
}

export async function setKeepSystemTzOnExit(enabled: boolean): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("set_keep_system_tz_on_exit", { enabled });
  }
  mockFlags.keepSystemTzOnExit = enabled;
  mockState.keep_system_tz_on_exit = enabled;
  return enabled;
}

const mockCliSettings = (): CliSettings => ({
  cli_mode: mockFlags.cliMode,
  sync_ai_tz_enabled: mockFlags.syncAiTz,
  cli_protection_enabled: mockFlags.cliProtection,
  synced_ai_timezone: mockState.synced_ai_timezone ?? null,
});

/** Режим покрытия CLI и тумблер подмены часового пояса/локали (независимые). */
export async function getCliSettings(): Promise<CliSettings> {
  if (isTauri()) {
    return await tauriInvoke<CliSettings>("get_cli_settings");
  }
  return mockCliSettings();
}

/** Применяется сразу; при отказе шлюза бросает ошибку с русским текстом, режим не меняется. */
export async function setCliMode(mode: CliMode): Promise<CliSettings> {
  if (isTauri()) {
    return await tauriInvoke<CliSettings>("set_cli_mode", { mode });
  }
  mockFlags.cliMode = mode;
  mockState.cli_mode = mode;
  return mockCliSettings();
}

/** Включает или откатывает TZ/LANG/LC_TIME сразу; защиту CLI не трогает. */
export async function setSyncAiTzEnabled(enabled: boolean): Promise<CliSettings> {
  if (isTauri()) {
    return await tauriInvoke<CliSettings>("set_sync_ai_tz_enabled", { enabled });
  }
  mockFlags.syncAiTz = enabled;
  mockState.sync_ai_tz_enabled = enabled;
  if (enabled && !mockState.synced_ai_timezone) mockState.synced_ai_timezone = "Europe/Amsterdam";
  return mockCliSettings();
}

/** Открывает системные настройки сети (где указывают DNS); в браузере ничего не делает. */
export async function openOsNetworkSettings(): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("open_os_network_settings_cmd");
  }
}

export async function openOsDatetimeSettings(): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("open_os_datetime_settings_cmd");
  }
}

export async function getAutostartStatus(): Promise<AutostartStatus> {
  if (isTauri()) {
    return await tauriInvoke<AutostartStatus>("get_autostart_status");
  }
  return {
    platform: "macos",
    supported: true,
    enabled: mockFlags.autostartEnabled,
    active_in_os: mockFlags.autostartEnabled,
    target: "~/Library/LaunchAgents/io.zastava.desktop.plist",
  };
}

export async function setAutostartEnabled(enabled: boolean): Promise<AutostartStatus> {
  if (isTauri()) {
    return await tauriInvoke<AutostartStatus>("set_autostart_enabled", { enabled });
  }
  mockFlags.autostartEnabled = enabled;
  mockState.autostart_enabled = enabled;
  return getAutostartStatus();
}

export async function getCoworkGuardStatus(): Promise<CoworkGuardStatus> {
  if (isTauri()) {
    return await tauriInvoke<CoworkGuardStatus>("get_cowork_guard_status");
  }
  return {
    platform: "macos",
    supported: true,
    service_present: false,
    start_type: null,
    service_running: false,
    task_installed: mockFlags.coworkTaskInstalled,
    task_healthy: mockFlags.coworkTaskInstalled,
    needs_repair: false,
    summary:
      "Фоновые службы в порядке: на macOS приложения с автозапуском стартуют через LaunchAgents; убедитесь, что Застава запускается при входе раньше Claude и IDE.",
    detected_ai_apps: [],
  };
}

export async function installOrRepairCoworkGuard(): Promise<CoworkGuardStatus> {
  if (isTauri()) {
    return await tauriInvoke<CoworkGuardStatus>("install_or_repair_cowork_guard");
  }
  mockFlags.coworkTaskInstalled = true;
  mockState.cowork_guard_enabled = true;
  return getCoworkGuardStatus();
}
