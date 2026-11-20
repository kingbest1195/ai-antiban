import type { ProtectionChangePreviewItem } from "../../types";
import { isTauri, tauriInvoke } from "./client";
import { mockFlags } from "./mocks/state";

export async function getErrorDiagnostics(
  errorTitle?: string,
  errorMessage?: string,
): Promise<string> {
  if (isTauri()) {
    return await tauriInvoke<string>("get_error_diagnostics", {
      errorTitle: errorTitle ?? null,
      errorMessage: errorMessage ?? null,
    });
  }
  const lines = [
    `Zastava WebPreview (${typeof navigator !== "undefined" ? navigator.userAgent : "unknown"})`,
    errorTitle ? `Error title: ${errorTitle}` : null,
    errorMessage ? `Error text: ${errorMessage}` : null,
    `Time: ${new Date().toISOString()}`,
  ].filter(Boolean);
  return lines.join("\n");
}

/** Копирует текст в системный буфер обмена через нативную команду Tauri (без потери user-gesture в WebView). */
export async function copyTextToClipboard(text: string): Promise<boolean> {
  if (!isTauri()) return false;
  try {
    await tauriInvoke<void>("copy_text_to_clipboard", { text });
    return true;
  } catch {
    return false;
  }
}

/** Экспортирует очищенный JSON-отчёт диагностики без прокси-ключей, токенов и IP-адресов. */
export async function exportDiagnosticBundle(): Promise<string> {
  if (isTauri()) {
    return await tauriInvoke<string>("export_diagnostic_bundle_cmd");
  }
  return JSON.stringify(
    {
      app_version: "3.0.0",
      os: "macos",
      arch: "aarch64",
      sysproxy_enabled: mockFlags.sysproxyActive,
      cli_protection_enabled: mockFlags.cliProtection,
      cli_mode: mockFlags.cliMode,
      split_tunnel_mode: mockFlags.splitTunnelMode,
      sync_ai_tz_enabled: mockFlags.syncAiTz,
      provider_routes: [],
      audits: {},
      note: "mock diagnostic bundle (IPs and credentials redacted)",
    },
    null,
    2,
  );
}

/** Возвращает список системных настроек и файлов, которыми управляет Застава. */
export async function previewProtectionChanges(): Promise<ProtectionChangePreviewItem[]> {
  if (isTauri()) {
    return await tauriInvoke<ProtectionChangePreviewItem[]>("preview_protection_changes_cmd");
  }
  return [
    {
      category: "system_pac",
      target: "Системный прокси ОС (PAC)",
      action: "Автонастройка прокси на активных сетевых интерфейсах",
      description: "Направляет только домены ИИ на локальный шлюз 127.0.0.1.",
      reversible: true,
    },
    {
      category: "browser_policy",
      target: "Политики браузеров (Chrome / Edge / Brave / Firefox)",
      action: "ProxyMode, ProxyPacUrl, QuicAllowed, DnsOverHttpsMode",
      description: "Обеспечивает работу маршрутов даже поверх TUN VPN.",
      reversible: true,
    },
    {
      category: "shell_rc",
      target: "~/.zshrc, ~/.bash_profile",
      action: "Блок # >>> zastava ... # <<< zastava",
      description: "Настройка переменных прокси для ИИ-инструментов и часового пояса.",
      reversible: true,
    },
    {
      category: "cli_settings",
      target: "~/.claude/settings.json, ~/.gemini/settings.json",
      action: "Параметры прокси и TZ",
      description: "Безопасное окружение только для CLI-клиентов ИИ.",
      reversible: true,
    },
    {
      category: "ide_settings",
      target: "VS Code / Cursor / Windsurf / Antigravity",
      action: "Локальная конфигурация прокси для расширений ИИ",
      description: "Оставляет npm, git и brew напрямую.",
      reversible: true,
    },
  ];
}
