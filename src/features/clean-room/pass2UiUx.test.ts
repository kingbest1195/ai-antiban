import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { PreFlightAuditCard, buildRadarLayers } from "./PreFlightAuditCard";
import { SandboxProfilesCard } from "./SandboxProfilesCard";
import { CleanRoomRadarAnim } from "../mascot";
import { BackupScreen } from "../backup/BackupScreen";
import { BunkerCard, formatBytesCompact } from "../bunker";
import { SosScreen } from "../sos/SosScreen";
import { ConnectSalesCards } from "../connect/ConnectSalesCards";
import { backup as backupCopy } from "../../shared/copy/ru/backup";
import { bunkerCopy } from "../../shared/copy/ru/bunker";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";
import { connect as connectCopy } from "../../shared/copy/ru/connect";
import { clearBunkerSnapshots, getBunkerStatus } from "../../utils/api/bunker";
import type { CleanRoomAuditReport, CleanRoomProfile, DetectedBrowser } from "../../types";

const AVAILABLE_BROWSERS: DetectedBrowser[] = [
  { engine: "chrome", display_name: "Google Chrome", executable_path: "/usr/bin/chrome", available: true },
];

function makeAudit(over: Partial<CleanRoomAuditReport> = {}): CleanRoomAuditReport {
  return {
    checked_at: 1_760_000_000,
    exit_ip: "185.212.102.40",
    exit_country: "SE",
    exit_timezone: "Europe/Stockholm",
    ip_is_tainted: false,
    os_tz_matches_exit: false,
    requires_os_sync: false,
    findings: [],
    critical_count: 0,
    warning_count: 0,
    ready_to_launch: true,
    ...over,
  };
}

function makeProfile(over: Partial<CleanRoomProfile> = {}): CleanRoomProfile {
  return {
    id: "cr-1",
    label: "Gemini Work",
    provider: "gemini",
    browser_engine: "chrome",
    bound_route_id: null,
    last_exit_ip: null,
    last_exit_country: null,
    status: "active",
    created_at: 1_760_000_000,
    last_opened_at: null,
    warmup_started_at: null,
    launchpad_step: 1,
    completed_checklist: [],
    ...over,
  };
}

describe("Pass 2 UI/UX & Anti-Slop regressions", () => {
  it("Point #3: macOS TZ показывает «Авто в песочнице», Windows mismatch ставит warn на радар, и все 4 пилюли имеют tip", () => {
    const macAudit = makeAudit({ os_tz_matches_exit: false, requires_os_sync: false });
    const macLayers = buildRadarLayers(macAudit, false);
    const macTzLayer = macLayers.find((l) => l.id === "os_tz");
    expect(macTzLayer?.status).toBe("pending");
    expect(macTzLayer?.tip).toContain("На macOS Застава сама задаёт нужный часовой пояс");

    const macHtml = renderToStaticMarkup(createElement(PreFlightAuditCard, { audit: macAudit }));
    expect(macHtml).toContain(copy.audit.meta.tzAutoSandbox);
    expect(macHtml).not.toContain(copy.audit.meta.tzMismatch);

    const winAudit = makeAudit({ os_tz_matches_exit: false, requires_os_sync: true });
    const winLayers = buildRadarLayers(winAudit, false);
    expect(winLayers.find((l) => l.id === "os_tz")?.status).toBe("warn");
    const winHtml = renderToStaticMarkup(createElement(PreFlightAuditCard, { audit: winAudit }));
    expect(winHtml).toContain(copy.audit.meta.tzMismatch);

    const radarHtml = renderToStaticMarkup(createElement(CleanRoomRadarAnim, { layers: macLayers }));
    expect(radarHtml).toContain("zs-tip");
  });

  it("Point #3: при ready_to_launch=true неблокирующие находки свёрнуты в ExpandRow «Детали проверки (N)»", () => {
    const readyAudit = makeAudit({
      ready_to_launch: true,
      critical_count: 0,
      findings: [
        {
          id: "cursor_ide_traces",
          category: "desktop_traces",
          title: "Найдены следы Cursor IDE",
          detail: "Обнаружен профиль редактора.",
          severity: "warning",
          path_hint: "~/Library/Application Support/Cursor",
          fix_action: null,
        },
      ],
    });
    const html = renderToStaticMarkup(createElement(PreFlightAuditCard, { audit: readyAudit }));
    expect(html).toContain(copy.audit.detailsTitle(1));
    expect(html).not.toContain("~/Library/Application Support/Cursor");
  });

  it("Point #4: SandboxProfilesCard использует «Сообщить о бане», убирает raw «·» и показывает статус «После бана»", () => {
    const html = renderToStaticMarkup(
      createElement(SandboxProfilesCard, {
        profiles: [makeProfile({ status: "tainted" })],
        activeProfileId: "cr-1",
        readyToLaunch: true,
        initialBrowsers: AVAILABLE_BROWSERS,
        onSelectProfile: vi.fn(),
      }),
    );
    expect(html).toContain(copy.sandbox.status.tainted);
    expect(html).toContain(`${copy.sandbox.profileCard.routeLabel}:`);
    expect(html).not.toContain("<span>·</span>");
    expect(html).not.toContain("Отметить профиль");
  });

  it("Point #5 & #6: BackupScreen без дубля ArchiveSection, SosScreen(embedded) без второго HintCard, без RESTORE_PROMPT.md", async () => {
    const statusBefore = await getBunkerStatus();
    expect(statusBefore.settings.max_total_mb).toBe(500);
    const cleared = await clearBunkerSnapshots();
    expect(cleared.snapshots_count).toBeLessThanOrEqual(statusBefore.snapshots_count);

    expect(bunkerCopy.actions.copyPrompt).toBe("Скопировать промпт переноса");
    expect(bunkerCopy.actions.copyPrompt).not.toContain("RESTORE_PROMPT");

    const fakeBackup = {
      claudeSummary: null,
      loadingClaudeSummary: false,
      claudeExporting: false,
      claudeExportResult: null,
      copiedPrompt: false,
      cleaningClaude: false,
      cleaningGpt: false,
      loadClaudeSummary: vi.fn(),
      handleExportClaude: vi.fn(),
      handleCopyRestorePrompt: vi.fn(),
      handleCleanSpecificClientCache: vi.fn(),
    };
    const backupHtml = renderToStaticMarkup(
      createElement(BackupScreen, {
        backup: fakeBackup,
        currentIp: "185.212.102.40",
        currentCountry: "DE",
        onProfileSwitched: vi.fn(),
        onToast: vi.fn(),
      }),
    );
    expect(backupHtml).not.toContain("Резервная копия данных");

    const sosEmbeddedHtml = renderToStaticMarkup(
      createElement(SosScreen, { embedded: true, onDismissHint: vi.fn() }),
    );
    expect(sosEmbeddedHtml).not.toContain("Выберите вашу ситуацию ниже");
  });

  it("Point #7: ConnectSalesCards без zs-sale--key и с подсказкой для socks5://host:port:user:pass", () => {
    const html = renderToStaticMarkup(
      createElement(ConnectSalesCards, {
        routes: [],
        hasRoutes: false,
        isLegacyConfigured: false,
        inputKey: "",
        addScope: "all",
        error: null,
        connecting: false,
        onInputKeyChange: vi.fn(),
        onAddScopeChange: vi.fn(),
        onAddKey: vi.fn(),
        onOpenGuide: vi.fn(),
      }),
    );
    expect(html).not.toContain("zs-sale--key");
    expect(html).toContain(connectCopy.key.caption);
    expect(connectCopy.key.caption).toContain("socks5://host:port:user:pass");
  });

  it("Final polish: ГБ-форматирование >= 1024 МБ, «Очистить локальные данные», «Риск проверки личности и блокировки Claude» и stacked prompt-box", () => {
    expect(formatBytesCompact(2189 * 1024 * 1024)).toBe("2.1 ГБ");
    expect(formatBytesCompact(1024 * 1024 * 1024)).toBe("1.0 ГБ");

    expect(backupCopy.cache.section).toBe("Локальные данные");
    expect(backupCopy.cache.title).toBe("Следы устройства и локальные данные");
    expect(backupCopy.cache.clean).toBe("Очистить локальные данные");
    expect(backupCopy.profiles.section).toBe("Профили Claude Desktop");

    expect(bunkerCopy.personaRisk.section).toBe("Риск проверки личности и блокировки Claude");
    expect(bunkerCopy.personaRisk.title).toBe("Риск проверки личности и блокировки Claude");

    const fakeBackup = {
      claudeSummary: null,
      loadingClaudeSummary: false,
      claudeExporting: false,
      claudeExportResult: null,
      copiedPrompt: false,
      cleaningClaude: false,
      cleaningGpt: false,
      loadClaudeSummary: vi.fn(),
      handleExportClaude: vi.fn(),
      handleCopyRestorePrompt: vi.fn(),
      handleCleanSpecificClientCache: vi.fn(),
    };

    const backupHtml = renderToStaticMarkup(
      createElement(BackupScreen, {
        backup: fakeBackup,
        currentIp: "185.212.102.40",
        currentCountry: "DE",
        onProfileSwitched: vi.fn(),
        onToast: vi.fn(),
      }),
    );
    expect(backupHtml).toContain("Очистить локальные данные");
    expect(backupHtml).toContain("Следы устройства и локальные данные");
    expect(backupHtml).toContain("Риск проверки личности и блокировки Claude");
    expect(backupHtml).not.toContain("Профили Claude Desktop и безопасный выход");
    expect(backupHtml).not.toContain("Сбросить кэш");

    const bunkerHtml = renderToStaticMarkup(
      createElement(BunkerCard, {
        backup: fakeBackup,
        onToast: vi.fn(),
        initialStatus: {
          bunker_dir: "/tmp/bunker",
          snapshots_count: 2,
          total_snapshots_bytes: 2189 * 1024 * 1024,
          latest_snapshot: null,
          has_any_local_data: true,
          sources: [],
          settings: {
            auto_backup_enabled: true,
            interval_hours: 24,
            retention_count: 3,
            max_total_mb: 2048,
            last_backup_at: 1_763_729_400,
            last_backup_size_bytes: 2189 * 1024 * 1024,
          },
        },
      }),
    );
    expect(bunkerHtml).toContain("2.1 ГБ");
    expect(bunkerHtml).toContain("На диске · до 2 ГБ");
    expect(bunkerHtml).toContain("Сохранить ZIP");
    expect(bunkerHtml).toContain("Очистить старые");
    expect(bunkerHtml).toContain("zs-bunker__prompt-box");
    expect(bunkerHtml).toContain("Промпт переноса контекста");
    expect(bunkerHtml).toContain("Скопировать промпт");
    expect(bunkerHtml).not.toContain("Сохранить ZIP на рабочий стол");
    expect(bunkerHtml).not.toContain("2189.0 МБ");
    expect(bunkerHtml).not.toContain("Автоматические локальные снапшоты");
  });
});
