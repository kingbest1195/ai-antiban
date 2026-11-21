import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { setMockScenario } from "../../utils/api/mocks/state";
import {
  convertWebExport,
  generateBunkerRestorePrompt,
  getBunkerStatus,
  runBunkerBackupNow,
  updateBunkerSettings,
} from "../../utils/api/bunker";
import { getPersonaRiskReport, updatePersonaSelfCheck } from "../../utils/api/sos";
import {
  BunkerCard,
  PersonaRiskCard,
  WebExportHelper,
  formatBytesCompact,
  personaLevelBadgeTone,
  personaLevelLabel,
} from "./index";

describe("bunker feature: BunkerCard, WebExportHelper & PersonaRiskCard", () => {
  beforeEach(() => {
    setMockScenario("clean");
  });

  it("BunkerCard рендерит заголовок, скелетон загрузки и контролы без ошибок", () => {
    const html = renderToStaticMarkup(createElement(BunkerCard, { onToast: vi.fn() }));
    expect(html).toContain("Бесплатный локальный Бункер");
    expect(html).toContain("Автоматические локальные копии");
  });

  it("API Бункера: getBunkerStatus, updateBunkerSettings, runBunkerBackupNow, generateBunkerRestorePrompt", async () => {
    const status = await getBunkerStatus();
    expect(status.bunker_dir).toBeTruthy();

    const updated = await updateBunkerSettings({
      auto_backup_enabled: false,
      interval_hours: 12,
      retention_count: 14,
    });
    expect(updated.auto_backup_enabled).toBe(false);
    expect(updated.interval_hours).toBe(12);
    expect(updated.retention_count).toBe(14);

    const backupRes = await runBunkerBackupNow();
    expect(backupRes.snapshot.files_count).toBeGreaterThan(0);

    const prompt = await generateBunkerRestorePrompt();
    expect(prompt.length).toBeGreaterThan(10);
  });

  it("WebExportHelper рендерит EmptyState с инструкциями для Claude.ai / ChatGPT и формой пути", () => {
    const html = renderToStaticMarkup(createElement(WebExportHelper, { onToast: vi.fn() }));
    expect(html).toContain("zs-empty");
    expect(html).toContain("https://claude.ai/settings/data-privacy");
    expect(html).toContain("https://chatgpt.com/#settings/DataControls");
    expect(html).toContain("Конвертировать локально");
  });

  it("convertWebExport локально конвертирует путь и возвращает Markdown + restore_prompt_preview", async () => {
    const res = await convertWebExport("~/Downloads/claude-export.zip");
    expect(res.detected_provider).toBe("claude");
    expect(res.markdown_files.length).toBeGreaterThan(0);
    expect(res.restore_prompt_preview).toBeTruthy();
  });

  it("PersonaRiskCard и уровни риска low / medium / high + updatePersonaSelfCheck", async () => {
    expect(personaLevelLabel("low")).toBe("Низкий");
    expect(personaLevelLabel("medium")).toBe("Средний");
    expect(personaLevelLabel("high")).toBe("Высокий");
    expect(personaLevelBadgeTone("low")).toBe("ok");
    expect(personaLevelBadgeTone("medium")).toBe("warn");
    expect(personaLevelBadgeTone("high")).toBe("danger");

    const baseReport = await updatePersonaSelfCheck({
      bought_or_grey_account: false,
      virtual_sms_used: false,
      reseller_payment_used: false,
      multi_account_same_browser: false,
    });
    expect(baseReport.score).toBeLessThan(55);

    const highReport = await updatePersonaSelfCheck({
      bought_or_grey_account: true,
      reseller_payment_used: true,
    });
    expect(highReport.score).toBeGreaterThanOrEqual(55);
    expect(highReport.level).toBe("high");

    const html = renderToStaticMarkup(
      createElement(PersonaRiskCard, {
        onToast: vi.fn(),
        onNavigateToCleanRoom: vi.fn(),
      }),
    );
    expect(html).toContain("Риск KYC и блокировки Claude");
    expect(formatBytesCompact(2_097_152)).toBe("2.0 МБ");
    const fresh = await getPersonaRiskReport();
    expect(fresh.self_check.bought_or_grey_account).toBe(true);
  });
});
