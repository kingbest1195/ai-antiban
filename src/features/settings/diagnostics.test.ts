import { describe, expect, it } from "vitest";
import { settings as copy } from "../../shared/copy/ru";
import { exportDiagnosticBundle, pauseUntilNetworkChange, previewProtectionChanges } from "../../utils/api";

describe("Диагностика, предпросмотр изменений и пауза до смены сети (API/мок + строки)", () => {
  it("exportDiagnosticBundle возвращает очищенный JSON без секретов", async () => {
    const json = await exportDiagnosticBundle();
    const parsed = JSON.parse(json);
    expect(parsed.app_version).toBeTruthy();
    expect(parsed).toHaveProperty("sysproxy_enabled");
    expect(parsed).toHaveProperty("provider_routes");
    expect(json).not.toContain("vless://");
  });

  it("previewProtectionChanges перечисляет слои и помечает их обратимыми", async () => {
    const items = await previewProtectionChanges();
    expect(items.length).toBeGreaterThanOrEqual(4);
    expect(items.every((i) => i.reversible === true)).toBe(true);
    expect(items.some((i) => i.category === "system_pac")).toBe(true);
    expect(items.some((i) => i.category === "browser_policy")).toBe(true);
  });

  it("pauseUntilNetworkChange возвращает режим until_network_change", async () => {
    const status = await pauseUntilNetworkChange("Тест причины");
    expect(status.paused).toBe(true);
    expect(status.mode).toBe("until_network_change");
    expect(status.gate_reason).toBe("Тест причины");
  });

  it("строки диагностики в настройках соответствуют спецификации", () => {
    expect(copy.diagnostics.exportAction).toBe("Скопировать отчёт диагностики (без ключей и IP)");
    expect(copy.diagnostics.exportToast).toBe("Диагностический отчёт скопирован (секреты и IP скрыты)");
    expect(copy.diagnostics.previewTitle).toBe("Что Застава настраивает в системе");
    expect(copy.diagnostics.reversibleBadge).toBe("Обратимо при выходе");
  });
});
