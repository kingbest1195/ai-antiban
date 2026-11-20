import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { listCleanProfiles } from "../../utils/api/cleanRoom";
import { setMockScenario } from "../../utils/api/mocks/state";
import {
  BannedBranch,
  PaymentBranch,
  PersonaBranch,
  SmsBranch,
  SosScreen,
  executeBannedCleanRoomJump,
} from "./index";

describe("sos feature: 4-branch decision tree & Safety Charter", () => {
  beforeEach(() => {
    setMockScenario("clean");
  });

  it("Branch 1A (RU-only): строгий красный STOP + 3-шаговый Протокол выживания (Бункер + отмена + BYOK/OpenRouter)", () => {
    const html = renderToStaticMarkup(
      createElement(PersonaBranch, { initialChoice: "ru_only", onToast: vi.fn() }),
    );
    expect(html).toContain("STOP — НЕ ЗАГРУЖАЙТЕ ДОКУМЕНТЫ РФ/РБ И НЕ ИСПОЛЬЗУЙТЕ ПОДДЕЛКИ");
    expect(html).toContain("~60 секунд");
    expect(html).toContain("Создать экстренный бэкап сейчас");
    expect(html).toContain("reportaproblem.apple.com");
    expect(html).toContain("OpenRouter");
    expect(html).toContain("Скопировать RESTORE_PROMPT.md");
  });

  it("Branch 1B (ВНЖ / иностранный паспорт): 4-пунктовый Pre-Flight чек-лист согласования реальных данных", () => {
    const html = renderToStaticMarkup(
      createElement(PersonaBranch, { initialChoice: "foreign_legal", onToast: vi.fn() }),
    );
    expect(html).toContain("Pre-Flight чек-лист для легального ВНЖ / иностранного паспорта");
    expect(html).toContain("1. Страна выходного IP Заставы строго совпадает со страной документа");
    expect(html).toContain("2. Часовой пояс ОС и браузера совпадает со страной документа");
    expect(html).toContain("3. Имя и фамилия в биллинге карты совпадают с документом");
    expect(html).toContain("4. Реальная камера, ровный свет, без OBS Virtual Camera");
  });

  it("Branch 2 (SMS): предупреждение о VoIP-пулах и рекомендации по физической SIM/eSIM", () => {
    const html = renderToStaticMarkup(createElement(SmsBranch));
    expect(html).toContain("Не приходит SMS или номер отклонён");
    expect(html).toContain("VoIP");
    expect(html).toContain("физическую SIM-карту или легальную eSIM");
  });

  it("Branch 3 (Оплата / 3DS): содержит CardCheck, AddressCard и предупреждение о двойном VPN", () => {
    const html = renderToStaticMarkup(
      createElement(PaymentBranch, { currentCountry: "US", onToast: vi.fn() }),
    );
    expect(html).toContain("Ошибка оплаты / 3DS / Your card was declined");
    expect(html).toContain("двойной туннель ломает 3DS");
    expect(html).toContain("DE");
  });

  it("Branch 4 (Бан): BannedBranch и executeBannedCleanRoomJump помечают IP tainted и прыгают в Чистую комнату (Шаг 1)", async () => {
    const html = renderToStaticMarkup(
      createElement(BannedBranch, { onToast: vi.fn(), onNavigateToCleanRoom: vi.fn() }),
    );
    expect(html).toContain("Account disabled / Organization suspended");
    expect(html).toContain("Перейти в Чистую комнату (Шаг 1)");

    const onNavigate = vi.fn();
    const onToast = vi.fn();
    await executeBannedCleanRoomJump(onNavigate, onToast);

    expect(onNavigate).toHaveBeenCalledWith(1);
    expect(onToast).toHaveBeenCalledTimes(1);

    const state = await listCleanProfiles();
    expect(Object.keys(state.tainted_ips).length).toBeGreaterThan(0);
  });

  it("SosScreen рендерит HintCard sos_intro и все 4 вкладки ситуаций", () => {
    const html = renderToStaticMarkup(
      createElement(SosScreen, {
        dismissedHints: [],
        onDismissHint: vi.fn(),
        onNavigateToCleanRoom: vi.fn(),
        onToast: vi.fn(),
      }),
    );
    expect(html).toContain("Быстрое дерево решений без воды");
    expect(html).toContain("Persona (KYC)");
    expect(html).toContain("SMS на номер");
    expect(html).toContain("Ошибка оплаты");
    expect(html).toContain("Бан аккаунта");
  });
});
