import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { subscription } from "../../shared/copy/ru";
import { listCleanProfiles } from "../../utils/api/cleanRoom";
import { cleanAntigravityAuthCache } from "../../utils/api/sos";
import { setMockScenario } from "../../utils/api/mocks/state";
import {
  BannedBranch,
  Gemini403Card,
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

  it("Branch 1A (RU-only): спокойное предупреждение + 3-шаговый Протокол выживания (Бункер + отмена + BYOK/OpenRouter)", () => {
    const html = renderToStaticMarkup(
      createElement(PersonaBranch, { initialChoice: "ru_only", onToast: vi.fn() }),
    );
    expect(html).toContain("Не загружайте документы РФ/РБ и не используйте подделки");
    expect(html).not.toContain("STOP — НЕ ЗАГРУЖАЙТЕ");
    expect(html).toContain("~60 секунд");
    expect(html).toContain("Создать копию сейчас");
    expect(html).toContain("reportaproblem.apple.com");
    expect(html).toContain("OpenRouter");
    expect(html).toContain("Скопировать промпт переноса");
    expect(html).toContain("zs-seg");
  });

  it("Branch 1B (ВНЖ / иностранный паспорт): 4-пунктовый Pre-Flight чек-лист согласования реальных данных", () => {
    const html = renderToStaticMarkup(
      createElement(PersonaBranch, { initialChoice: "foreign_legal", onToast: vi.fn() }),
    );
    expect(html).toContain("Чек-лист перед проверкой для легального ВНЖ / иностранного паспорта");
    expect(html).toContain("1. Страна выходного IP Заставы строго совпадает со страной документа");
    expect(html).toContain("2. Часовой пояс системы и браузера совпадает со страной документа");
    expect(html).toContain("3. Имя и фамилия в адресе оплаты карты совпадают с документом");
    expect(html).toContain("4. Реальная камера, ровный свет, без OBS Virtual Camera");
  });

  it("Branch 2 (SMS): предупреждение о VoIP-пулах и рекомендации по физической SIM/eSIM", () => {
    const html = renderToStaticMarkup(createElement(SmsBranch));
    expect(html).toContain("Не приходит SMS или номер отклонён");
    expect(html).toContain("интернет-телефония");
    expect(html).toContain("физическую SIM-карту или легальную eSIM");
  });

  it("Branch 3 (Оплата / 3DS): содержит CardCheck, AddressCard (без US-штатов по умолчанию) и не подставляет NL при --", () => {
    const html = renderToStaticMarkup(
      createElement(PaymentBranch, { currentCountry: "US", onToast: vi.fn() }),
    );
    expect(html).toContain("Ошибка оплаты / 3DS / Your card was declined");
    expect(html).toContain("двойной туннель ломает 3DS");
    expect(html).toContain(subscription.address.nonUsTitle);
    expect(html).toContain(subscription.address.nonUsUnknownText);
    expect(html).not.toContain("subs-state-tab-DE");
    expect(html).not.toContain("19801");

    const unknownCountryHtml = renderToStaticMarkup(
      createElement(PaymentBranch, { currentCountry: "--", onToast: vi.fn() }),
    );
    expect(unknownCountryHtml).toContain("Маршрут VPN не выбран");
    expect(unknownCountryHtml).not.toContain("Нидерланды");
  });

  it("Branch 4 (Бан): BannedBranch и executeBannedCleanRoomJump помечают IP tainted и прыгают в Чистую комнату (Шаг 1)", async () => {
    const html = renderToStaticMarkup(
      createElement(BannedBranch, { onToast: vi.fn(), onNavigateToCleanRoom: vi.fn() }),
    );
    expect(html).toContain("Account disabled / Organization suspended");
    expect(html).toContain("Открыть Чистую комнату");

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
    expect(html).toContain("Выберите вашу ситуацию ниже");
    expect(html).toContain("Проверка личности");
    expect(html).toContain("SMS на номер");
    expect(html).toContain("Ошибка оплаты");
    expect(html).toContain("Бан аккаунта");
    expect(html).toContain("Ошибка 403 в Antigravity / Gemini");
    expect(html).toContain("myaccount.google.com/connections");
    expect(html).toContain("OpenCode");
  });

  it("Gemini403Card и BannedBranch: 1-клик сброс кеша входа 403 и перенос памяти", async () => {
    const cleanRes = await cleanAntigravityAuthCache();
    expect(cleanRes.success).toBe(true);
    expect(cleanRes.provider).toBe("gemini");

    const cardHtml = renderToStaticMarkup(createElement(Gemini403Card, { onToast: vi.fn() }));
    expect(cardHtml).toContain("One-Time Appeal Policy");
    expect(cardHtml).toContain("Сбросить кеш входа (1 клик)");
    expect(cardHtml).toContain("GEMINI.md");

    const bannedHtml = renderToStaticMarkup(
      createElement(BannedBranch, { onToast: vi.fn(), onNavigateToCleanRoom: vi.fn() }),
    );
    expect(bannedHtml).toContain("Перенести память и правила в другой ИИ");
    expect(bannedHtml).toContain("Скопировать промпт и выгрузить");
  });
});
