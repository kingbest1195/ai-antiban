import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { guides as copy, subscription } from "../../shared/copy/ru";
import { GuidesScreen } from "./GuidesScreen";
import { BLACKLISTED_PROVIDERS, VIRTUAL_CARD_PROVIDERS, VPS_PROVIDERS } from "./providers";

describe("PaymentGuide inside GuidesScreen", () => {
  it("рендерит проверку карты с переданной страной шлюза и не открывает US-штаты в AddressCard до проверки карты", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "02-safe-payment-cards",
        currentIp: "185.212.102.40",
        currentCountry: "DE",
      }),
    );

    expect(html).toContain(subscription.card.title);
    expect(html).toContain(subscription.card.gateway("DE"));
    expect(html).toContain(subscription.address.nonUsTitle);
    expect(html).toContain(subscription.address.nonUsUnknownText);
    expect(html).not.toContain("subs-state-tab-DE");
    expect(html).not.toContain("19801");
  });

  it("не подставляет молча NL, если currentCountry не определена (-- или undefined)", () => {
    const dashHtml = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "02-safe-payment-cards",
        currentCountry: "--",
      }),
    );
    expect(dashHtml).toContain("Маршрут VPN не выбран");
    expect(dashHtml).not.toContain(subscription.card.gateway("NL"));

    const undefHtml = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "02-safe-payment-cards",
      }),
    );
    expect(undefHtml).toContain("Маршрут VPN не выбран");
    expect(undefHtml).not.toContain(subscription.card.gateway("NL"));
  });

  it("показывает защиту от серых карт и посредников, 96ч/72ч инварианты и не обещает 100% гарантии", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "02-safe-payment-cards",
        currentCountry: "NL",
      }),
    );

    expect(html).toContain("Playerok");
    expect(html).toContain("FunPay");
    expect(html).toContain("Apple Pay");
    expect(html).toContain("US Apple ID");
    expect(html).toContain("подарочной картой");
    expect(html).toMatch(/96\s*(?:ч|час)/);
    expect(html).toMatch(/72\s*(?:ч|час)/);
    expect(html).not.toContain("равен нулю");
    expect(html).not.toContain("на 100%");
    expect(html).not.toContain("любая виртуальная карта подходит");
  });

  it("выстраивает 2 секции (через App Store и картой на сайте), 3 шага Т-Банк + СберБанк, и не содержит внутренней кухни", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "02-safe-payment-cards",
        currentCountry: "US",
      }),
    );

    // Две ясные секции вместо Уровень 1 / Уровень 2
    const appStoreIdx = html.indexOf("Самый надёжный способ: через App Store");
    const webCardIdx = html.indexOf("Оплата картой на сайте");
    const tbankIdx = html.indexOf("Т-Банк");
    const kupikodIdx = html.indexOf("Kupikod");
    const wanttopayIdx = html.indexOf("WantToPay");
    const platipomiruIdx = html.indexOf("Плати по миру");

    expect(appStoreIdx).toBeGreaterThan(-1);
    expect(webCardIdx).toBeGreaterThan(appStoreIdx);
    expect(tbankIdx).toBeGreaterThan(appStoreIdx);
    expect(kupikodIdx).toBeGreaterThan(tbankIdx);
    expect(wanttopayIdx).toBeGreaterThan(webCardIdx);
    expect(platipomiruIdx).toBeGreaterThan(wanttopayIdx);

    // 3 коротких нумерованных шага Т-Банк + вариант СберБанк Онлайн
    const tbank = VIRTUAL_CARD_PROVIDERS.find((p) => p.id === "tbank");
    expect(tbank?.steps).toHaveLength(3);
    expect(html).toContain("СберБанк Онлайн");
    expect(html).toContain("Apple Card");
    expect(html).toContain("+60%");

    // Компактные нюансы Kupikod
    expect(html).toContain("Важные нюансы");
    expect(html).toContain("25–34%");
    expect(html).toContain("Kupicoins");
    expect(html).toContain("2 часов");
    expect(html).toContain("support@kupikod.com");
    expect(html).toContain("видеозапись экрана");
    expect(html).toContain("Пропуск Kupikod");
    expect(html).toContain("299");

    // WantToPay и Плати по миру + сохранение реферальных URL только в данных для перехода по кнопке
    expect(html).toContain("Easy");
    expect(html).toContain("Smart");
    expect(html).toContain("предоплаченная");
    expect(html).toContain("$0.25–$1.00");
    expect(html).toContain("Для подписок");

    const wanttopay = VIRTUAL_CARD_PROVIDERS.find((p) => p.id === "wanttopay");
    const platipomiru = VIRTUAL_CARD_PROVIDERS.find((p) => p.id === "platipomiru");
    const kupikod = VIRTUAL_CARD_PROVIDERS.find((p) => p.id === "kupikod");
    expect(wanttopay?.url).toBe("https://telegram.me/WantToPayBot?start=w17851188--ERIEX");
    expect(platipomiru?.url).toBe("https://platipomiru.com/?code=UXCAF1Z9");
    expect(kupikod?.url).toBe("https://kupikod.com/");

    // Ноль внутренней кухни и запрещённого жаргона в гайдах и данных провайдеров
    expect(VIRTUAL_CARD_PROVIDERS.some((p) => p.id === "epn")).toBe(false);
    expect("refStatus" in (wanttopay ?? {})).toBe(false);
    expect("refStatusLabels" in copy.payment).toBe(false);

    const guidesSectionHtml = html.slice(appStoreIdx);
    const providersSerialized = JSON.stringify(VIRTUAL_CARD_PROVIDERS) + JSON.stringify(BLACKLISTED_PROVIDERS);
    const guidesPaymentSerialized = JSON.stringify(copy.payment);
    for (const forbidden of [
      "Bitrefill",
      "EasyPay",
      "OpenRouter",
      "ProxyAPI.ru",
      "BotHub",
      "Партнёрская ссылка",
      "Непартнёрская инструкция",
      "Без партнёрской ссылки",
      "Уровень 1",
      "Уровень 2",
      "Apple IAP",
      "clientsupport@maxipay.global",
      "связующее звено",
      "централизованный агент",
      "US Business",
      "446614",
      "Anthropic API",
      "Persona KYC",
      "Sumsub",
      "AML",
      "493724",
      "рекламных пулов",
      "ToS",
      "биллинг",
      "refStatus",
      "zs-banner--warn",
    ]) {
      expect(guidesSectionHtml, `Секция гайдов не должна содержать «${forbidden}»`).not.toContain(forbidden);
      expect(providersSerialized, `providers.ts не должен содержать «${forbidden}»`).not.toContain(forbidden);
      expect(guidesPaymentSerialized, `guides.payment не должен содержать «${forbidden}»`).not.toContain(forbidden);
    }
  });

  it("рендерит компактный блок «Чем лучше не платить» (BLACKLISTED_PROVIDERS) и соблюдает дизайн-хартию", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "02-safe-payment-cards",
        currentCountry: "NL",
      }),
    );

    expect(html).toContain("Чем лучше не платить");
    expect(BLACKLISTED_PROVIDERS.length).toBeGreaterThanOrEqual(8);
    for (const item of [
      "Antarctic Wallet",
      "Altyn Wallet",
      "Wayment",
      "e.pn",
      "RedotPay",
      "PST.net",
      "FlexCard",
      "Plati.market",
      "Avito",
      "GGSel",
      "Ozon",
      "WB",
      "случайные боты в Telegram",
    ]) {
      expect(html).toContain(item);
    }

    // Не более одной primary CTA на экране (внутри CardCheck)
    const primaryCount = (html.match(/zs-btn--primary/g) ?? []).length;
    expect(primaryCount).toBeLessThanOrEqual(1);

    // Ноль восклицательных знаков в текстовом содержимом PaymentGuide
    const textOnly = html.replace(/<[^>]+>/g, " ");
    expect(textOnly).not.toContain("!");
  });
});

describe("VpsGuide inside GuidesScreen", () => {
  it("использует Vultr вместо is*hosting, предупреждает о Cmd+Q и не даёт ложных абсолютных обещаний", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "01-personal-vpn-amnezia",
        currentIp: "185.212.102.40",
        currentCountry: "NL",
      }),
    );

    expect(html).toContain("Vultr");
    expect(html).not.toContain("is*hosting");
    expect(html).not.toContain("ishosting");
    expect(html).not.toContain("защищает от бана на 100%");
    expect(html).not.toContain("идеальный ASN");
    expect(html).toContain("Cmd+Q");
    expect(html).toContain("4 часа");

    const vultr = VPS_PROVIDERS.find((p) => p.id === "vultr");
    expect(vultr?.url).toBe("https://www.vultr.com/?ref=9936768");
    expect(VPS_PROVIDERS.some((p) => p.id === "ishosting")).toBe(false);
    for (const p of VPS_PROVIDERS) {
      expect(p.badge).not.toBe(p.badge.toUpperCase());
    }
  });
});
