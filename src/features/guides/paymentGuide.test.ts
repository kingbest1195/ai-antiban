import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { subscription } from "../../shared/copy/ru";
import { GuidesScreen } from "./GuidesScreen";
import { VPS_PROVIDERS } from "./providers";

describe("PaymentGuide inside GuidesScreen", () => {
  it("рендерит BIN-чекер и безналоговый адрес США с переданной страной шлюза", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "02-safe-payment-cards",
        currentIp: "185.212.102.40",
        currentCountry: "DE",
      }),
    );

    expect(html).toContain(subscription.card.title);
    expect(html).toContain(subscription.card.gateway("DE"));
    expect(html).toContain(subscription.address.title);
    expect(html).toContain(subscription.address.copyFull);
  });

  it("подставляет NL по умолчанию, если currentCountry не определена (--)", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "02-safe-payment-cards",
        currentCountry: "--",
      }),
    );

    expect(html).toContain(subscription.card.gateway("NL"));
  });

  it("показывает предупреждение против посредников, уточнение про личный Apple ID и не обещает нулевой риск", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "02-safe-payment-cards",
        currentCountry: "NL",
      }),
    );

    expect(html).toContain("Playerok");
    expect(html).toContain("FunPay");
    expect(html).toContain("Apple Pay");
    expect(html).toContain("личный Apple ID");
    expect(html).toContain("Gift Card");
    expect(html).not.toContain("равен нулю");
    expect(html).not.toContain("на 100%");
  });
});

describe("VpsGuide inside GuidesScreen", () => {
  it("использует Vultr вместо is*hosting, предупреждает о Cmd+Q и не даёт ложных абсолютных обещаний", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "01-personal-vpn-15min",
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
  });
});
