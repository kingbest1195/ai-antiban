import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { subscription } from "../../shared/copy/ru";
import { GuidesScreen } from "./GuidesScreen";

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
});
