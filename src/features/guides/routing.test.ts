import { createElement } from "react";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("../../ui/Steps", async () => {
  const actual = await vi.importActual<typeof import("../../ui/Steps")>("../../ui/Steps");
  return {
    ...actual,
    Steps: ({ items }: { items: Array<{ title: ReactNode; text?: ReactNode; body?: ReactNode }> }) =>
      createElement(
        "ol",
        { className: "zs-steps" },
        items.map((item, idx) =>
          createElement("li", { key: idx }, item.title, item.text, item.body),
        ),
      ),
  };
});

import { guides as copy } from "../../shared/copy/ru";
import { GuideContext } from "./context";
import { GuidesScreen } from "./GuidesScreen";
import { PaymentGuide } from "./PaymentGuide";
import { VIRTUAL_CARD_PROVIDERS } from "./providers";
import { resolveGuide } from "./routing";

describe("resolveGuide (Bug #2 routing)", () => {
  it("маршрутизирует сетевые/DNS/IPv6/STUN гайды в раздел os, part: 'geo'", () => {
    expect(resolveGuide("03-os-privacy-setup#geo")).toEqual({ section: "os", part: "geo" });
    expect(resolveGuide("03-os-network-dns")).toEqual({ section: "os", part: "geo" });
    expect(resolveGuide("os-geo")).toEqual({ section: "os", part: "geo" });
  });

  it("сохраняет существующую маршрутизацию часового пояса и локали в part: 'tz'", () => {
    expect(resolveGuide("03-os-privacy-setup")).toEqual({ section: "os", part: "tz" });
    expect(resolveGuide("os")).toEqual({ section: "os", part: "tz" });
  });

  it("сохраняет маршрутизацию оплаты и способов VPS", () => {
    expect(resolveGuide("02-safe-payment-cards")).toEqual({ section: "payment" });
    expect(resolveGuide("payment")).toEqual({ section: "payment" });
    expect(resolveGuide("01-personal-vpn-amnezia")).toEqual({ section: "vps", method: "amnezia" });
    expect(resolveGuide("vless_one_cmd")).toEqual({ section: "vps", method: "vless_one_cmd" });
    expect(resolveGuide("terminal")).toEqual({ section: "vps", method: "cascade" });
    expect(resolveGuide("cascade")).toEqual({ section: "vps", method: "cascade" });
    expect(resolveGuide("unknown-id")).toEqual({ section: "vps" });
  });
});

describe("OsGuide geo DNS card & PaymentGuide quick-entry", () => {
  it("рендерит карточку DNS (1.1.1.1 / 8.8.8.8 / DoH) и кнопку настроек сети при переходе по 03-os-privacy-setup#geo", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "03-os-privacy-setup#geo",
        currentIp: "185.212.102.40",
        currentCountry: "NL",
      }),
    );

    expect(html).toContain(copy.os.dns.title);
    expect(html).toContain("1.1.1.1");
    expect(html).toContain("8.8.8.8");
    expect(html).toContain("DoH");
    expect(html).toContain(copy.os.dns.openNetwork);
  });

  it("рендерит быструю кнопку BIN/адрес США в PaymentGuide и не содержит устаревшую ссылку на вкладку «Биллинг»", () => {
    const html = renderToStaticMarkup(
      createElement(
        GuideContext.Provider,
        {
          value: {
            currentIp: "185.212.102.40",
            currentCountry: "NL",
            copiedId: null,
            copy: async () => {},
          },
        },
        createElement(PaymentGuide, { onOpenPaymentTools: () => {} }),
      ),
    );

    expect(html).toContain(copy.payment.openPaymentTools);
    expect(html).toContain(copy.payment.pitchText);
    expect(copy.payment.pitchText).not.toContain("во вкладке «Биллинг»");
    expect(VIRTUAL_CARD_PROVIDERS.map((p) => p.description).join("\n")).not.toContain("«Биллинг»");
  });

  it("GuidesScreen (VpsGuide) маскирует IPv4 и IPv6 currentIp при hideIpMode=true", () => {
    const html = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "01-personal-vpn-amnezia",
        currentIp: "185.212.102.40",
        currentCountry: "NL",
        hideIpMode: true,
      }),
    );
    expect(html).toContain("•••.•••.•••.40");
    expect(html).not.toContain("185.212.102.40");

    const htmlV6 = renderToStaticMarkup(
      createElement(GuidesScreen, {
        initialGuide: "01-personal-vpn-amnezia",
        currentIp: "2001:db8:85a3::7334",
        currentCountry: "DE",
        hideIpMode: true,
      }),
    );
    expect(htmlV6).toContain("••••:••••:…:7334");
    expect(htmlV6).not.toContain("2001:db8:85a3::7334");
  });
});
