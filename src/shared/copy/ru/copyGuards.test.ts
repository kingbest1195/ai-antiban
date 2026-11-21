import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("../../../ui/Modal", () => ({
  Modal: ({ open, title, children, footer }: { open: boolean; title: string; children?: unknown; footer?: unknown }) =>
    open ? createElement("div", { "data-modal": title }, children as never, footer as never) : null,
}));

import { cleanRoom } from "./cleanRoom";
import { settings } from "./settings";
import { subscription } from "./subscription";
import { sosCopy as sos } from "./sos";
import { VIRTUAL_CARD_PROVIDERS } from "../../../features/guides/providers";
import { WhatsNewSheet } from "../../../features/shell-v3/WhatsNewSheet";

function serializeStrings(val: unknown): string {
  if (typeof val === "string") return val;
  if (typeof val === "function") return String(val);
  if (Array.isArray(val)) return val.map(serializeStrings).join("\n");
  if (val && typeof val === "object") return Object.values(val).map(serializeStrings).join("\n");
  return "";
}

describe("v3.0.1 RU Copy & Anti-Jargon Guards", () => {
  const BANNED_JARGON = ["Launchpad", "PowerPill", "READY ·", "set_pac_url", "read-only"];

  it("не содержит сырой технический жаргон в cleanRoom, settings, subscription, sos и WhatsNewSheet", () => {
    const whatsNewHtml = renderToStaticMarkup(
      createElement(WhatsNewSheet, { open: true, onAcknowledge: vi.fn(), onRestartOnboarding: vi.fn() }),
    );
    const sources: Array<[string, string]> = [
      ["src/shared/copy/ru/cleanRoom.ts", serializeStrings(cleanRoom)],
      ["src/shared/copy/ru/settings.ts", serializeStrings(settings)],
      ["src/shared/copy/ru/subscription.ts", serializeStrings(subscription)],
      ["src/shared/copy/ru/sos.ts", serializeStrings(sos)],
      ["src/features/onboarding/WhatsNewSheet.tsx", whatsNewHtml],
    ];

    for (const [name, text] of sources) {
      for (const term of BANNED_JARGON) {
        expect(text, `${name} не должен содержать «${term}»`).not.toContain(term);
      }
    }
  });

  it("src/features/guides/providers.ts не содержит устаревшую ссылку на вкладку «Биллинг»", () => {
    const text = serializeStrings(VIRTUAL_CARD_PROVIDERS);
    expect(text).not.toContain("вкладке «Биллинг»");
    expect(text).not.toContain("«Биллинг»");
  });
});
