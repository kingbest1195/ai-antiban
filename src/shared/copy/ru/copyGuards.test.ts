import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("../../../ui/Modal", () => ({
  Modal: ({ open, title, children, footer }: { open: boolean; title: string; children?: unknown; footer?: unknown }) =>
    open ? createElement("div", { "data-modal": title }, children as never, footer as never) : null,
}));

import { alertDialog } from "./alert";
import { backup } from "./backup";
import { bunkerCopy } from "./bunker";
import { checks } from "./checks";
import { cleanRoom } from "./cleanRoom";
import { guides } from "./guides";
import { overview } from "./overview";
import { settings } from "./settings";
import { about, shell, shutdown, tabs, timezone, updates } from "./shell";
import { subscription } from "./subscription";
import { sosCopy as sos } from "./sos";
import { toast } from "./toasts";
import { BLACKLISTED_PROVIDERS, VIRTUAL_CARD_PROVIDERS, VPS_PROVIDERS } from "../../../features/guides/providers";
import { WhatsNewSheet } from "../../../features/shell-v3/WhatsNewSheet";

function serializeStrings(val: unknown): string {
  if (typeof val === "string") return val;
  if (typeof val === "function") {
    return String(val)
      .replace(/^\([^)]*\)\s*=>\s*/, "")
      .replace(/\$\{[^}]+\}/g, "X");
  }
  if (Array.isArray(val)) return val.map(serializeStrings).join("\n");
  if (val && typeof val === "object") return Object.values(val).map(serializeStrings).join("\n");
  return "";
}

/**
 * Бан-лист §8.2 (технический жаргон, внутренняя кухня и сленг),
 * с разумными границами слов, чтобы не ловить легитимные enum-идентификаторы и обычные слова вроде «сервис».
 */
const BANNED_PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  { label: "Launchpad", pattern: /\bLaunchpad\b/ },
  { label: "PowerPill", pattern: /\bPowerPill\b/ },
  { label: "READY ·", pattern: /READY ·/ },
  { label: "set_pac_url", pattern: /\bset_pac_url\b/ },
  { label: "read-only", pattern: /\bread-only\b/ },
  { label: "PayShield", pattern: /payshield/iu },
  { label: "Stripe", pattern: /(?<![\p{L}\p{N}_])stripe(?![\p{L}\p{N}_])/iu },
  { label: "Stripe Radar", pattern: /stripe\s+radar/iu },
  { label: "BIN", pattern: /(?<![\p{L}\p{N}_])bin(?![\p{L}\p{N}_])/iu },
  { label: "BIN-рентген", pattern: /bin-рентген/iu },
  { label: "Zero PCI-DSS", pattern: /zero\s+pci-dss/iu },
  { label: "Zero-PAN", pattern: /zero-pan/iu },
  { label: "CHD", pattern: /(?<![\p{L}\p{N}_])chd(?![\p{L}\p{N}_])/iu },
  { label: "эмитент", pattern: /(?<![\p{L}\p{N}_])эмитент[\p{L}]*/iu },
  { label: "AVS", pattern: /(?<![\p{L}\p{N}_])avs(?![\p{L}\p{N}_])/iu },
  { label: "KYC", pattern: /(?<![\p{L}\p{N}_])kyc(?![\p{L}\p{N}_])/iu },
  { label: "Persona KYC", pattern: /persona\s+kyc/iu },
  { label: "DirectCard", pattern: /(?<![\p{L}\p{N}_])directcard(?![\p{L}\p{N}_])/iu },
  { label: "Apple IAP", pattern: /apple\s+iap/iu },
  { label: "ASN", pattern: /(?<![\p{L}\p{N}_])asn(?![\p{L}\p{N}_])/iu },
  { label: "Split-IP", pattern: /split-ip/iu },
  { label: "биллинг", pattern: /(?<![\p{L}\p{N}_])биллинг[\p{L}-]*/iu },
  { label: "чекаут", pattern: /(?<![\p{L}\p{N}_])чекаут[\p{L}]*/iu },
  { label: "пост-платёжный карантин", pattern: /пост-плат[её]жн[\p{L}]*\s+карантин[\p{L}]*/iu },
  { label: "Fail-Closed", pattern: /fail-closed/iu },
  { label: "FallbackUnknown", pattern: /(?<![\p{L}\p{N}_])fallbackunknown(?![\p{L}\p{N}_])/iu },
  { label: "Tainted", pattern: /(?<![\p{L}\p{N}_])tainted(?![\p{L}\p{N}_])/iu },
  { label: "Партнёрская ссылка", pattern: /партн[её]рск[\p{L}]*\s+ссылк[\p{L}]*/iu },
  { label: "Непартнёрская", pattern: /(?<![\p{L}\p{N}_])непартн[её]рск[\p{L}]*/iu },
  { label: "Уровень 1", pattern: /(?<![\p{L}\p{N}_])уровень\s+1(?![\p{L}\p{N}_])/iu },
  { label: "Уровень 2", pattern: /(?<![\p{L}\p{N}_])уровень\s+2(?![\p{L}\p{N}_])/iu },
  { label: "maxipay.global", pattern: /maxipay\.global/iu },
  { label: "связующее звено", pattern: /связующ[\p{L}]*\s+звен[\p{L}]*/iu },
  { label: "Централизованный агент", pattern: /централизованн[\p{L}]*\s+агент[\p{L}]*/iu },
  { label: "446614", pattern: /(?<![\p{L}\p{N}_])446614(?![\p{L}\p{N}_])/u },
  { label: "Anthropic API", pattern: /anthropic\s+api/iu },
  { label: "UAC", pattern: /(?<![\p{L}\p{N}_])uac(?![\p{L}\p{N}_])/iu },
  { label: "CLI / IDE", pattern: /cli\s*\/\s*ide/iu },
  { label: "TZ", pattern: /(?<![\p{L}\p{N}_])tz(?![\p{L}\p{N}_])/iu },
  { label: "Системный TZ", pattern: /системн[\p{L}]*\s+tz(?![\p{L}\p{N}_])/iu },
  { label: "LANG", pattern: /(?<![\p{L}\p{N}_])LANG(?![\p{L}\p{N}_])/u },
  { label: "LC_TIME", pattern: /(?<![\p{L}\p{N}_])LC_TIME(?![\p{L}\p{N}_])/u },
  { label: "CoworkVMService", pattern: /coworkvmservice/iu },
  { label: "хвост(ы/ов)", pattern: /(?<![\p{L}\p{N}_])хвост(?:ы|ов|а|у|ом|е|ами|ах)?(?![\p{L}\p{N}_])/iu },
];

describe("v3.0.1 / v3.1.0 RU Copy & Anti-Jargon Guards", () => {
  it("не содержит технический жаргон, сленг и внутреннюю кухню §8.2 во всех пользовательских словарях и providers.ts", () => {
    const whatsNewHtml = renderToStaticMarkup(
      createElement(WhatsNewSheet, { open: true, onAcknowledge: vi.fn(), onRestartOnboarding: vi.fn() }),
    );
    const providersText = serializeStrings([VIRTUAL_CARD_PROVIDERS, BLACKLISTED_PROVIDERS, VPS_PROVIDERS]);
    const guidesLegacySanitized = serializeStrings({ vps: guides.vps, os: guides.os })
      .replace(/ASN\/DC/g, "")
      .replace(/LANG=en_US\.UTF-8/g, "");
    const checksSanitized = serializeStrings({
      ...checks,
      data: { ...checks.data, asn: "" },
      items: { ...checks.items, asn: { ...checks.items.asn, title: "" } },
    });
    const sources: Array<[string, string]> = [
      ["src/features/guides/providers.ts", providersText],
      ["src/shared/copy/ru/guides.ts (payment & common)", serializeStrings({ ...guides, vps: undefined, os: undefined })],
      ["src/shared/copy/ru/guides.ts (vps & os)", guidesLegacySanitized],
      ["src/shared/copy/ru/subscription.ts", serializeStrings(subscription)],
      ["src/shared/copy/ru/alert.ts", serializeStrings(alertDialog)],
      ["src/shared/copy/ru/settings.ts", serializeStrings(settings)],
      ["src/shared/copy/ru/overview.ts", serializeStrings(overview)],
      ["src/shared/copy/ru/backup.ts", serializeStrings(backup)],
      ["src/shared/copy/ru/cleanRoom.ts", serializeStrings(cleanRoom)],
      ["src/shared/copy/ru/bunker.ts", serializeStrings(bunkerCopy)],
      ["src/shared/copy/ru/sos.ts", serializeStrings(sos)],
      ["src/shared/copy/ru/checks.ts", checksSanitized],
      ["src/shared/copy/ru/shell.ts", serializeStrings({ tabs, shell, timezone, shutdown, updates, about })],
      ["src/shared/copy/ru/toasts.ts", serializeStrings(toast)],
      ["src/features/shell-v3/WhatsNewSheet.tsx", whatsNewHtml],
    ];

    for (const [name, text] of sources) {
      for (const { label, pattern } of BANNED_PATTERNS) {
        expect(text, `${name} не должен содержать «${label}»`).not.toMatch(pattern);
      }
    }
  });

  it("src/features/guides/providers.ts не содержит устаревшую ссылку на вкладку «Биллинг» и запрещённых рекомендаций", () => {
    const recommendedText = serializeStrings(VIRTUAL_CARD_PROVIDERS);
    const blacklistText = serializeStrings(BLACKLISTED_PROVIDERS);

    expect(recommendedText).not.toContain("вкладке «Биллинг»");
    expect(recommendedText).not.toContain("«Биллинг»");
    expect(blacklistText).not.toContain("«Биллинг»");

    expect(VIRTUAL_CARD_PROVIDERS.some((p) => p.id === "epn")).toBe(false);
    for (const forbidden of ["e.pn", "Bitrefill", "EasyPay", "OpenRouter", "ProxyAPI.ru", "BotHub"]) {
      expect(recommendedText, `VIRTUAL_CARD_PROVIDERS не должен рекомендовать ${forbidden}`).not.toContain(forbidden);
    }

    for (const provider of VIRTUAL_CARD_PROVIDERS) {
      expect(["tier1_iap", "tier2_conditional"]).toContain(provider.tier);
      expect(provider.warnings.length).toBeGreaterThan(0);
    }

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
      "Playerok",
      "FunPay",
    ]) {
      expect(blacklistText).toContain(item);
    }
  });

  it("согласует формулировки под 96 ч прогрева и 72 ч пост-платёжного карантина в guides, subscription и cleanRoom", () => {
    const guidesPaymentText = serializeStrings(guides.payment);
    const subText = serializeStrings(subscription);
    const crText = serializeStrings(cleanRoom);

    for (const [name, text] of [
      ["guides.payment", guidesPaymentText],
      ["subscription", subText],
      ["cleanRoom", crText],
    ] as const) {
      expect(text, `${name} должен упоминать 96 часов прогрева`).toMatch(/96\s*(?:ч|час)/);
      expect(text, `${name} должен упоминать 72 часа карантина`).toMatch(/72\s*(?:ч|час)/);
      expect(text, `${name} не должен содержать устаревшее «3–5 дней»`).not.toContain("3–5 дней");
      expect(text, `${name} не должен содержать устаревшее «3–4 дня»`).not.toContain("3–4 дня");
      expect(text, `${name} не должен обещать универсальность виртуальных карт`).not.toContain("любая виртуальная карта подходит");
    }

    // OpenRouter остаётся только в аварийном sos.ts
    expect(serializeStrings(sos)).toContain("OpenRouter");
    expect(guidesPaymentText).not.toContain("OpenRouter");
  });

  it("сканирует .tsx файлы оплаты, гайдов, проверок, Бункера, SOS и Чистой комнаты на запрещённый пользовательский жаргон", () => {
    const rawTsxModules = import.meta.glob(
      [
        "../../../features/subscription/**/*.tsx",
        "../../../features/guides/**/*.tsx",
        "../../../features/checks/**/*.tsx",
        "../../../features/backup/**/*.tsx",
        "../../../features/bunker/**/*.tsx",
        "../../../features/sos/**/*.tsx",
        "../../../features/clean-room/**/*.tsx",
        "../../../features/alert/**/*.tsx",
      ],
      { query: "?raw", import: "default", eager: true },
    ) as Record<string, string>;

    const tsxBanned: Array<{ label: string; pattern: RegExp }> = [
      { label: "KYC", pattern: /(?<![\p{L}\p{N}_])kyc(?![\p{L}\p{N}_])/iu },
      { label: "PayShield", pattern: /payshield/iu },
      { label: "Stripe Radar", pattern: /stripe\s+radar/iu },
      { label: "Persona KYC", pattern: /persona\s+kyc/iu },
      { label: "биллинг", pattern: /(?<![\p{L}\p{N}_])биллинг[\p{L}-]*/iu },
      { label: "чекаут", pattern: /(?<![\p{L}\p{N}_])чекаут[\p{L}]*/iu },
      { label: "BIN-рентген", pattern: /bin-рентген/iu },
    ];

    const stripComments = (src: string): string =>
      src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/.*$/gm, " ");

    const entries = Object.entries(rawTsxModules);
    expect(entries.length).toBeGreaterThan(10);

    for (const [file, source] of entries) {
      const codeOnly = stripComments(source);
      for (const { label, pattern } of tsxBanned) {
        expect(codeOnly, `${file} не должен содержать «${label}»`).not.toMatch(pattern);
      }
    }
  });
});
