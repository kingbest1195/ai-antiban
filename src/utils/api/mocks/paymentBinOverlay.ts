import type { BinReport } from "../../../types";
import { countryName } from "../../../shared/lib/country";

function normCc(cc?: string | null): string {
  return (cc ?? "").trim().toUpperCase();
}

export function validateMockBinPrefix(raw: string): string {
  const clean = raw.trim();
  if (!/^\d+$/.test(clean)) {
    throw new Error("Допускаются только первые 6–8 цифр карты без букв и символов.");
  }
  if (clean.length < 6) {
    throw new Error("Введите минимум 6 первых цифр карты.");
  }
  if (clean.length > 8) {
    throw new Error(
      "Для вашей безопасности не вводите полный номер карты — достаточно первых 6–8 цифр.",
    );
  }
  return clean;
}

function mockLookupOverlay(bin: string): BinReport {
  if (bin.startsWith("000000") || bin.startsWith("999999")) {
    return {
      binPrefix: bin,
      status: "unknown",
      scheme: null,
      funding: "unknown",
      isPrepaid: null,
      isCommercial: null,
      isReloadable: null,
      cardCategory: null,
      countryCode: null,
      issuerName: null,
      knownFintechLabel: null,
      source: "fallbackUnknown",
      claudeWebVerdict: "highKycRisk",
      warnings: [
        "Не удалось проверить карту — оплата вслепую повышает риск проверки по паспорту и селфи. Повторите проверку позже или оплатите через App Store.",
      ],
    };
  }
  if (
    bin.startsWith("2200") ||
    bin.startsWith("2201") ||
    bin.startsWith("2202") ||
    bin.startsWith("2203") ||
    bin.startsWith("2204")
  ) {
    return {
      binPrefix: bin,
      status: "critical",
      scheme: "MIR",
      funding: "debit",
      isPrepaid: false,
      isCommercial: false,
      isReloadable: null,
      cardCategory: "CLASSIC",
      countryCode: "RU",
      issuerName: "NSPK MIR",
      knownFintechLabel: bin.startsWith("220441") ? "Antarctic Wallet (MIR RU)" : null,
      source: "localOverlay",
      claudeWebVerdict: "blocked",
      warnings: [
        "Карта выпущена в России — платёжная система сайта отклоняет карты этого региона.",
      ],
    };
  }
  if (bin.startsWith("493724")) {
    return {
      binPrefix: bin,
      status: "critical",
      scheme: "VISA",
      funding: "prepaid",
      isPrepaid: true,
      isCommercial: true,
      isReloadable: true,
      cardCategory: "PREPAID BUSINESS",
      countryCode: "SG",
      issuerName: "NIUM PTE. LTD.",
      knownFintechLabel: "Wayment / RedotPay (SG Nium)",
      source: "localOverlay",
      claudeWebVerdict: "highKycRisk",
      warnings: [
        "Предоплаченная корпоративная карта Сингапура: при оплате на сайте часто вызывает проверку по паспорту и селфи.",
      ],
    };
  }
  if (bin.startsWith("404038")) {
    return {
      binPrefix: bin,
      status: "critical",
      scheme: "VISA",
      funding: "prepaid",
      isPrepaid: true,
      isCommercial: false,
      isReloadable: true,
      cardCategory: "PREPAID",
      countryCode: "HK",
      issuerName: "REDOTPAY HK",
      knownFintechLabel: "RedotPay (HK)",
      source: "localOverlay",
      claudeWebVerdict: "blocked",
      warnings: ["Карты Гонконга платёжная система сайта не принимает для оплаты подписки."],
    };
  }
  if (bin.startsWith("440043")) {
    return {
      binPrefix: bin,
      status: "ok",
      scheme: "VISA",
      funding: "debit",
      isPrepaid: false,
      isCommercial: false,
      isReloadable: null,
      cardCategory: "CLASSIC",
      countryCode: "KZ",
      issuerName: "KASPI BANK JSC",
      knownFintechLabel: "Kaspi Gold (KZ)",
      source: "localOverlay",
      claudeWebVerdict: "needsMatchingIpBilling",
      warnings: [],
    };
  }
  if (bin.startsWith("446614")) {
    return {
      binPrefix: bin,
      status: "warning",
      scheme: "VISA",
      funding: "debit",
      isPrepaid: false,
      isCommercial: true,
      isReloadable: null,
      cardCategory: "BUSINESS",
      countryCode: "US",
      issuerName: "CBW BANK",
      knownFintechLabel: "Плати по миру (США)",
      source: "localOverlay",
      claudeWebVerdict: "needsMatchingIpBilling",
      warnings: ["Корпоративная карта США: требуется строгое совпадение подключения и адреса оплаты в США."],
    };
  }
  if (bin.startsWith("489504") || bin.startsWith("414720") || bin.startsWith("483312")) {
    return {
      binPrefix: bin,
      status: "ok",
      scheme: "VISA",
      funding: "debit",
      isPrepaid: false,
      isCommercial: false,
      isReloadable: null,
      cardCategory: "CLASSIC",
      countryCode: "US",
      issuerName: "JPMORGAN CHASE BANK, N.A.",
      knownFintechLabel: null,
      source: "localOverlay",
      claudeWebVerdict: "safeAligned",
      warnings: [],
    };
  }
  if (bin.startsWith("535456")) {
    return {
      binPrefix: bin,
      status: "ok",
      scheme: "MASTERCARD",
      funding: "debit",
      isPrepaid: false,
      isCommercial: false,
      isReloadable: null,
      cardCategory: "STANDARD",
      countryCode: "NL",
      issuerName: "ING BANK N.V.",
      knownFintechLabel: null,
      source: "localOverlay",
      claudeWebVerdict: "safeAligned",
      warnings: [],
    };
  }
  return {
    binPrefix: bin,
    status: "ok",
    scheme: "VISA",
    funding: "debit",
    isPrepaid: false,
    isCommercial: false,
    isReloadable: null,
    cardCategory: "CLASSIC",
    countryCode: "GB",
    issuerName: "BARCLAYS BANK UK PLC",
    knownFintechLabel: null,
    source: "proxyApi",
    claudeWebVerdict: "needsMatchingIpBilling",
    warnings: [],
  };
}

export function mockCheckCardBin(bin: string, vpnCountry?: string | null): BinReport {
  const strict = validateMockBinPrefix(bin);
  const report = mockLookupOverlay(strict);
  const vpnCc = normCc(vpnCountry);
  if (
    report.source !== "fallbackUnknown" &&
    report.status !== "critical" &&
    report.countryCode &&
    vpnCc &&
    vpnCc !== "--" &&
    report.countryCode !== vpnCc
  ) {
    report.status = "warning";
    if (report.claudeWebVerdict === "safeAligned") {
      report.claudeWebVerdict = "needsMatchingIpBilling";
    }
    const cardLabel = countryName(report.countryCode) || report.countryCode;
    const vpnLabel = countryName(vpnCc) || vpnCc;
    report.warnings = [
      ...report.warnings,
      `Несовпадение регионов: карта выпущена в ${cardLabel}, а текущее подключение — ${vpnLabel}.`,
    ];
  }
  return report;
}
