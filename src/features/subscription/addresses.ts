// Безналоговые штаты США и контекстная логика адреса для оплаты.

export interface TaxFreeAddress {
  stateName: string;
  code: string;
  street: string;
  city: string;
  zip: string;
}

export type AddressScenario = "apple_iap" | "card";

export const TAX_FREE_ADDRESSES: TaxFreeAddress[] = [
  {
    stateName: "Делавэр (без налога)",
    code: "DE",
    street: "1201 N Orange St, Ste 700",
    city: "Wilmington",
    zip: "19801",
  },
  {
    stateName: "Орегон (без налога)",
    code: "OR",
    street: "1001 SW 5th Ave, Ste 1100",
    city: "Portland",
    zip: "97204",
  },
  {
    stateName: "Нью-Гэмпшир (без налога)",
    code: "NH",
    street: "100 Market St, Ste 400",
    city: "Portsmouth",
    zip: "03801",
  },
  {
    stateName: "Монтана (без налога)",
    code: "MT",
    street: "208 N Broadway, Ste 320",
    city: "Billings",
    zip: "59101",
  },
  {
    stateName: "Аляска (без налога)",
    code: "AK",
    street: "333 W 4th Ave, Ste 200",
    city: "Anchorage",
    zip: "99501",
  },
];

export function normalizeCountryCode(raw?: string | null): string | null {
  const clean = raw?.trim().toUpperCase() ?? "";
  return /^[A-Z]{2}$/.test(clean) ? clean : null;
}

/**
 * Безналоговые адреса США показываются ТОЛЬКО когда:
 * 1) карта выпущена в США (`cardCountry === "US"`), ИЛИ
 * 2) выбран сценарий `Apple IAP (US Apple ID)`.
 */
export function shouldShowUsTaxFreeAddresses(opts: {
  cardCountry?: string | null;
  scenario?: AddressScenario;
}): boolean {
  if (opts.scenario === "apple_iap") return true;
  const cc = normalizeCountryCode(opts.cardCountry);
  return cc === "US";
}
