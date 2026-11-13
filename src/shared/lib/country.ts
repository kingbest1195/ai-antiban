let names: Intl.DisplayNames | null | undefined;

/** Страна словом по коду ISO: «NL» → «Нидерланды». Без кода или при сбое возвращается исходное значение. */
export function countryName(code: string | null | undefined): string {
  if (!code || code === "--") return "";
  const normalized = code.toUpperCase() === "UK" ? "GB" : code.toUpperCase();
  if (names === undefined) {
    try {
      names = new Intl.DisplayNames(["ru"], { type: "region" });
    } catch {
      names = null;
    }
  }
  try {
    return names?.of(normalized) ?? code;
  } catch {
    return code;
  }
}

/** Страна с кодом: «NL» → «Нидерланды (NL)». При отсутствии кода возвращает пустую строку. */
export function formatCountryWithCode(code: string | null | undefined): string {
  if (!code || code === "--") return "";
  const upper = code.trim().toUpperCase();
  if (!upper) return "";
  const name = countryName(upper);
  if (!name || name.toUpperCase() === upper) return upper;
  return `${name} (${upper})`;
}
