import { describe, expect, it } from "vitest";
import { formatRouteBadgeLabel, formatRouteOptionLabel, hasCountryMention } from "./country";

describe("hasCountryMention", () => {
  it("распознаёт название страны и ISO-код с учётом границ слова", () => {
    expect(hasCountryMention("Zastava · Франция", "FR")).toBe(true);
    expect(hasCountryMention("Zastava · FR", "FR")).toBe(true);
    expect(hasCountryMention("My France Server", "FR")).toBe(false);
    expect(hasCountryMention("Freedom Route", "FR")).toBe(false);
    expect(hasCountryMention("Нидерланды (NL)", "NL")).toBe(true);
  });
});

describe("formatRouteOptionLabel", () => {
  it("не дублирует страну и не создаёт вложенных скобок, когда label уже содержит название страны", () => {
    expect(
      formatRouteOptionLabel({
        label: "Zastava · Франция",
        country: "FR",
        ipOrHost: "136.244.114.42",
      }),
    ).toBe("Zastava · Франция (FR · 136.244.114.42)");
  });

  it("не дублирует код страны, когда label уже содержит ISO-код", () => {
    expect(
      formatRouteOptionLabel({
        label: "Zastava · FR",
        country: "FR",
        ipOrHost: "136.244.114.42",
      }),
    ).toBe("Zastava · FR (Франция · 136.244.114.42)");
  });

  it("оставляет только IP, если в label уже есть и страна, и код", () => {
    expect(
      formatRouteOptionLabel({
        label: "Zastava · Нидерланды (NL)",
        country: "NL",
        ipOrHost: "185.212.102.40",
      }),
    ).toBe("Zastava · Нидерланды (NL) (185.212.102.40)");
  });

  it("форматирует страну без вложенных скобок, когда в label её нет", () => {
    expect(
      formatRouteOptionLabel({
        label: "Рабочий сервер",
        country: "NL",
        ipOrHost: "185.212.102.40",
      }),
    ).toBe("Рабочий сервер (Нидерланды, NL · 185.212.102.40)");
  });

  it("использует fallbackLabel, если label пустой", () => {
    expect(
      formatRouteOptionLabel({
        label: "",
        country: "DE",
        ipOrHost: "1.2.3.4",
        fallbackLabel: "Маршрут",
      }),
    ).toBe("Маршрут (Германия, DE · 1.2.3.4)");
  });
});

describe("formatRouteBadgeLabel", () => {
  it("не добавляет код страны повторно, если страна уже упомянута в label", () => {
    expect(formatRouteBadgeLabel("Zastava · Франция", "FR")).toBe("Zastava · Франция");
    expect(formatRouteBadgeLabel("Zastava · FR", "FR")).toBe("Zastava · FR");
    expect(formatRouteBadgeLabel("Мой сервер", "NL")).toBe("Мой сервер · NL");
  });
});
