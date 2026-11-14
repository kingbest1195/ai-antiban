import { describe, expect, it } from "vitest";
import { formatCountryWithCode, isCountryBlockedForProvider } from "./country";
import { formatIp, maskIpsInText, resolvePinnedIp } from "./format";

describe("formatIp и maskIpsInText: режим скрытия IP для скриншотов", () => {
  it("маскирует IPv4, сохраняя только последний октет", () => {
    expect(formatIp("136.244.114.42", true)).toBe("•••.•••.•••.42");
    expect(formatIp("185.212.102.40:8080", true)).toBe("•••.•••.•••.40:8080");
    expect(formatIp("136.244.114.42", false)).toBe("136.244.114.42");
    expect(formatIp("--", true)).toBe("--");
    expect(formatIp(null, true)).toBe("--");
  });

  it("маскирует IPv6 и произвольные IPv4 внутри строк отчёта", () => {
    expect(formatIp("2001:db8::1", true)).toBe("••••:••••:…:1");
    expect(maskIpsInText("IP изменился с 10.0.0.1 на 185.212.102.40.", true)).toBe(
      "IP изменился с •••.•••.•••.1 на •••.•••.•••.40.",
    );
    expect(maskIpsInText("IP 10.0.0.1", false)).toBe("IP 10.0.0.1");
  });
});

describe("resolvePinnedIp: попровайдерный и глобальный пин", () => {
  it("отдаёт приоритет привязке конкретного провайдера перед default и pinned_ip", () => {
    const state = {
      pinned_ip: "1.1.1.1",
      pinned_ips: { default: "2.2.2.2", openai: "3.3.3.3" },
    };
    expect(resolvePinnedIp(state, "openai")).toBe("3.3.3.3");
    expect(resolvePinnedIp(state, "anthropic")).toBe("2.2.2.2");
    expect(resolvePinnedIp({ pinned_ip: "1.1.1.1" }, "gemini")).toBe("1.1.1.1");
    expect(resolvePinnedIp(null, "anthropic")).toBeNull();
  });
});

describe("formatCountryWithCode и isCountryBlockedForProvider", () => {
  it("форматирует страны с ISO-кодом и нормализует UK → GB", () => {
    expect(formatCountryWithCode("FR")).toBe("Франция (FR)");
    expect(formatCountryWithCode("gb")).toBe("Великобритания (GB)");
    expect(formatCountryWithCode("UK")).toBe("Великобритания (GB)");
  });

  it("проверяет списки заблокированных стран из матрицы провайдеров", () => {
    expect(isCountryBlockedForProvider("openai", "RU")).toBe(true);
    expect(isCountryBlockedForProvider("openai", "HK")).toBe(true);
    expect(isCountryBlockedForProvider("anthropic", "CN")).toBe(true);
    expect(isCountryBlockedForProvider("anthropic", "MM")).toBe(true);
    expect(isCountryBlockedForProvider("gemini", "MM")).toBe(false);
    expect(isCountryBlockedForProvider("openai", "VE")).toBe(true);
    expect(isCountryBlockedForProvider("gemini", "VE")).toBe(false);
    expect(isCountryBlockedForProvider("anthropic", "FR")).toBe(false);
    expect(isCountryBlockedForProvider("openai", "NL")).toBe(false);
  });
});
