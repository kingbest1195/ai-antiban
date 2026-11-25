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

  it("маскирует IPv6 и произвольные IPv4/IPv6 внутри строк отчёта", () => {
    expect(formatIp("2001:db8::1", true)).toBe("••••:••••:…:1");
    expect(maskIpsInText("IP изменился с 10.0.0.1 на 185.212.102.40.", true)).toBe(
      "IP изменился с •••.•••.•••.1 на •••.•••.•••.40.",
    );
    expect(maskIpsInText("IPv6 2001:db8::1 обнаружен в 14:03:27", true)).toBe(
      "IPv6 ••••:••••:…:1 обнаружен в 14:03:27",
    );
    expect(maskIpsInText("IP 10.0.0.1", false)).toBe("IP 10.0.0.1");
  });

  it("маскирует dot- и dash-разделённые IPv4 внутри PTR-хостов без ложных срабатываний на даты и версии", () => {
    const ptrText =
      "PTR (64.176.194.110.vultrusercontent.com), static.5.101.220.185.clients.your-server.de, " +
      "185-220-101-5.isp.net, ip64-176-194-110.isp.net и ec2-54-12-34-56.compute-1.amazonaws.com; " +
      "версии v2.1.2, v1.2.3.4, v1-2-3-4.example.com, Chrome/131.0.0.0, дата 2026-11-25, id 12-34-56-78 и 1.2.3.4.5.example.com.";
    const masked = maskIpsInText(ptrText, true);

    expect(masked).not.toContain("64.176.194.110");
    expect(masked).not.toContain("5.101.220.185");
    expect(masked).not.toContain("185-220-101-5");
    expect(masked).not.toContain("64-176-194-110");
    expect(masked).not.toContain("54-12-34-56");
    expect(masked).toContain("•••.•••.•••.110.vultrusercontent.com");
    expect(masked).toContain("static.•••.•••.•••.185.clients.your-server.de");
    expect(masked).toContain("•••-•••-•••-5.isp.net");
    expect(masked).toContain("ip•••-•••-•••-110.isp.net");
    expect(masked).toContain("ec2-•••-•••-•••-56.compute-1.amazonaws.com");
    expect(masked).toContain("v2.1.2");
    expect(masked).toContain("v1.2.3.4");
    expect(masked).toContain("v1-2-3-4.example.com");
    expect(masked).toContain("Chrome/131.0.0.0");
    expect(masked).toContain("2026-11-25");
    expect(masked).toContain("12-34-56-78");
    expect(masked).toContain("1.2.3.4.5.example.com");
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

  it("не подмешивает default/pinned_ip для провайдера на активном маршруте Заставы", () => {
    const routedState = {
      pinned_ip: "1.1.1.1",
      pinned_ips: { default: "2.2.2.2", openai: "3.3.3.3" },
      profile_route_id: "route-a",
      default_route_id: null,
      provider_routes: {},
    };
    expect(resolvePinnedIp(routedState, "anthropic")).toBeNull();
    expect(resolvePinnedIp(routedState, "openai")).toBe("3.3.3.3");
    expect(resolvePinnedIp(routedState, "gemini")).toBe("2.2.2.2");

    const routedWithKeyPin = {
      ...routedState,
      pinned_ips: { default: "2.2.2.2", anthropic: "45.45.45.45" },
    };
    expect(resolvePinnedIp(routedWithKeyPin, "anthropic")).toBe("45.45.45.45");
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
