import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { connect as copy } from "../../shared/copy/ru";
import { formatCountryWithCode } from "../../shared/lib/country";
import type { RouteView, RoutesSnapshot } from "../../types";
import { ConnectScreen, getAffectedProvidersForRoute, resolveProviderExitCountry } from "./ConnectScreen";

const makeRoute = (id: string, country: string, exitIp: string, label: string): RouteView => ({
  id,
  label,
  country,
  exit_ip: exitIp,
  enabled: true,
  added_at: 1,
  entries: [{ proto: "https", host: "proxy.example.com", port: 443, has_password: false, sni: "proxy.example.com" }],
  status: "active",
  is_default: id === "default-r",
  bound_providers: [],
  is_profile_route: false,
  health: { reachable: true, latency_ms: 42, checked_at: 1 },
});

describe("resolveProviderExitCountry и ConnectScreen", () => {
  const routes: RouteView[] = [
    makeRoute("default-r", "FR", "136.244.114.42", "Париж"),
    makeRoute("hk-r", "HK", "45.64.10.22", "Гонконг"),
  ];
  const snapshot: RoutesSnapshot = {
    routes,
    default_route_id: "default-r",
    provider_routes: {
      anthropic: "direct",
      openai: "hk-r",
      gemini: "default-r",
    },
    effective: {},
    dangling: [],
  };

  it("корректно определяет итоговую страну для direct, default и явного маршрута", () => {
    expect(resolveProviderExitCountry("anthropic", snapshot, routes, "RU")).toBe("RU");
    expect(resolveProviderExitCountry("openai", snapshot, routes, "NL")).toBe("HK");
    expect(resolveProviderExitCountry("gemini", snapshot, routes, "RU")).toBe("FR");
    expect(resolveProviderExitCountry("anthropic", null, [], "DE")).toBe("DE");
  });

  it("маскирует IP при hideIpMode, добавляет код страны и показывает предупреждение для заблокированной страны", () => {
    const html = renderToStaticMarkup(
      createElement(ConnectScreen, {
        state: {
          pinned_ip: null,
          strict_pinning_enabled: true,
          ip_history: {},
          session_allowed_providers: [],
          blocked_providers: [],
        },
        routesSnapshot: snapshot,
        currentIp: "95.165.10.22",
        currentCountry: "RU",
        hideIpMode: true,
        onRefreshState: vi.fn(async () => {}),
        onAuditRefresh: vi.fn(async () => {}),
        onOpenGuide: vi.fn(),
        onToast: vi.fn(),
      }),
    );

    expect(html).toContain("•••.•••.•••.42");
    expect(html).not.toContain("136.244.114.42");
    expect(html).toContain("Франция (FR)");
    expect(html).toContain(copy.routes.blockedCountryTitle(copy.routes.services.anthropic, formatCountryWithCode("RU")));
    expect(html).toContain(copy.routes.blockedCountryTitle(copy.routes.services.openai, formatCountryWithCode("HK")));
    expect(html).not.toContain(copy.routes.blockedCountryTitle(copy.routes.services.gemini, formatCountryWithCode("FR")));
  });

  it("getAffectedProvidersForRoute возвращает только затронутые сервисы или 'all'", () => {
    expect(getAffectedProvidersForRoute("hk-r", snapshot)).toEqual(["openai"]);
    expect(
      getAffectedProvidersForRoute("default-r", {
        ...snapshot,
        provider_routes: { anthropic: "direct", openai: "hk-r" },
      }),
    ).toEqual(["gemini"]);
    expect(getAffectedProvidersForRoute("unused-r", snapshot)).toEqual([]);
    expect(
      getAffectedProvidersForRoute("default-r", {
        routes,
        default_route_id: "default-r",
        provider_routes: {},
        effective: {},
        dangling: [],
      }),
    ).toBe("all");
    expect(getAffectedProvidersForRoute("hk-r", null)).toBe("all");
  });
});
