import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { connect as copy, PROMO_COPY } from "../../shared/copy/ru";
import { formatCountryWithCode } from "../../shared/lib/country";
import type { RouteView, RoutesSnapshot } from "../../types";
import { DIRECT_ROUTE_ID } from "../../utils/api";
import { ConnectSalesCards } from "./ConnectSalesCards";
import { ConnectScreen, getAffectedProvidersForRoute, resolveProviderExitCountry } from "./ConnectScreen";
import { HOSTINGS } from "./hostings";
import { RouteDisableModals } from "./RouteDisableModals";
import { RouteUnavailableBanner } from "./RouteUnavailableBanner";
import {
  disableRouteAndSwitchBindingsToDirect,
  inspectRouteUsageForDisable,
  resetProfileRouteAndDisable,
  switchUnavailableBannerToDirect,
  type RouteBindActions,
} from "./routeDisableModel";

vi.mock("../../ui/Modal", () => ({
  Modal: ({ open, title, children, footer }: { open: boolean; title: string; children?: unknown; footer?: unknown }) =>
    open ? createElement("div", { "data-modal": title }, children as never, footer as never) : null,
}));

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

  it("показывает кнопку сброса при profile_route_error у активного профиля", () => {
    const html = renderToStaticMarkup(
      createElement(ConnectScreen, {
        state: {
          pinned_ip: null,
          strict_pinning_enabled: true,
          ip_history: {},
          session_allowed_providers: [],
          blocked_providers: [],
        },
        routesSnapshot: {
          ...snapshot,
          profile_route_error: "Ключ профиля Claude удалён — трафик Anthropic остановлен",
        },
        currentIp: "95.165.10.22",
        currentCountry: "DE",
        onRefreshState: vi.fn(async () => {}),
        onOpenGuide: vi.fn(),
        onToast: vi.fn(),
      }),
    );

    expect(html).toContain(copy.routes.profileErrorTitle);
    expect(html).toContain(copy.routes.resetToDirect);
  });

  it("использует Vultr с реферальной ссылкой и не содержит is*hosting", () => {
    const vultr = HOSTINGS.find((h) => h.id === "vultr");
    expect(vultr?.name).toBe("Vultr");
    expect(vultr?.url).toBe("https://www.vultr.com/?ref=9936768");
    expect(HOSTINGS.some((h) => (h.id as string) === "ishosting")).toBe(false);

    const html = renderToStaticMarkup(
      createElement(ConnectScreen, {
        state: null,
        routesSnapshot: snapshot,
        currentIp: "95.165.10.22",
        currentCountry: "DE",
        onRefreshState: vi.fn(async () => {}),
        onOpenGuide: vi.fn(),
        onToast: vi.fn(),
      }),
    );
    expect(html).toContain("Vultr");
    expect(html).not.toContain("is*hosting");
  });
});

describe("Bug #6: Route Toggle OFF UX, profile_route_id guard и Disabled banner", () => {
  const routes: RouteView[] = [
    makeRoute("default-r", "FR", "136.244.114.42", "Париж"),
    makeRoute("profile-r", "NL", "185.212.102.40", "Амстердам"),
    makeRoute("unused-r", "DE", "145.241.12.8", "Франкфурт"),
  ];

  const makeMockActions = (): RouteBindActions => ({
    bindProvider: vi.fn(async () => ({ routes: [], provider_routes: {}, effective: {}, dangling: [] })),
    setDefault: vi.fn(async () => ({ routes: [], provider_routes: {}, effective: {}, dangling: [] })),
    setEnabled: vi.fn(async () => ({ routes: [], provider_routes: {}, effective: {}, dangling: [] })),
    listProfiles: vi.fn(async () => ({
      active_profile_id: "work-claude",
      profiles: [],
      claude_desktop_installed: false,
      storage_dir: "/tmp",
    })),
    bindProfileRoute: vi.fn(async () => ({
      active_profile_id: "work-claude",
      profiles: [],
      claude_desktop_installed: false,
      storage_dir: "/tmp",
    })),
  });

  it("getAffectedProvidersForRoute учитывает profile_route_id для anthropic", () => {
    const snap: RoutesSnapshot = {
      routes,
      default_route_id: "default-r",
      profile_route_id: "profile-r",
      provider_routes: {
        anthropic: "direct",
        openai: "default-r",
      },
      effective: {},
      dangling: [],
    };

    expect(getAffectedProvidersForRoute("profile-r", snap)).toEqual(["anthropic"]);
    expect(getAffectedProvidersForRoute("default-r", snap)).toEqual(["openai", "gemini"]);
    expect(getAffectedProvidersForRoute("unused-r", snap)).toEqual([]);
  });

  it("Route-OFF рендерит оба выбора (Direct vs остановка/блокировка) и отдельное предупреждение для profile_route_id", () => {
    const snap: RoutesSnapshot = {
      routes,
      default_route_id: "default-r",
      profile_route_id: "profile-r",
      provider_routes: {},
      effective: {},
      dangling: [],
    };
    const usage = inspectRouteUsageForDisable("profile-r", snap, routes);
    expect(usage.inUse).toBe(true);
    expect(usage.isProfileRoute).toBe(true);

    const choiceHtml = renderToStaticMarkup(
      createElement(RouteDisableModals, {
        pendingDisable: { routeId: "profile-r", routeLabel: "Амстердам", usage },
        confirmProfileReset: null,
        busy: false,
        onCancelDisable: vi.fn(),
        onChooseDirect: vi.fn(),
        onChooseStopAndBlock: vi.fn(),
        onCancelProfileReset: vi.fn(),
        onConfirmProfileReset: vi.fn(),
      }),
    );

    expect(choiceHtml).toContain(copy.routes.disableModal.switchToDirect);
    expect(choiceHtml).toContain(copy.routes.disableModal.stopAndBlock);
    expect(choiceHtml).toContain(copy.routes.disableModal.profileNote);

    const profileConfirmHtml = renderToStaticMarkup(
      createElement(RouteDisableModals, {
        pendingDisable: null,
        confirmProfileReset: { routeId: "profile-r", routeLabel: "Амстердам", usage },
        busy: false,
        onCancelDisable: vi.fn(),
        onChooseDirect: vi.fn(),
        onChooseStopAndBlock: vi.fn(),
        onCancelProfileReset: vi.fn(),
        onConfirmProfileReset: vi.fn(),
      }),
    );

    expect(profileConfirmHtml).toContain(copy.routes.profileResetModal.title);
    expect(profileConfirmHtml).toContain(copy.routes.profileResetModal.confirm);
    expect(profileConfirmHtml).toContain("аккаунты");
  });

  it("перевод маршрута в Direct сбрасывает default/provider привязки, но блокирует тихий сброс profile_route_id без подтверждения", async () => {
    const actions = makeMockActions();
    const snap: RoutesSnapshot = {
      routes,
      default_route_id: "default-r",
      profile_route_id: null,
      provider_routes: { openai: "default-r" },
      effective: {},
      dangling: [],
    };
    const usage = inspectRouteUsageForDisable("default-r", snap, routes);
    await disableRouteAndSwitchBindingsToDirect({ routeId: "default-r", routeLabel: "Париж", usage }, actions);

    expect(actions.bindProvider).toHaveBeenCalledWith("openai", DIRECT_ROUTE_ID);
    expect(actions.setDefault).toHaveBeenCalledWith(null);
    expect(actions.setEnabled).toHaveBeenCalledWith("default-r", false);
    expect(actions.bindProfileRoute).not.toHaveBeenCalled();

    const profileSnap: RoutesSnapshot = {
      ...snap,
      profile_route_id: "profile-r",
    };
    const profileUsage = inspectRouteUsageForDisable("profile-r", profileSnap, routes);
    await expect(
      disableRouteAndSwitchBindingsToDirect(
        { routeId: "profile-r", routeLabel: "Амстердам", usage: profileUsage },
        actions,
      ),
    ).rejects.toThrow(/profile_route_id/);

    await resetProfileRouteAndDisable(
      { routeId: "profile-r", routeLabel: "Амстердам", usage: profileUsage },
      actions,
    );
    expect(actions.bindProfileRoute).toHaveBeenCalledWith("work-claude", null);
    expect(actions.setEnabled).toHaveBeenCalledWith("profile-r", false);
  });

  it("routeUnavailableBanner при reason='disabled' показывает 1-click переход на Direct, сохраняет CopyErrorLogButton и охраняет profile_route_id", async () => {
    const disabledHtml = renderToStaticMarkup(
      createElement(RouteUnavailableBanner, {
        banner: {
          route_id: "default-r",
          provider: "openai",
          reason: "disabled",
          message: "Маршрут отключён пользователем",
        },
        dismissLabel: "Скрыть",
        onOpenConnect: vi.fn(),
        onDismiss: vi.fn(),
      }),
    );

    expect(disabledHtml).toContain(copy.routes.switchToDirect);
    expect(disabledHtml).toContain("Маршрут отключён пользователем");
    expect(disabledHtml).toContain("Скопировать лог");

    const unreachableHtml = renderToStaticMarkup(
      createElement(RouteUnavailableBanner, {
        banner: {
          route_id: "default-r",
          provider: "openai",
          reason: "unreachable",
          message: "Узел не отвечает",
        },
        dismissLabel: "Скрыть",
        onOpenConnect: vi.fn(),
        onDismiss: vi.fn(),
      }),
    );

    expect(unreachableHtml).not.toContain(copy.routes.switchToDirect);
    expect(unreachableHtml).toContain("Скопировать лог");

    const actions = makeMockActions();
    const snapWithProfile: RoutesSnapshot = {
      routes,
      default_route_id: "default-r",
      profile_route_id: "profile-r",
      provider_routes: { openai: "default-r" },
      effective: {},
      dangling: [],
    };

    const guardOutcome = await switchUnavailableBannerToDirect(
      { route_id: "profile-r", provider: "anthropic", reason: "Disabled", message: "off" },
      snapWithProfile,
      { allowProfileReset: false },
      actions,
    );
    expect(guardOutcome).toBe("needs_profile_confirmation");
    expect(actions.bindProfileRoute).not.toHaveBeenCalled();

    const confirmedOutcome = await switchUnavailableBannerToDirect(
      { route_id: "profile-r", provider: "anthropic", reason: "Disabled", message: "off" },
      snapWithProfile,
      { allowProfileReset: true },
      actions,
    );
    expect(confirmedOutcome).toBe("switched");
    expect(actions.bindProfileRoute).toHaveBeenCalledWith("work-claude", null);
    expect(actions.bindProvider).toHaveBeenCalledWith("anthropic", DIRECT_ROUTE_ID);

    const directOutcome = await switchUnavailableBannerToDirect(
      { route_id: "default-r", provider: "openai", reason: "disabled", message: "off" },
      snapWithProfile,
      {},
      actions,
    );
    expect(directOutcome).toBe("switched");
    expect(actions.bindProvider).toHaveBeenCalledWith("openai", DIRECT_ROUTE_ID);
  });

  it("Low #7: ConnectScreen в layout='default' держит не более 1 primary CTA даже при нескольких истекающих маршрутах", () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const expiringRoutes: RouteView[] = [
      { ...makeRoute("exp-1", "NL", "185.212.102.40", "Амстердам"), expires_at: nowSec + 3600 },
      { ...makeRoute("exp-2", "DE", "145.241.12.8", "Франкфурт"), expires_at: nowSec - 60, status: "expired" },
    ];
    const htmlWithExpiring = renderToStaticMarkup(
      createElement(ConnectScreen, {
        state: null,
        routesSnapshot: {
          routes: expiringRoutes,
          default_route_id: "exp-1",
          provider_routes: {},
          effective: {},
          dangling: [],
        },
        currentIp: "95.165.10.22",
        currentCountry: "RU",
        onRefreshState: vi.fn(async () => {}),
        onOpenGuide: vi.fn(),
        onToast: vi.fn(),
      }),
    );
    expect((htmlWithExpiring.match(/zs-btn--primary/g) ?? []).length).toBeLessThanOrEqual(1);

    const htmlEmpty = renderToStaticMarkup(
      createElement(ConnectScreen, {
        state: null,
        routesSnapshot: {
          routes: [],
          default_route_id: null,
          provider_routes: {},
          effective: {},
          dangling: [],
        },
        currentIp: "95.165.10.22",
        currentCountry: "RU",
        onRefreshState: vi.fn(async () => {}),
        onOpenGuide: vi.fn(),
        onToast: vi.fn(),
      }),
    );
    expect((htmlEmpty.match(/zs-btn--primary/g) ?? []).length).toBeLessThanOrEqual(1);
  });

  it("§7.2: RouteListSection показывает кнопку обновления подписки при has_sub_url и снимает бейдж истечения при grace_extended", () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const subRoute: RouteView = {
      ...makeRoute("sub-1", "NL", "185.212.102.40", "Подписка NL"),
      has_sub_url: true,
      expires_at: nowSec + 86_400 * 10,
    };
    const graceRoute: RouteView = {
      ...makeRoute("legacy-1", "DE", "145.241.12.8", "Старый ключ"),
      expires_at: nowSec - 3600,
      status: "active",
      grace_extended: true,
      has_sub_url: false,
    };

    const html = renderToStaticMarkup(
      createElement(ConnectScreen, {
        state: null,
        routesSnapshot: {
          routes: [subRoute, graceRoute],
          default_route_id: "sub-1",
          provider_routes: {},
          effective: {},
          dangling: [],
        },
        currentIp: "95.165.10.22",
        currentCountry: "RU",
        onRefreshState: vi.fn(async () => {}),
        onOpenGuide: vi.fn(),
        onToast: vi.fn(),
      }),
    );

    expect(html).toContain(copy.key.refreshSub);
    expect(html).toContain(copy.key.graceExtendedBadge);
    expect(html).not.toContain(copy.key.expired);
  });

  it("Bug #3: уточняет Timeweb как РФ-узел, честный статический IP и 1-строчный ориентир в ConnectSalesCards", () => {
    const timeweb = HOSTINGS.find((h) => h.id === "timeweb");
    const hostvds = HOSTINGS.find((h) => h.id === "hostvds");
    expect(timeweb?.sub).toContain("РФ-узел для Каскада");
    expect(timeweb?.sub).toContain("180 ₽/мес");
    expect(hostvds?.sub).toContain("Зарубежный VPS (NL, US, FI)");
    expect(hostvds?.sub).toContain("190 ₽/мес");

    const benefitsText = PROMO_COPY.keyBenefits.join(" ");
    expect(benefitsText).not.toContain("резидентский");
    expect(benefitsText).toContain("Выделенный статический IP с высоким доверием (один и тот же адрес)");

    const salesHtml = renderToStaticMarkup(
      createElement(ConnectSalesCards, {
        routes: [],
        hasRoutes: false,
        isLegacyConfigured: false,
        inputKey: "",
        addScope: "all",
        error: null,
        connecting: false,
        onInputKeyChange: vi.fn(),
        onAddScopeChange: vi.fn(),
        onAddKey: vi.fn(),
        onOpenGuide: vi.fn(),
      }),
    );
    expect(salesHtml).toContain(PROMO_COPY.salesOrientation);
    expect(salesHtml).toContain("РФ-узел для Каскада");
  });
});
