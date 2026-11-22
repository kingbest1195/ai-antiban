import type { ProviderId, RouteUnavailablePayload, RouteView, RoutesSnapshot } from "../../types";
import {
  DIRECT_ROUTE_ID,
  bindProviderRoute,
  bindRouteToClaudeProfile,
  listClaudeProfiles,
  setDefaultRoute,
  setRouteEnabled,
} from "../../utils/api";
import { connect as copy } from "../../shared/copy/ru";

export const ALL_PROVIDERS: ProviderId[] = ["anthropic", "openai", "gemini"];

export interface RouteDisableUsage {
  inUse: boolean;
  isProfileRoute: boolean;
  isDefaultRoute: boolean;
  explicitProviders: ProviderId[];
  affected: "all" | ProviderId[];
}

export interface PendingDisableRoute {
  routeId: string;
  routeLabel: string;
  usage: RouteDisableUsage;
}

/** Возвращает сервисы, на которые влияет маршрут (с учётом приоритета `profile_route_id`), или `"all"`. */
export function getAffectedProvidersForRoute(
  routeId: string,
  snapshot: RoutesSnapshot | null | undefined,
): "all" | ProviderId[] {
  if (!snapshot) return "all";
  const affected = ALL_PROVIDERS.filter((p) => {
    if (p === "anthropic" && snapshot.profile_route_id) {
      return snapshot.profile_route_id === routeId;
    }
    const explicit = snapshot.provider_routes[p];
    return explicit === routeId || (!explicit && snapshot.default_route_id === routeId);
  });
  return affected.length === ALL_PROVIDERS.length ? "all" : affected;
}

/** Определяет, какие сервисы, default-маршрут и активный профиль Claude завязаны на маршрут. */
export function inspectRouteUsageForDisable(
  routeId: string,
  snapshot: RoutesSnapshot | null | undefined,
  routes: RouteView[],
): RouteDisableUsage {
  const affected = getAffectedProvidersForRoute(routeId, snapshot);
  const route = routes.find((r) => r.id === routeId);

  if (!snapshot) {
    const explicitProviders = (route?.bound_providers ?? []).filter((p): p is ProviderId =>
      ALL_PROVIDERS.includes(p as ProviderId),
    );
    const isProfileRoute = Boolean(route?.is_profile_route);
    const isDefaultRoute = Boolean(route?.is_default);
    return {
      inUse: isProfileRoute || isDefaultRoute || explicitProviders.length > 0,
      isProfileRoute,
      isDefaultRoute,
      explicitProviders,
      affected,
    };
  }

  const isProfileRoute = snapshot.profile_route_id === routeId;
  const isDefaultRoute = snapshot.default_route_id === routeId;
  const explicitProviders = ALL_PROVIDERS.filter((p) => snapshot.provider_routes[p] === routeId);
  const hasAffected = affected === "all" || affected.length > 0;

  return {
    inUse: isProfileRoute || isDefaultRoute || explicitProviders.length > 0 || hasAffected,
    isProfileRoute,
    isDefaultRoute,
    explicitProviders,
    affected,
  };
}

/** Формирует человекочитаемый список затронутых привязок для модального окна отключения маршрута. */
export function formatRouteUsageSummary(usage: RouteDisableUsage): string {
  const parts: string[] = [];
  if (usage.isProfileRoute) {
    parts.push(copy.key.profileBadge);
  }
  if (usage.isDefaultRoute) {
    parts.push(copy.routes.default);
  }
  const explicitNotDuplicate =
    usage.affected === "all"
      ? ALL_PROVIDERS
      : Array.from(new Set([...usage.explicitProviders, ...usage.affected]));
  for (const p of explicitNotDuplicate) {
    if (p === "anthropic" && usage.isProfileRoute && !usage.explicitProviders.includes("anthropic")) {
      continue;
    }
    parts.push(copy.routes.services[p]);
  }
  return parts.length > 0 ? parts.join(", ") : copy.routes.default;
}

export interface RouteBindActions {
  bindProvider: typeof bindProviderRoute;
  setDefault: typeof setDefaultRoute;
  setEnabled: typeof setRouteEnabled;
  listProfiles: typeof listClaudeProfiles;
  bindProfileRoute: typeof bindRouteToClaudeProfile;
}

const DEFAULT_ACTIONS: RouteBindActions = {
  bindProvider: bindProviderRoute,
  setDefault: setDefaultRoute,
  setEnabled: setRouteEnabled,
  listProfiles: listClaudeProfiles,
  bindProfileRoute: bindRouteToClaudeProfile,
};

/** Снимает привязки маршрута (кроме `profile_route_id`, для него нужно отдельное подтверждение) и переводит их в Direct. */
export async function disableRouteAndSwitchBindingsToDirect(
  pending: PendingDisableRoute,
  actions: RouteBindActions = DEFAULT_ACTIONS,
): Promise<void> {
  if (pending.usage.isProfileRoute) {
    throw new Error("profile_route_id requires explicit profile reset confirmation");
  }
  for (const provider of pending.usage.explicitProviders) {
    await actions.bindProvider(provider, DIRECT_ROUTE_ID);
  }
  if (pending.usage.isDefaultRoute) {
    await actions.setDefault(null);
  }
  await actions.setEnabled(pending.routeId, false);
}

/** Сбрасывает `profile_route_id` активного профиля (после явного подтверждения), переводит привязки в Direct и выключает маршрут. */
export async function resetProfileRouteAndDisable(
  pending: PendingDisableRoute,
  actions: RouteBindActions = DEFAULT_ACTIONS,
): Promise<void> {
  const list = await actions.listProfiles();
  if (list.active_profile_id) {
    await actions.bindProfileRoute(list.active_profile_id, null);
  }
  for (const provider of pending.usage.explicitProviders) {
    await actions.bindProvider(provider, DIRECT_ROUTE_ID);
  }
  if (pending.usage.isDefaultRoute) {
    await actions.setDefault(null);
  }
  await actions.setEnabled(pending.routeId, false);
}

export function isRouteDisabledReason(reason: string | null | undefined): boolean {
  return (reason ?? "").trim().toLowerCase() === "disabled";
}

export function bannerRequiresProfileConfirmation(
  banner: RouteUnavailablePayload,
  snapshot: RoutesSnapshot | null | undefined,
): boolean {
  return (
    banner.provider.toLowerCase() === "anthropic" &&
    Boolean(snapshot?.profile_route_id) &&
    snapshot?.profile_route_id === banner.route_id
  );
}

/** Выполняет 1-click перевод заблокированного провайдера на свой VPN (Direct) из баннера `routeUnavailableBanner`. */
export async function switchUnavailableBannerToDirect(
  banner: RouteUnavailablePayload,
  snapshot: RoutesSnapshot | null | undefined,
  opts: { allowProfileReset?: boolean } = {},
  actions: RouteBindActions = DEFAULT_ACTIONS,
): Promise<"switched" | "needs_profile_confirmation"> {
  const needsProfileReset = bannerRequiresProfileConfirmation(banner, snapshot);
  if (needsProfileReset && !opts.allowProfileReset) {
    return "needs_profile_confirmation";
  }

  if (needsProfileReset) {
    const list = await actions.listProfiles();
    if (list.active_profile_id) {
      await actions.bindProfileRoute(list.active_profile_id, null);
    }
  }

  const provider = banner.provider.toLowerCase() as ProviderId;
  if (ALL_PROVIDERS.includes(provider)) {
    await actions.bindProvider(provider, DIRECT_ROUTE_ID);
  }

  return "switched";
}

/** Определяет страну выхода для сервиса по выбранной привязке маршрута или текущему VPN. */
export function resolveProviderExitCountry(
  providerId: ProviderId,
  snapshot: RoutesSnapshot | null | undefined,
  routes: RouteView[],
  currentCountry: string,
): string {
  const explicitBinding = snapshot?.provider_routes[providerId];
  if (explicitBinding === DIRECT_ROUTE_ID) return currentCountry;
  const routeId = explicitBinding || snapshot?.default_route_id || "";
  if (routeId) {
    const bound = routes.find((r) => r.id === routeId);
    if (bound) return bound.country ?? "";
  }
  return currentCountry;
}
