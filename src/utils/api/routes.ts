import type {
  ProviderId,
  RoutesSnapshot,
  RouteTestResult,
  RouteView,
  UpstreamProxyConfig,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";
import {
  DIRECT_ROUTE_ID,
  mockRoutesSnapshot,
  mockState,
  recomputeMockEffective,
} from "./mocks/state";

export { DIRECT_ROUTE_ID };

export async function setUpstreamProxy(key: string): Promise<UpstreamProxyConfig> {
  if (isTauri()) {
    return await tauriInvoke<UpstreamProxyConfig>("set_upstream_proxy", { key });
  }
  const cfg: UpstreamProxyConfig = {
    enabled: true,
    raw_key: key,
    protocol: "http",
    host: "185.212.102.40",
    port: 8899,
    label: "Zastava Upstream Clean NL",
  };
  mockState.upstream_proxy = cfg;
  return cfg;
}

export async function toggleUpstreamProxy(
  enabled: boolean,
): Promise<UpstreamProxyConfig | null> {
  if (isTauri()) {
    return await tauriInvoke<UpstreamProxyConfig | null>("toggle_upstream_proxy", {
      enabled,
    });
  }
  if (mockState.upstream_proxy) {
    mockState.upstream_proxy.enabled = enabled;
    return { ...mockState.upstream_proxy };
  }
  return null;
}

export async function clearUpstreamProxy(): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("clear_upstream_proxy");
  }
  mockState.upstream_proxy = null;
  return true;
}

export async function getRoutesSnapshot(): Promise<RoutesSnapshot> {
  if (isTauri()) {
    return await tauriInvoke<RoutesSnapshot>("list_routes");
  }
  return {
    ...mockRoutesSnapshot,
    routes: [...mockRoutesSnapshot.routes],
    provider_routes: { ...mockRoutesSnapshot.provider_routes },
    effective: { ...mockRoutesSnapshot.effective },
    dangling: [...mockRoutesSnapshot.dangling],
  };
}

export async function upsertRoute(
  rawKey: string,
  label?: string | null,
  setAsDefault?: boolean,
): Promise<RouteView> {
  if (isTauri()) {
    const view = await tauriInvoke<RouteView>("add_route", { key: rawKey });
    if (setAsDefault) {
      await tauriInvoke("set_default_route", { routeId: view.id });
    }
    return view;
  }

  const trimmed = rawKey.trim();
  const id = `r-${Math.random().toString(16).slice(2, 10)}`;
  const displayLabel =
    label && label.trim().length > 0
      ? label.trim()
      : trimmed.startsWith("zastava://")
      ? "ВПН Заставы"
      : trimmed.replace(/^[a-z0-9]+:\/\//i, "").split(/[/@]/)[0] || "Шлюз";

  const newRoute: RouteView = {
    id,
    label: displayLabel,
    country: "NL",
    exit_ip: "185.212.102.40",
    expires_at: null,
    enabled: true,
    added_at: Math.floor(Date.now() / 1000),
    entries: [
      {
        proto: trimmed.startsWith("socks5")
          ? "socks5"
          : trimmed.startsWith("https")
          ? "https"
          : "http",
        host: "185.212.102.40",
        port: 1080,
        username: null,
        has_password: false,
        sni: null,
      },
    ],
    status: "active",
    is_default: Boolean(setAsDefault || mockRoutesSnapshot.routes.length === 0),
    bound_providers: [],
    is_profile_route: false,
    health: {
      reachable: true,
      last_error: null,
      observed_exit_ip: "185.212.102.40",
      observed_country: "NL",
      exit_ip_matches: true,
      latency_ms: 32,
      checked_at: Math.floor(Date.now() / 1000),
    },
  };

  mockRoutesSnapshot.routes.push(newRoute);
  if (newRoute.is_default) {
    mockRoutesSnapshot.default_route_id = newRoute.id;
    for (const r of mockRoutesSnapshot.routes) {
      r.is_default = r.id === newRoute.id;
    }
    recomputeMockEffective();
  }

  return newRoute;
}

export async function removeRoute(routeId: string): Promise<RoutesSnapshot> {
  if (isTauri()) {
    return await tauriInvoke<RoutesSnapshot>("remove_route", { id: routeId });
  }

  mockRoutesSnapshot.routes = mockRoutesSnapshot.routes.filter((r) => r.id !== routeId);
  if (mockRoutesSnapshot.default_route_id === routeId) {
    mockRoutesSnapshot.default_route_id = null;
  }
  for (const [p, rid] of Object.entries(mockRoutesSnapshot.provider_routes)) {
    if (rid === routeId) {
      delete mockRoutesSnapshot.provider_routes[p];
    }
  }
  recomputeMockEffective();
  return getRoutesSnapshot();
}

export async function setRouteEnabled(
  routeId: string,
  enabled: boolean,
): Promise<RoutesSnapshot> {
  if (isTauri()) {
    return await tauriInvoke<RoutesSnapshot>("set_route_enabled", {
      id: routeId,
      enabled,
    });
  }

  const r = mockRoutesSnapshot.routes.find((item) => item.id === routeId);
  if (r) {
    r.enabled = enabled;
    r.status = enabled ? "active" : "disabled";
  }
  return getRoutesSnapshot();
}

export async function setDefaultRoute(routeId: string | null): Promise<RoutesSnapshot> {
  if (isTauri()) {
    return await tauriInvoke<RoutesSnapshot>("set_default_route", { routeId });
  }

  mockRoutesSnapshot.default_route_id = routeId;
  for (const r of mockRoutesSnapshot.routes) {
    r.is_default = r.id === routeId;
  }
  recomputeMockEffective();
  return getRoutesSnapshot();
}

export async function bindProviderRoute(
  provider: ProviderId,
  target: string,
): Promise<RoutesSnapshot> {
  const routeId =
    target === "default"
      ? null
      : target === "direct" || target === DIRECT_ROUTE_ID
      ? DIRECT_ROUTE_ID
      : target;
  if (isTauri()) {
    return await tauriInvoke<RoutesSnapshot>("bind_provider_route", {
      provider,
      routeId,
    });
  }

  if (routeId === null) {
    delete mockRoutesSnapshot.provider_routes[provider];
  } else {
    mockRoutesSnapshot.provider_routes[provider] = routeId;
  }

  recomputeMockEffective();
  return getRoutesSnapshot();
}

export async function testRoute(rawOrId: string): Promise<RouteTestResult> {
  if (isTauri()) {
    return await tauriInvoke<RouteTestResult>("test_route", { id: rawOrId });
  }

  return {
    ok: true,
    exit_ip: "185.212.102.40",
    country: "NL",
    latency_ms: 38,
    exit_ip_matches: true,
    error: null,
  };
}
