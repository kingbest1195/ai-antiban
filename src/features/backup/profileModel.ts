import type { ClaudeProfile, RouteView } from "../../types";
import { backup as copy } from "../../shared/copy/ru";
import { formatRouteBadgeLabel } from "../../shared/lib/country";
import { decodeZastavaKeyPreview } from "../../shared/lib/zastavaKey";

export const KEY_OPTION_NONE = "__none__";
export const KEY_OPTION_NEW = "__new__";

export function hasProfileKeyBinding(
  p: Pick<ClaudeProfile, "bound_upstream_key" | "bound_route_id">,
): boolean {
  return Boolean(p.bound_upstream_key || p.bound_route_id);
}

export function isProfileRouteMissing(
  p: Pick<ClaudeProfile, "bound_upstream_key" | "bound_route_id">,
  availableRoutes: Pick<RouteView, "id">[],
  routesLoaded: boolean,
): boolean {
  if (!routesLoaded || p.bound_upstream_key || !p.bound_route_id) return false;
  return !availableRoutes.some((r) => r.id === p.bound_route_id);
}

export function resolveCreateProfileIpBinding(
  bindCurrentOnCreate: boolean,
  ipKnown: boolean,
  currentIp: string,
  currentCountry: string,
  createKeyChoice: string,
): { ip: string | null; country: string | null } {
  if (createKeyChoice !== KEY_OPTION_NONE) {
    return { ip: null, country: null };
  }
  return {
    ip: bindCurrentOnCreate && ipKnown ? currentIp : null,
    country: bindCurrentOnCreate && ipKnown && currentCountry !== "--" ? currentCountry : null,
  };
}

export function resolveInitialBindChoice(
  p: Pick<ClaudeProfile, "bound_upstream_key" | "bound_route_id">,
  availableRoutes: Pick<RouteView, "id">[],
): { choice: string; keyInput: string } {
  if (p.bound_route_id && availableRoutes.some((r) => r.id === p.bound_route_id)) {
    return { choice: p.bound_route_id, keyInput: "" };
  }
  if (p.bound_upstream_key) {
    return { choice: KEY_OPTION_NEW, keyInput: p.bound_upstream_key };
  }
  return { choice: KEY_OPTION_NONE, keyInput: "" };
}

export function resolveBoundBadge(
  p: ClaudeProfile,
  routes: RouteView[],
  routesLoaded: boolean,
): { text: string; tone: "info" | "danger" } | null {
  const t = copy.profiles;
  if (!p.bound_upstream_key && !p.bound_route_id) return null;
  if (isProfileRouteMissing(p, routes, routesLoaded)) {
    return { text: "Маршрут удалён", tone: "danger" };
  }
  if (p.bound_route_id) {
    const match = routes.find((r) => r.id === p.bound_route_id);
    if (match) {
      return { text: t.keyBoundLabel(formatRouteBadgeLabel(match.label, match.country)), tone: "info" };
    }
  }
  if (p.bound_upstream_key) {
    const preview = decodeZastavaKeyPreview(p.bound_upstream_key);
    if (preview?.label) {
      return { text: t.keyBoundLabel(formatRouteBadgeLabel(preview.label, preview.country)), tone: "info" };
    }
    if (preview?.entrySummary) {
      return { text: t.keyBoundLabel(preview.entrySummary), tone: "info" };
    }
  }
  return { text: t.keyBound, tone: "info" };
}

/** Форматирует длительность паузы смены IP как `H:MM:SS` (например, `4:00:00`). */
export function formatCooldownDuration(totalSeconds: number): string {
  const clamped = Math.max(0, Math.floor(totalSeconds));
  const h = Math.floor(clamped / 3600);
  const m = Math.floor((clamped % 3600) / 60);
  const s = clamped % 60;
  return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

/** Форматирует обратный отсчёт паузы смены IP как `HH:MM:SS` (например, `03:59:42`). */
export function formatCooldownHms(totalSeconds: number): string {
  const clamped = Math.max(0, Math.floor(totalSeconds));
  const h = Math.floor(clamped / 3600);
  const m = Math.floor((clamped % 3600) / 60);
  const s = clamped % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}
