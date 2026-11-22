import type { CleanProfileStatus, CleanRoomProfile, RouteView } from "../../types";
import type { BadgeTone } from "../../ui";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";
import { formatRouteOptionLabel } from "../../shared/lib/country";
import { formatIp } from "../../shared/lib/format";

export const DIRECT_VALUE = "__direct__";

export const STATUS_TONE: Record<CleanProfileStatus, BadgeTone> = {
  active: "info",
  warming_up: "warn",
  ready: "ok",
  tainted: "danger",
};

/** Возвращает причину блокировки запуска песочницы или null, если запуск разрешён. */
export function resolveSandboxBlockReason(
  profile: Pick<CleanRoomProfile, "status">,
  readyToLaunch: boolean,
  manualKillswitch: boolean,
): string | null {
  if (manualKillswitch) return copy.sandbox.profileCard.blockedReasonKillswitch;
  if (profile.status === "tainted") return copy.sandbox.profileCard.blockedReasonTainted;
  if (!readyToLaunch) return copy.sandbox.profileCard.blockedReasonAudit;
  return null;
}

export function providerLabel(provider: string): string {
  const key = provider.toLowerCase();
  if (key === "anthropic" || key === "claude") return copy.sandbox.providers.anthropic;
  if (key === "openai" || key === "chatgpt") return copy.sandbox.providers.openai;
  if (key === "gemini") return copy.sandbox.providers.gemini;
  return copy.sandbox.providers.custom;
}

export function resolveBoundRouteLabel(
  boundRouteId: string | null,
  routes: readonly RouteView[],
  hideIpMode: boolean,
): string {
  if (!boundRouteId) return copy.sandbox.profileCard.routeDirect;
  const found = routes.find((r) => r.id === boundRouteId);
  if (!found) return copy.sandbox.profileCard.routeMissing;
  return formatRouteOptionLabel({
    label: found.label,
    country: found.country,
    ipOrHost: found.exit_ip ? formatIp(found.exit_ip, hideIpMode) : null,
    fallbackLabel: found.id,
  });
}
