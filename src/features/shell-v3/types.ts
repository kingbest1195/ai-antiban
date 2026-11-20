import type { CoworkGuardWatcherState } from "../../shared/hooks/useCoworkGuardWatcher";
import type { Route } from "../../shared/hooks";
import type {
  AppStateData,
  GatewayStatsSnapshot,
  PersonaRiskReport,
  ProviderId,
  RouteUnavailablePayload,
  RoutesSnapshot,
  UpdateCheckResult,
} from "../../types";
import type { MenuEntry } from "../../ui";
import type { OverviewScreenProps } from "../overview/OverviewScreen";
import type { useOverviewModel } from "../overview/useOverviewModel";

export type ShellV3SectionId = "services" | "clean-room" | "backup" | "connect" | "checks";

export interface OverviewView {
  loading: boolean;
  failed: boolean;
  progress: { done: number; total: number };
  model: ReturnType<typeof useOverviewModel>;
}

export interface ShellV3HeaderProps {
  pingMs: number | null;
  refreshing: boolean;
  onRescan: () => void;
  hideIpMode: boolean;
  onToggleHideIp: () => void;
  updateInfo: UpdateCheckResult | null;
  onOpenUpdate: () => void;
  menuItems: MenuEntry[];
}

export interface AlertStripProps {
  view: OverviewView;
  overview: OverviewScreenProps;
  coworkGuard: CoworkGuardWatcherState;
  ipChangeCooldownUntil?: number | null;
  routeUnavailableBanner: RouteUnavailablePayload | null;
  routesSnapshot?: RoutesSnapshot | null;
  onPushRoute: (route: Route) => void;
  onDismissRouteUnavailable: () => void;
  onRefreshRoutes: () => Promise<unknown>;
  onRefreshState: () => Promise<unknown>;
  onAuditRefresh: (providerId?: ProviderId) => Promise<void> | void;
  onOpenAbout?: () => void;
}

export interface HomeHubProps {
  overview: OverviewScreenProps;
  view: OverviewView;
  togglingSysproxy: boolean;
  coworkGuard: CoworkGuardWatcherState;
  personaRisk: PersonaRiskReport | null;
  gatewayStats: GatewayStatsSnapshot | null;
  state: AppStateData | null;
  routeUnavailableBanner: RouteUnavailablePayload | null;
  onPushRoute: (route: Route) => void;
  onDismissRouteUnavailable: () => void;
  onRefreshRoutes: () => Promise<unknown>;
  onRefreshState: () => Promise<unknown>;
  onAuditRefresh: (providerId?: ProviderId) => Promise<void> | void;
  version: string;
}
