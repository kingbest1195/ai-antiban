import { useCallback, useState } from "react";
import type { ProviderId } from "../../types";
import type { SosBranchId } from "../../features/sos";
import type { CleanRoomTab } from "../../features/clean-room";

export type TabId = "overview" | "connect" | "checks" | "backup" | "guides";

export const TAB_ORDER: TabId[] = ["overview", "connect", "checks", "backup", "guides"];

/** Гайд, который открывается, если вызвавший не указал другой. */
export const DEFAULT_GUIDE = "01-personal-vpn-15min";

export type ShellPage =
  | "home"
  | "services"
  | "clean-room"
  | "backup"
  | "connect"
  | "checks"
  | "guides"
  | "stats";

export interface Route {
  page: ShellPage;
  checksProvider?: ProviderId;
  checksSubTab?: "checks" | "guides";
  guideRef?: string;
  cleanRoomTab?: CleanRoomTab;
  cleanRoomStep?: number;
  sosBranch?: SosBranchId;
}

const HOME_ROUTE: Route = { page: "home" };

function routesEqual(a: Route, b: Route): boolean {
  return (
    a.page === b.page &&
    a.checksProvider === b.checksProvider &&
    a.checksSubTab === b.checksSubTab &&
    a.guideRef === b.guideRef &&
    a.cleanRoomTab === b.cleanRoomTab &&
    a.cleanRoomStep === b.cleanRoomStep &&
    a.sosBranch === b.sosBranch
  );
}

/** Добавляет маршрут в стек, не дублируя идентичную вершину стека. */
export function pushRoute(stack: readonly Route[], next: Route): Route[] {
  const base = stack.length > 0 ? stack : [HOME_ROUTE];
  const top = base[base.length - 1];
  if (next.page === "home") return [HOME_ROUTE];
  if (top && routesEqual(top, next)) return [...base];
  return [...base, next];
}

/** Возвращается на предыдущий маршрут в стеке, сохраняя его параметры. */
export function popRoute(stack: readonly Route[]): Route[] {
  if (stack.length <= 1) return [HOME_ROUTE];
  return stack.slice(0, -1);
}

/** Сбрасывает стек до главного экрана или указанного маршрута. */
export function resetRouteStack(route?: Route): Route[] {
  if (!route || route.page === "home") return [HOME_ROUTE];
  return [HOME_ROUTE, route];
}

/** ?tab= понимает и старые id вкладок (pulse, clean-ip, claude_vault, bin, audit, guide), и новые. */
function readInitialStack(): Route[] {
  if (typeof window === "undefined") return [HOME_ROUTE];
  const raw = new URLSearchParams(window.location.search).get("tab");
  switch (raw) {
    case "connect":
    case "clean-ip":
      return [HOME_ROUTE, { page: "connect" }];
    case "checks":
    case "audit":
      return [HOME_ROUTE, { page: "checks" }];
    case "backup":
    case "claude_vault":
      return [HOME_ROUTE, { page: "backup" }];
    case "guides":
    case "guide":
      return [HOME_ROUTE, { page: "guides", guideRef: DEFAULT_GUIDE }];
    case "clean-room":
      return [HOME_ROUTE, { page: "clean-room", cleanRoomTab: "launchpad" }];
    case "bin":
    case "subscription":
      return [HOME_ROUTE, { page: "clean-room", cleanRoomTab: "payment" }];
    case "overview":
    case "pulse":
    default:
      return [HOME_ROUTE];
  }
}

function pageToTab(page: ShellPage): TabId {
  if (page === "connect" || page === "checks" || page === "backup" || page === "guides") {
    return page;
  }
  return "overview";
}

/** Стек навигации оболочки v3 с сохранением параметров маршрута и обратной совместимостью goTab/openGuide. */
export function useNavigation() {
  const [navStack, setNavStack] = useState<Route[]>(readInitialStack);
  const [guideTarget, setGuideTarget] = useState<string>(DEFAULT_GUIDE);
  const [cleanRoomNavKey, setCleanRoomNavKey] = useState(0);
  const [guideNavKey, setGuideNavKey] = useState(0);
  const [sosNavKey, setSosNavKey] = useState(0);

  const currentRoute = navStack[navStack.length - 1] ?? HOME_ROUTE;
  const tab = pageToTab(currentRoute.page);
  const checksProvider = currentRoute.checksProvider;
  const subscriptionOpen = currentRoute.page === "clean-room" && currentRoute.cleanRoomTab === "payment";

  const bumpTargetKeys = useCallback((route?: Route) => {
    if (!route) return;
    if (route.page === "clean-room") setCleanRoomNavKey((k) => k + 1);
    if (route.page === "guides" || route.checksSubTab === "guides") setGuideNavKey((k) => k + 1);
    if (route.page === "backup") setSosNavKey((k) => k + 1);
  }, []);

  const push = useCallback((route: Route) => {
    if (route.guideRef) setGuideTarget(route.guideRef);
    bumpTargetKeys(route);
    setNavStack((prev) => pushRoute(prev, route));
  }, [bumpTargetKeys]);

  const pop = useCallback(() => {
    setNavStack((prev) => popRoute(prev));
  }, []);

  const goHome = useCallback(() => {
    setNavStack([HOME_ROUTE]);
  }, []);

  const reset = useCallback((route?: Route) => {
    if (route?.guideRef) setGuideTarget(route.guideRef);
    bumpTargetKeys(route);
    setNavStack(resetRouteStack(route));
  }, [bumpTargetKeys]);

  const goTab = useCallback((next: TabId, opts?: { provider?: ProviderId }) => {
    if (next === "overview") {
      setNavStack([HOME_ROUTE]);
      return;
    }
    if (next === "checks") {
      setNavStack((prev) => pushRoute(prev, { page: "checks", checksProvider: opts?.provider }));
      return;
    }
    const nextRoute: Route = { page: next };
    bumpTargetKeys(nextRoute);
    setNavStack((prev) => pushRoute(prev, nextRoute));
  }, [bumpTargetKeys]);

  /** Открывает «Гайды», сохраняя предыдущий экран в navStack для кнопки «Назад». */
  const openGuide = useCallback(
    (guideId?: string) => {
      const target = guideId || guideTarget || DEFAULT_GUIDE;
      setGuideTarget(target);
      setGuideNavKey((k) => k + 1);
      setNavStack((prev) => pushRoute(prev, { page: "guides", guideRef: target }));
    },
    [guideTarget],
  );

  const openSubscription = useCallback(() => {
    setCleanRoomNavKey((k) => k + 1);
    setNavStack((prev) => pushRoute(prev, { page: "clean-room", cleanRoomTab: "payment" }));
  }, []);

  const closeSubscription = useCallback(() => {
    setNavStack((prev) => popRoute(prev));
  }, []);

  return {
    navStack,
    currentRoute,
    canGoBack: navStack.length > 1,
    push,
    pop,
    goHome,
    reset,
    tab,
    goTab,
    checksProvider,
    subscriptionOpen,
    openSubscription,
    closeSubscription,
    guideTarget: currentRoute.guideRef ?? guideTarget,
    cleanRoomNavKey,
    guideNavKey,
    sosNavKey,
    openGuide,
  };
}
