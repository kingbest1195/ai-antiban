import { useCallback, useState } from "react";
import type { ProviderId } from "../../types";

export type TabId = "overview" | "connect" | "checks" | "backup" | "guides";

export const TAB_ORDER: TabId[] = ["overview", "connect", "checks", "backup", "guides"];

/** Гайд, который открывается, если вызвавший не указал другой. */
export const DEFAULT_GUIDE = "01-personal-vpn-15min";

interface Initial {
  tab: TabId;
  subscription: boolean;
}

/** ?tab= понимает и старые id вкладок (pulse, clean-ip, claude_vault, bin, audit, guide), и новые. */
function readInitial(): Initial {
  const raw = new URLSearchParams(window.location.search).get("tab");
  switch (raw) {
    case "overview":
    case "pulse":
      return { tab: "overview", subscription: false };
    case "connect":
    case "clean-ip":
      return { tab: "connect", subscription: false };
    case "checks":
    case "audit":
      return { tab: "checks", subscription: false };
    case "backup":
    case "claude_vault":
      return { tab: "backup", subscription: false };
    case "guides":
    case "guide":
      return { tab: "guides", subscription: false };
    case "bin":
    case "subscription":
      return { tab: "overview", subscription: true };
    default:
      return { tab: "overview", subscription: false };
  }
}

/** Навигация оболочки: вкладка, экран «Подписка» из меню «Ещё» и цель гайда. */
export function useNavigation() {
  const [initial] = useState(readInitial);
  const [tab, setTab] = useState<TabId>(initial.tab);
  const [subscriptionOpen, setSubscriptionOpen] = useState<boolean>(initial.subscription);
  const [guideTarget, setGuideTarget] = useState<string>(DEFAULT_GUIDE);

  /** Сервис, чей отчёт показывает «Проверки»; без него — худший из трёх. Сбрасывается при уходе с вкладки. */
  const [checksProvider, setChecksProvider] = useState<ProviderId | undefined>(undefined);

  const goTab = useCallback((next: TabId, opts?: { provider?: ProviderId }) => {
    setSubscriptionOpen(false);
    setChecksProvider(next === "checks" ? opts?.provider : undefined);
    setTab(next);
  }, []);

  /** Открывает «Гайды»; без id остаётся прежняя цель. */
  const openGuide = useCallback((guideId?: string) => {
    if (guideId) setGuideTarget(guideId);
    setSubscriptionOpen(false);
    setChecksProvider(undefined);
    setTab("guides");
  }, []);

  const openSubscription = useCallback(() => setSubscriptionOpen(true), []);
  const closeSubscription = useCallback(() => setSubscriptionOpen(false), []);

  return { tab, goTab, checksProvider, subscriptionOpen, openSubscription, closeSubscription, guideTarget, openGuide };
}
