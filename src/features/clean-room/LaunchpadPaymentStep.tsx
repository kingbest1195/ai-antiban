import type { ShowToast } from "../../shared/hooks";
import { PaymentFlowPanel, type PaymentScenarioFlow } from "../subscription/PaymentFlowPanel";

export interface LaunchpadPaymentStepProps {
  initialFlow?: PaymentScenarioFlow;
  profileId?: string | null;
  routeId?: string | null;
  exitIp?: string | null;
  exitAsn?: number | null;
  exitCountry?: string;
  hideIpMode?: boolean;
  inCleanRoom?: boolean;
  warmupStartedAt?: number | null;
  compactPrimary?: boolean;
  onNavigateToPaymentGuide?: () => void;
  onStateUpdated?: () => Promise<unknown> | void;
  onToast?: ShowToast;
}

/** Общая панель оплаты для Шага 4 запуска аккаунта и быстрой вкладки «Оплата и прогрев». */
export function LaunchpadPaymentStep({
  initialFlow = "app_store",
  profileId,
  routeId,
  exitIp,
  exitAsn,
  exitCountry = "",
  hideIpMode = false,
  inCleanRoom,
  warmupStartedAt,
  compactPrimary = true,
  onNavigateToPaymentGuide,
  onStateUpdated,
  onToast,
}: LaunchpadPaymentStepProps) {
  const cleanExitCountry = exitCountry && exitCountry !== "--" ? exitCountry : "";
  const resolvedInCleanRoom = inCleanRoom ?? Boolean(profileId);

  return (
    <PaymentFlowPanel
      initialFlow={initialFlow}
      profileId={profileId}
      routeId={routeId}
      exitIp={exitIp}
      exitAsn={exitAsn}
      exitCountry={cleanExitCountry}
      hideIpMode={hideIpMode}
      inCleanRoom={resolvedInCleanRoom}
      warmupStartedAt={warmupStartedAt}
      compactPrimary={compactPrimary}
      onNavigateToPaymentGuide={onNavigateToPaymentGuide}
      onStateUpdated={onStateUpdated}
      onToast={onToast}
    />
  );
}
