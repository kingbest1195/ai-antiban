import { useState } from "react";
import type { AppStateData, RiskReport } from "../../types";
import { Segmented } from "../../ui";
import { subscription as copy } from "../../shared/copy/ru";
import type { ShowToast } from "../../shared/hooks";
import { PaymentFlowPanel, type PaymentScenarioFlow } from "./PaymentFlowPanel";
import { Warmup, warmupProgress } from "./Warmup";
import "./subscription.css";

export interface SubscriptionScreenProps {
  vpnCountry?: string;
  activeReport?: RiskReport | null;
  state?: AppStateData | null;
  initialTab?: SubTab;
  initialFlow?: PaymentScenarioFlow;
  warmupStartedAt?: number | null;
  onStartWarmup?: () => Promise<unknown> | void;
  onStateChange?: () => void;
  onNavigateToPaymentGuide?: () => void;
  onToast?: ShowToast;
}

export type SubTab = "card" | "warmup";

/** Экран «Подписка» (меню «Ещё»): выбор сценария оплаты, адрес, защита маршрута и прогрев. */
export function SubscriptionScreen({
  vpnCountry,
  activeReport,
  state,
  initialTab = "card",
  initialFlow = "app_store",
  warmupStartedAt,
  onStartWarmup,
  onStateChange,
  onNavigateToPaymentGuide,
  onToast,
}: SubscriptionScreenProps) {
  const [tab, setTab] = useState<SubTab>(initialTab);

  const rawCountry =
    vpnCountry && vpnCountry !== "--" ? vpnCountry : activeReport?.telemetry.country_code;
  const country = rawCountry && rawCountry !== "--" ? rawCountry : "";
  const exitIp = activeReport?.telemetry.ip ?? state?.pinned_ip ?? null;
  const exitAsn = activeReport?.telemetry.asn ?? null;
  const profileId = state?.clean_room?.active_profile_id ?? null;
  const activeProfile = profileId
    ? state?.clean_room?.profiles.find((p) => p.id === profileId) ?? null
    : null;
  const inCleanRoom = Boolean(profileId);
  const effectiveWarmupStartedAt =
    warmupStartedAt !== undefined
      ? warmupStartedAt
      : (activeProfile?.warmup_started_at ?? state?.warmup_started_at ?? null);

  const warm = warmupProgress(effectiveWarmupStartedAt);
  const warmupLabel = warm.started
    ? warm.done
      ? copy.tabs.warmupDone
      : copy.tabs.warmupRunning
    : copy.tabs.warmup;

  return (
    <div className="zs-stack">
      <Segmented<SubTab>
        aria-label={copy.tabsLabel}
        value={tab}
        onChange={setTab}
        options={[
          { value: "card", label: copy.tabs.card },
          { value: "warmup", label: warmupLabel },
        ]}
      />

      {tab === "card" ? (
        <PaymentFlowPanel
          initialFlow={initialFlow}
          profileId={profileId}
          routeId={activeProfile?.bound_route_id ?? state?.default_route_id ?? null}
          exitIp={exitIp}
          exitAsn={exitAsn}
          exitCountry={country}
          hideIpMode={Boolean(state?.hide_ip_mode)}
          inCleanRoom={inCleanRoom}
          warmupStartedAt={effectiveWarmupStartedAt}
          onNavigateToPaymentGuide={onNavigateToPaymentGuide}
          onStateUpdated={onStateChange}
          onToast={onToast}
        />
      ) : (
        <Warmup
          state={state}
          warmupStartedAt={effectiveWarmupStartedAt}
          onStartWarmup={onStartWarmup}
          onStateChange={onStateChange}
          onNavigateToPaymentGuide={onNavigateToPaymentGuide}
          onToast={onToast}
        />
      )}
    </div>
  );
}
