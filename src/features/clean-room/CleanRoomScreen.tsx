import { useCallback, useEffect, useState } from "react";
import type {
  AppStateData,
  CleanRoomAuditReport,
  CleanRoomState,
  DetectedBrowser,
  RiskReport,
  RoutesSnapshot,
} from "../../types";
import {
  dismissHint,
  getRoutesSnapshot,
  listCleanProfiles,
  startCleanProfileWarmup,
} from "../../utils/api";
import { Segmented, HintCard } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";
import { CooldownBanner } from "../overview/CooldownBanner";
import { AddressCard } from "../subscription/AddressCard";
import { CardCheck } from "../subscription/CardCheck";
import { Warmup } from "../subscription/Warmup";
import "../subscription/subscription.css";
import { LaunchpadSteps } from "./LaunchpadSteps";
import { PreFlightAuditCard, isCleanRoomReadyToLaunch } from "./PreFlightAuditCard";
import { SandboxProfilesCard } from "./SandboxProfilesCard";
import "./cleanRoom.css";

export type CleanRoomTab = "launchpad" | "payment";

export interface CleanRoomScreenProps {
  state?: AppStateData | null;
  report?: RiskReport | null;
  routesSnapshot?: RoutesSnapshot | null;
  hideIpMode?: boolean;
  onNavigateToGuide?: (guideRef: string) => void;
  onNavigateToConnect?: () => void;
  onStateUpdated?: () => Promise<unknown> | void;
  initialTab?: CleanRoomTab;
  initialStep?: number;
  navKey?: number;
  manualKillswitch?: boolean;
  onDismissHint?: (hintId: string) => Promise<unknown> | void;
  toast?: ShowToast;
  /** Предзагруженные данные аудита и браузеров (для SSR/тестов и мгновенного рендера). */
  initialAudit?: CleanRoomAuditReport | null;
  initialBrowsers?: DetectedBrowser[];
}

const EMPTY_CLEAN_ROOM: CleanRoomState = {
  profiles: [],
  active_profile_id: null,
  tainted_ips: {},
};

/** Экран «Чистая комната»: Pre-Flight детектор, браузерная песочница, 4-шаговый Launchpad и быстрый вход «Оплата и прогрев». */
export function CleanRoomScreen({
  state,
  report,
  routesSnapshot: externalRoutes,
  hideIpMode = false,
  onNavigateToGuide,
  onNavigateToConnect,
  onStateUpdated,
  initialTab = "launchpad",
  initialStep,
  navKey,
  manualKillswitch: manualKillswitchProp,
  onDismissHint,
  toast,
  initialAudit,
  initialBrowsers,
}: CleanRoomScreenProps) {
  const [tab, setTab] = useState<CleanRoomTab>(initialTab);
  const [cleanState, setCleanState] = useState<CleanRoomState>(
    () => state?.clean_room ?? EMPTY_CLEAN_ROOM,
  );
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(
    () => state?.clean_room?.active_profile_id ?? state?.clean_room?.profiles[0]?.id ?? null,
  );
  const [routesSnap, setRoutesSnap] = useState<RoutesSnapshot | null>(externalRoutes ?? null);
  const [auditReport, setAuditReport] = useState<CleanRoomAuditReport | null | undefined>(
    initialAudit,
  );
  const [localDismissed, setLocalDismissed] = useState<string[]>(
    () => state?.dismissed_hints ?? [],
  );
  const [createTrigger, setCreateTrigger] = useState<number>(0);

  useEffect(() => {
    setTab(initialTab);
  }, [initialTab, navKey]);

  useEffect(() => {
    if (state?.clean_room) {
      setCleanState(state.clean_room);
      setSelectedProfileId((prev) =>
        prev && state.clean_room?.profiles.some((p) => p.id === prev)
          ? prev
          : (state.clean_room?.active_profile_id ?? state.clean_room?.profiles[0]?.id ?? null),
      );
    }
  }, [state?.clean_room]);

  useEffect(() => {
    if (state?.dismissed_hints) {
      setLocalDismissed(state.dismissed_hints);
    }
  }, [state?.dismissed_hints]);

  useEffect(() => {
    if (externalRoutes !== undefined) {
      setRoutesSnap(externalRoutes);
    }
  }, [externalRoutes]);

  const refreshCleanProfiles = useCallback(
    async (explicitNext?: CleanRoomState) => {
      if (explicitNext) {
        setCleanState(explicitNext);
        setSelectedProfileId((prev) =>
          prev && explicitNext.profiles.some((p) => p.id === prev)
            ? prev
            : (explicitNext.active_profile_id ?? explicitNext.profiles[0]?.id ?? null),
        );
      } else {
        try {
          const fresh = await listCleanProfiles();
          setCleanState(fresh);
          setSelectedProfileId((prev) =>
            prev && fresh.profiles.some((p) => p.id === prev)
              ? prev
              : (fresh.active_profile_id ?? fresh.profiles[0]?.id ?? null),
          );
        } catch {
          // Игнорируем в standalone-режиме без бэкенда
        }
      }
      await onStateUpdated?.();
    },
    [onStateUpdated],
  );

  useEffect(() => {
    if (!state?.clean_room) {
      void refreshCleanProfiles();
    }
  }, [state?.clean_room, refreshCleanProfiles]);

  useEffect(() => {
    if (externalRoutes === undefined) {
      void getRoutesSnapshot()
        .then(setRoutesSnap)
        .catch(() => {});
    }
  }, [externalRoutes]);

  const handleDismissHint = async (hintId: string) => {
    setLocalDismissed((prev) => (prev.includes(hintId) ? prev : [...prev, hintId]));
    try {
      if (onDismissHint) {
        await onDismissHint(hintId);
      } else {
        await dismissHint(hintId);
        await onStateUpdated?.();
      }
    } catch {
      // Локально подсказка уже скрыта
    }
  };

  const manualKillswitch = Boolean(manualKillswitchProp ?? state?.manual_killswitch);
  const readyToLaunch = isCleanRoomReadyToLaunch(auditReport, manualKillswitch);
  const activeProfile =
    cleanState.profiles.find((p) => p.id === selectedProfileId) ??
    cleanState.profiles[0] ??
    null;

  const exitCountry =
    auditReport?.exit_country ||
    (report?.telemetry.country_code && report.telemetry.country_code !== "--"
      ? report.telemetry.country_code
      : "NL");

  const handlePaymentTabWarmup = async () => {
    if (!activeProfile) return;
    await startCleanProfileWarmup(activeProfile.id);
    await refreshCleanProfiles();
  };

  return (
    <div className="zs-stack cr-stack">
      <CooldownBanner
        cooldownUntil={state?.ip_change_cooldown_until}
        onCleared={onStateUpdated}
        onToast={toast}
      />

      <HintCard
        hintId={copy.hint.id}
        body={copy.hint.body}
        dismissedHints={localDismissed}
        onDismiss={(id) => void handleDismissHint(id)}
      />

      <Segmented<CleanRoomTab>
        aria-label={copy.tabsLabel}
        value={tab}
        onChange={setTab}
        options={[
          { value: "launchpad", label: copy.tabs.launchpad },
          { value: "payment", label: copy.tabs.payment },
        ]}
      />

      {tab === "launchpad" ? (
        <div className="cr-stack">
          <PreFlightAuditCard
            activeProfileId={activeProfile?.id ?? null}
            activeProfileRouteId={activeProfile?.bound_route_id ?? null}
            routes={routesSnap?.routes ?? []}
            defaultRouteId={state?.default_route_id ?? routesSnap?.default_route_id ?? null}
            taintedIps={cleanState.tainted_ips}
            hideIpMode={hideIpMode}
            manualKillswitch={manualKillswitch}
            audit={initialAudit !== undefined ? auditReport : undefined}
            onAuditUpdated={setAuditReport}
            onTaintedStateUpdated={refreshCleanProfiles}
            onNavigateToConnect={onNavigateToConnect}
            onAcknowledgeIsolation={() => setCreateTrigger((n) => n + 1)}
            onStateUpdated={onStateUpdated}
            toast={toast}
          />

          <SandboxProfilesCard
            profiles={cleanState.profiles}
            activeProfileId={activeProfile?.id ?? null}
            routes={routesSnap?.routes ?? []}
            taintedIps={cleanState.tainted_ips}
            hideIpMode={hideIpMode}
            readyToLaunch={readyToLaunch}
            manualKillswitch={manualKillswitch}
            initialBrowsers={initialBrowsers}
            onSelectProfile={setSelectedProfileId}
            onProfilesChanged={refreshCleanProfiles}
            openCreateTrigger={createTrigger}
            toast={toast}
          />

          <LaunchpadSteps
            state={state}
            activeProfile={activeProfile}
            exitCountry={exitCountry}
            readyToLaunch={readyToLaunch}
            manualKillswitch={manualKillswitch}
            initialStep={initialStep}
            navKey={navKey}
            onNavigateToGuide={onNavigateToGuide}
            onProfilesChanged={() => refreshCleanProfiles()}
            onStateUpdated={onStateUpdated}
            toast={toast}
          />
        </div>
      ) : (
        <div className="cr-stack">
          <p className="zs-t-body cr-lead">{copy.paymentQuickNote}</p>

          <CardCheck
            exitCountry={exitCountry}
            onToast={toast}
            onNavigateToPaymentGuide={
              onNavigateToGuide ? () => onNavigateToGuide("payment") : undefined
            }
          />

          <AddressCard onToast={toast} />

          <Warmup
            state={state}
            warmupStartedAt={activeProfile?.warmup_started_at ?? state?.warmup_started_at ?? null}
            onStartWarmup={activeProfile ? handlePaymentTabWarmup : undefined}
            hideReset={Boolean(activeProfile)}
            disclaimer={copy.launchpad.step3.disclaimer}
            onStateChange={() => void onStateUpdated?.()}
            onNavigateToPaymentGuide={
              onNavigateToGuide ? () => onNavigateToGuide("payment") : undefined
            }
            onToast={toast}
          />
        </div>
      )}
    </div>
  );
}
