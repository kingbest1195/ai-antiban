import { useEffect, useState } from "react";
import type { AppStateData, CleanRoomProfile } from "../../types";
import {
  launchCleanBrowser,
  startCleanProfileWarmup,
  updateCleanProfileStep,
} from "../../utils/api";
import { Badge, Banner, Button, Card, Field, Row, Rows } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";
import { AddressCard } from "../subscription/AddressCard";
import { CardCheck } from "../subscription/CardCheck";
import { Warmup } from "../subscription/Warmup";
import "../subscription/subscription.css";
import { resolveSandboxBlockReason } from "./SandboxProfilesCard";

export interface LaunchpadStepsProps {
  state?: AppStateData | null;
  activeProfile: CleanRoomProfile | null;
  exitCountry: string;
  readyToLaunch: boolean;
  manualKillswitch?: boolean;
  initialStep?: number;
  navKey?: number;
  onNavigateToGuide?: (guideRef: string) => void;
  onProfilesChanged?: () => Promise<unknown> | void;
  onStateUpdated?: () => Promise<unknown> | void;
  onRequestCreateProfile?: () => void;
  toast?: ShowToast;
}

/** Возвращает URL регистрации провайдера для запуска браузерной песочницы на Шаге 2. */
export function providerSignupUrl(provider: string | null | undefined, customUrl?: string): string {
  const key = (provider ?? "").toLowerCase();
  if (key === "anthropic" || key === "claude") return "https://claude.ai";
  if (key === "openai" || key === "chatgpt") return "https://chatgpt.com";
  if (key === "gemini") return "https://aistudio.google.com";
  return customUrl?.trim() || "https://claude.ai";
}

function clampStep(step: number | undefined): number {
  if (!step || !Number.isFinite(step)) return 1;
  return Math.min(4, Math.max(1, Math.trunc(step)));
}

/** Интерактивный 4-шаговый Launchpad нового аккаунта с синхронизацией в CleanRoomProfile. */
export function LaunchpadSteps({
  state,
  activeProfile,
  exitCountry,
  readyToLaunch,
  manualKillswitch = false,
  initialStep,
  navKey,
  onNavigateToGuide,
  onProfilesChanged,
  onStateUpdated,
  onRequestCreateProfile,
  toast,
}: LaunchpadStepsProps) {
  const [step, setStep] = useState<number>(() =>
    clampStep(initialStep ?? activeProfile?.launchpad_step ?? 1),
  );
  const [checklist, setChecklist] = useState<string[]>(
    () => activeProfile?.completed_checklist ?? [],
  );
  const [customUrl, setCustomUrl] = useState<string>("https://claude.ai");
  const [launching, setLaunching] = useState<boolean>(false);

  useEffect(() => {
    if (initialStep !== undefined) {
      setStep(clampStep(initialStep));
    }
  }, [initialStep, navKey]);

  useEffect(() => {
    if (!activeProfile) return;
    setChecklist(activeProfile.completed_checklist);
    if (initialStep === undefined) {
      setStep(clampStep(activeProfile.launchpad_step));
    }
  }, [activeProfile, initialStep]);

  const persistStep = async (nextStep: number, nextChecklist: string[]) => {
    const clamped = clampStep(nextStep);
    setStep(clamped);
    setChecklist(nextChecklist);
    if (!activeProfile) return;
    try {
      await updateCleanProfileStep(activeProfile.id, clamped, nextChecklist);
      await onProfilesChanged?.();
    } catch (err) {
      toast?.(copy.sandbox.toast.error, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const toggleCheckItem = (id: string) => {
    const next = checklist.includes(id)
      ? checklist.filter((item) => item !== id)
      : [...checklist, id];
    void persistStep(step, next);
  };

  const blockReason = activeProfile
    ? resolveSandboxBlockReason(activeProfile, readyToLaunch, manualKillswitch)
    : readyToLaunch
      ? copy.launchpad.step1.checkProfileFail
      : copy.sandbox.profileCard.blockedReasonAudit;

  const canLaunchStep2 = Boolean(activeProfile) && blockReason === null;
  const signupUrl = providerSignupUrl(activeProfile?.provider, customUrl);

  const handleLaunchSignup = async () => {
    if (!activeProfile || !canLaunchStep2 || launching) return;
    setLaunching(true);
    try {
      const res = await launchCleanBrowser(activeProfile.id, signupUrl);
      toast?.(
        copy.sandbox.toast.launched,
        copy.sandbox.toast.launchedText(res.browser_engine, res.alias_port),
        "success",
      );
      await onProfilesChanged?.();
    } catch (err) {
      toast?.(copy.sandbox.toast.error, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setLaunching(false);
    }
  };

  const handleStartWarmup = async () => {
    if (!activeProfile) return;
    await startCleanProfileWarmup(activeProfile.id);
    await onProfilesChanged?.();
    await onStateUpdated?.();
  };

  return (
    <Card
      title={copy.launchpad.title}
      aside={
        activeProfile ? (
          <Badge tone="info">{copy.launchpad.activeProfile(activeProfile.label)}</Badge>
        ) : undefined
      }
    >
      <div className="cr-step-nav" role="tablist" aria-label={copy.launchpad.title}>
        {copy.launchpad.stepLabels.map((s) => (
          <button
            key={s.step}
            type="button"
            role="tab"
            aria-selected={step === s.step}
            className="cr-step-tab"
            onClick={() => void persistStep(s.step, checklist)}
          >
            {s.short}
          </button>
        ))}
      </div>

      {!activeProfile && <p className="zs-t-caption cr-lead">{copy.launchpad.noProfileNote}</p>}

      {step === 1 && (
        <div className="cr-stack">
          <div>
            <h4 className="zs-t-heading" style={{ margin: 0 }}>{copy.launchpad.step1.title}</h4>
            <p className="zs-t-body cr-lead" style={{ marginTop: 4 }}>{copy.launchpad.step1.text}</p>
          </div>
          <Rows>
            <Row
              icon="shield"
              tone={readyToLaunch ? "ok" : "danger"}
              title={readyToLaunch ? copy.launchpad.step1.checkAuditOk : copy.launchpad.step1.checkAuditFail}
            />
            <Row
              icon="globe"
              tone={activeProfile ? "ok" : "warn"}
              title={
                activeProfile
                  ? copy.launchpad.step1.checkProfileOk(activeProfile.label)
                  : copy.launchpad.step1.checkProfileFail
              }
              trail={
                !activeProfile && onRequestCreateProfile ? (
                  <Button size="sm" onClick={onRequestCreateProfile}>
                    {copy.sandbox.createBtn}
                  </Button>
                ) : undefined
              }
            />
            <Row
              icon="key"
              tone={activeProfile?.bound_route_id ? "ok" : "warn"}
              title={
                activeProfile?.bound_route_id
                  ? copy.launchpad.step1.checkRouteOk
                  : copy.launchpad.step1.checkRouteDirect
              }
            />
          </Rows>
          <Button variant="primary" icon="arrow" onClick={() => void persistStep(2, checklist)}>
            {copy.launchpad.step1.nextBtn}
          </Button>
        </div>
      )}

      {step === 2 && (
        <div className="cr-stack">
          <div>
            <h4 className="zs-t-heading" style={{ margin: 0 }}>{copy.launchpad.step2.title}</h4>
            <p className="zs-t-body cr-lead" style={{ marginTop: 4 }}>{copy.launchpad.step2.text}</p>
          </div>
          {activeProfile?.provider === "custom" && (
            <Field
              label={copy.launchpad.step2.customUrlLabel}
              value={customUrl}
              onChange={(e) => setCustomUrl(e.target.value)}
              placeholder={copy.launchpad.step2.customUrlPlaceholder}
            />
          )}
          {blockReason && <p className="cr-blocked-reason">{blockReason}</p>}
          <div className="cr-row-inline">
            <Button
              variant="primary"
              icon="shield"
              disabled={!canLaunchStep2 || launching}
              aria-disabled={!canLaunchStep2 ? "true" : undefined}
              title={blockReason ?? undefined}
              onClick={() => void handleLaunchSignup()}
            >
              {launching ? copy.sandbox.profileCard.launching : copy.launchpad.step2.launchBtn}
            </Button>
          </div>
          <div>
            <p className="zs-t-heading" style={{ margin: 0 }}>{copy.launchpad.step2.checklistTitle}</p>
            <ul className="cr-checklist">
              {copy.launchpad.step2.checklist.map((item) => (
                <li key={item.id}>
                  <label className="cr-check-item">
                    <input
                      type="checkbox"
                      checked={checklist.includes(item.id)}
                      onChange={() => toggleCheckItem(item.id)}
                    />
                    <span>
                      <span className="cr-check-item__title">{item.title}</span>
                      <span className="cr-check-item__detail">{item.detail}</span>
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          </div>
          <Button variant="secondary" icon="arrow" onClick={() => void persistStep(3, checklist)}>
            {copy.launchpad.step2.nextBtn}
          </Button>
        </div>
      )}

      {step === 3 && (
        <div className="cr-stack">
          <div>
            <h4 className="zs-t-heading" style={{ margin: 0 }}>{copy.launchpad.step3.title}</h4>
            <p className="zs-t-body cr-lead" style={{ marginTop: 4 }}>{copy.launchpad.step3.text}</p>
          </div>
          <Warmup
            state={state}
            warmupStartedAt={activeProfile?.warmup_started_at ?? state?.warmup_started_at ?? null}
            onStartWarmup={activeProfile ? handleStartWarmup : undefined}
            hideReset={Boolean(activeProfile)}
            disclaimer={copy.launchpad.step3.disclaimer}
            onStateChange={() => void onStateUpdated?.()}
            onNavigateToPaymentGuide={onNavigateToGuide ? () => onNavigateToGuide("payment") : undefined}
            onToast={toast}
          />
          <div>
            <p className="zs-t-heading" style={{ margin: 0 }}>{copy.launchpad.step3.checklistTitle}</p>
            <ul className="cr-checklist">
              {copy.launchpad.step3.checklist.map((item) => (
                <li key={item.id}>
                  <label className="cr-check-item">
                    <input
                      type="checkbox"
                      checked={checklist.includes(item.id)}
                      onChange={() => toggleCheckItem(item.id)}
                    />
                    <span>
                      <span className="cr-check-item__title">{item.title}</span>
                      <span className="cr-check-item__detail">{item.detail}</span>
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          </div>
          <Button variant="secondary" icon="arrow" onClick={() => void persistStep(4, checklist)}>
            {copy.launchpad.step3.nextBtn}
          </Button>
        </div>
      )}

      {step === 4 && (
        <div className="cr-stack">
          <div>
            <h4 className="zs-t-heading" style={{ margin: 0 }}>{copy.launchpad.step4.title}</h4>
            <p className="zs-t-body cr-lead" style={{ marginTop: 4 }}>{copy.launchpad.step4.text}</p>
          </div>
          <Banner
            tone="danger"
            role="alert"
            icon="alert"
            title={copy.launchpad.step4.resellerWarningTitle}
          >
            {copy.launchpad.step4.resellerWarningText}
          </Banner>
          <CardCheck
            exitCountry={exitCountry}
            onToast={toast}
            onNavigateToPaymentGuide={onNavigateToGuide ? () => onNavigateToGuide("payment") : undefined}
          />
          <AddressCard onToast={toast} />
          {onNavigateToGuide && (
            <Button variant="secondary" icon="arrow" onClick={() => onNavigateToGuide("payment")}>
              {copy.launchpad.step4.openGuideBtn}
            </Button>
          )}
        </div>
      )}
    </Card>
  );
}
