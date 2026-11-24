import { useEffect, useState } from "react";
import type {
  AiPaymentService,
  BinReport,
  PaymentChannel,
  PaymentReadinessReport,
  ReadinessTier,
  SubscriptionPlan,
} from "../../types";
import { evaluatePaymentReadiness } from "../../utils/api";
import { Badge, Banner, Card, Icon, Segmented, Select } from "../../ui";
import type { BadgeTone, BannerTone } from "../../ui";
import { subscription } from "../../shared/copy/ru";
import { buildCountryOptions, COMMON_COUNTRY_CODES, countryName } from "../../shared/lib/country";
import { warmupProgress } from "./Warmup";

const copy = subscription.readiness;
const appStoreCopy = subscription.appStore;

export type AccountAgeChoice = "under4d" | "over4d";

export interface PaymentReadinessCardProps {
  binReport?: BinReport | null;
  exitCountry?: string;
  inCleanRoom?: boolean;
  profileId?: string | null;
  channel?: PaymentChannel;
  onChannelChange?: (channel: PaymentChannel) => void;
  plan?: SubscriptionPlan;
  onPlanChange?: (plan: SubscriptionPlan) => void;
  targetService?: AiPaymentService;
  onTargetServiceChange?: (service: AiPaymentService) => void;
  billingCountry?: string;
  onBillingCountryChange?: (country: string) => void;
  appleIdCountry?: string;
  onAppleIdCountryChange?: (country: string) => void;
  warmupStartedAt?: number | null;
  /** Внутри сценария «Картой на сайте» скрывает вариант App Store (он в верхнем переключателе). */
  hideChannelAppleIap?: boolean;
  /** Предзагруженный отчёт (для тестов и SSR). */
  initialReport?: PaymentReadinessReport | null;
}

export function readinessTierTone(tier: ReadinessTier): BadgeTone {
  if (tier === "green") return "ok";
  if (tier === "yellow") return "warn";
  return "danger";
}

export function isWebWalletTrapChannel(channel: PaymentChannel): boolean {
  return channel === "googlePayWeb" || channel === "applePayWeb";
}

function axisTone(status: string): BadgeTone {
  if (status === "ok") return "ok";
  if (status === "warning" || status === "unknown") return "warn";
  return "danger";
}

function bannerToneForTier(tier: ReadinessTier): BannerTone {
  if (tier === "green") return "ok";
  if (tier === "yellow") return "warn";
  return "danger";
}

/** Единая карточка «Готово ли к оплате» с автоподстановкой стран и свёрнутыми деталями проверки. */
export function PaymentReadinessCard({
  binReport,
  exitCountry,
  inCleanRoom = false,
  profileId,
  channel: controlledChannel,
  onChannelChange,
  plan: controlledPlan,
  onPlanChange,
  targetService: controlledService,
  onTargetServiceChange,
  billingCountry: controlledBilling,
  onBillingCountryChange,
  appleIdCountry: controlledAppleId,
  onAppleIdCountryChange,
  warmupStartedAt,
  hideChannelAppleIap = false,
  initialReport,
}: PaymentReadinessCardProps) {
  const normalizedExit = exitCountry && exitCountry !== "--" ? exitCountry.trim().toUpperCase() : "";
  const [localChannel, setLocalChannel] = useState<PaymentChannel>("appleIAP");
  const [localPlan, setLocalPlan] = useState<SubscriptionPlan>("pro");
  const [localService, setLocalService] = useState<AiPaymentService>("claude_pro");
  const [localBilling, setLocalBilling] = useState<string>(
    binReport?.countryCode ?? normalizedExit ?? "",
  );
  const [billingTouched, setBillingTouched] = useState<boolean>(false);
  const [googleProfileCountry, setGoogleProfileCountry] = useState<string>(normalizedExit);
  const [googleTouched, setGoogleTouched] = useState<boolean>(false);
  const [localAppleIdCountry, setLocalAppleIdCountry] = useState<string>("US");
  const [accountAge, setAccountAge] = useState<AccountAgeChoice>("under4d");
  const [report, setReport] = useState<PaymentReadinessReport | null>(initialReport ?? null);
  const [loading, setLoading] = useState<boolean>(false);

  const channel = controlledChannel ?? localChannel;
  const plan = controlledPlan ?? localPlan;
  const targetService = controlledService ?? localService;
  const billingCountry = controlledBilling ?? localBilling;
  const appleIdCountry = controlledAppleId ?? localAppleIdCountry;
  const warmup = warmupProgress(warmupStartedAt);
  const warmupStarted = warmup.started;
  const warmupDone = warmup.done;

  const setChannel = (next: PaymentChannel) => {
    if (controlledChannel === undefined) setLocalChannel(next);
    onChannelChange?.(next);
  };

  const setPlan = (next: SubscriptionPlan) => {
    if (controlledPlan === undefined) setLocalPlan(next);
    onPlanChange?.(next);
  };

  const setTargetService = (next: AiPaymentService) => {
    if (controlledService === undefined) setLocalService(next);
    onTargetServiceChange?.(next);
    if (next === "claude_max") setPlan("max");
    else if (next === "claude_pro") setPlan("pro");
  };

  const setBillingCountry = (next: string) => {
    setBillingTouched(true);
    const upper = next.trim().toUpperCase();
    if (controlledBilling === undefined) setLocalBilling(upper);
    onBillingCountryChange?.(upper);
  };

  const setAppleIdCountry = (next: string) => {
    const upper = next.trim().toUpperCase();
    if (controlledAppleId === undefined) setLocalAppleIdCountry(upper);
    onAppleIdCountryChange?.(upper);
  };

  useEffect(() => {
    if (controlledBilling !== undefined) return;
    if (binReport?.countryCode) {
      setLocalBilling(binReport.countryCode.toUpperCase());
      setBillingTouched(false);
    } else if (!billingTouched && normalizedExit) {
      setLocalBilling(normalizedExit);
    }
  }, [binReport?.countryCode, normalizedExit, controlledBilling, billingTouched]);

  useEffect(() => {
    if (googleTouched) return;
    if (binReport?.countryCode) {
      setGoogleProfileCountry(binReport.countryCode.toUpperCase());
    } else if (normalizedExit) {
      setGoogleProfileCountry(normalizedExit);
    }
  }, [binReport?.countryCode, normalizedExit, googleTouched]);

  useEffect(() => {
    if (initialReport !== undefined) {
      setReport(initialReport);
      return;
    }
    let cancelled = false;
    setLoading(true);
    const providerForService =
      targetService === "gemini"
        ? "gemini"
        : targetService === "chatgpt"
          ? "openai"
          : "anthropic";
    evaluatePaymentReadiness({
      bin: binReport?.binPrefix ?? null,
      billingCountry: billingCountry || null,
      googleProfileCountry: googleProfileCountry || null,
      appleIdCountry: appleIdCountry || null,
      channel,
      inCleanRoom,
      plan,
      profileId: profileId ?? null,
      provider: providerForService,
      targetService,
      accountAgeConfirmed96h: warmupDone ? true : accountAge === "over4d",
    })
      .then((res) => {
        if (!cancelled) setReport(res);
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    binReport?.binPrefix,
    billingCountry,
    googleProfileCountry,
    appleIdCountry,
    channel,
    inCleanRoom,
    plan,
    targetService,
    profileId,
    normalizedExit,
    accountAge,
    warmupDone,
    initialReport,
  ]);

  const showWalletTrap = isWebWalletTrapChannel(channel);
  const cardCc = binReport?.countryCode?.toUpperCase() || null;
  const exitCc = normalizedExit || null;
  const gpCc = googleProfileCountry.trim().toUpperCase() || null;
  const hasWalletConflict =
    showWalletTrap &&
    Boolean(
      (cardCc && exitCc && cardCc !== exitCc) ||
        (channel === "googlePayWeb" && cardCc && gpCc && cardCc !== gpCc),
    );

  const billingOptions = buildCountryOptions(
    [cardCc, exitCc, billingCountry],
    copy.billingCountryEmpty,
  );
  const googleOptions = buildCountryOptions(
    [cardCc, exitCc, googleProfileCountry],
    copy.googleProfileEmpty,
  );
  const otherAppleCountries = COMMON_COUNTRY_CODES.filter(
    (code) => code !== "US" && code !== "TR" && code !== "KZ",
  )
    .map((code) => ({ value: code, label: countryName(code) || code }))
    .sort((a, b) => a.label.localeCompare(b.label, "ru"));

  const axesList = report
    ? [
        report.axes.networkBase,
        report.axes.cardBin,
        report.axes.geoBillingParity,
        report.axes.channelEnvWarmup,
      ]
    : [];

  const rawReasons = report
    ? Array.from(new Set([...report.blockers, ...report.warnings]))
    : [];
  const reasons =
    rawReasons.length > 0
      ? rawReasons.slice(0, 3)
      : report?.tier === "green"
        ? [copy.greenDefaultReason]
        : [];

  const channelOptions = hideChannelAppleIap
    ? [
        { value: "directCard" as PaymentChannel, label: copy.channels.directCard },
        { value: "googlePayWeb" as PaymentChannel, label: copy.channels.googlePayWeb },
        { value: "applePayWeb" as PaymentChannel, label: copy.channels.applePayWeb },
        { value: "googlePlayIap" as PaymentChannel, label: copy.channels.googlePlayIap },
      ]
    : [
        { value: "appleIAP" as PaymentChannel, label: copy.channels.appleIAP },
        { value: "googlePlayIap" as PaymentChannel, label: copy.channels.googlePlayIap },
        { value: "directCard" as PaymentChannel, label: copy.channels.directCard },
        { value: "googlePayWeb" as PaymentChannel, label: copy.channels.googlePayWeb },
        { value: "applePayWeb" as PaymentChannel, label: copy.channels.applePayWeb },
      ];

  const isStoreIap = channel === "appleIAP" || channel === "googlePlayIap";

  const effectiveAction =
    report?.recommendedAction || (report?.tier === "green" ? copy.greenDefaultAction : null);

  return (
    <Card
      title={copy.title}
      aside={
        report ? (
          <Badge
            tone={readinessTierTone(report.tier)}
            icon={report.tier === "green" ? "check" : "alert"}
          >
            {copy.tiers[report.tier]}
          </Badge>
        ) : undefined
      }
    >
      <p className="zs-t-caption subs-lead">{copy.subtitle}</p>

      <div className="subs-readiness-controls">
        <Segmented<PaymentChannel>
          aria-label={copy.channelLabel}
          className="subs-channel-seg"
          value={channel}
          onChange={setChannel}
          options={channelOptions}
        />

        <Select
          label={copy.serviceLabel}
          value={targetService}
          onChange={(e) => setTargetService(e.target.value as AiPaymentService)}
          options={[
            { value: "claude_pro", label: copy.services.claude_pro },
            { value: "claude_max", label: copy.services.claude_max },
            { value: "chatgpt", label: copy.services.chatgpt },
            { value: "cursor", label: copy.services.cursor },
            { value: "gemini", label: copy.services.gemini },
          ]}
        />

        {!isStoreIap && (
          <Segmented<SubscriptionPlan>
            aria-label={copy.planLabel}
            value={plan}
            onChange={setPlan}
            options={[
              { value: "pro", label: copy.plans.pro },
              { value: "max", label: copy.plans.max },
            ]}
          />
        )}

        {!isStoreIap && !warmupStarted && (
          <Segmented<AccountAgeChoice>
            aria-label={copy.accountAgeLabel}
            value={accountAge}
            onChange={setAccountAge}
            options={[
              { value: "under4d", label: copy.accountAgeUnder4 },
              { value: "over4d", label: copy.accountAgeOver4 },
            ]}
          />
        )}

        {channel === "appleIAP" ? (
          <Select
            label={copy.appleIdLabel}
            value={appleIdCountry}
            onChange={(e) => setAppleIdCountry(e.target.value)}
          >
            <option value="US">{appStoreCopy.countryUs}</option>
            <option value="TR">{appStoreCopy.countryTr}</option>
            <option value="KZ">{appStoreCopy.countryKz}</option>
            <optgroup label={appStoreCopy.otherGroupLabel}>
              {otherAppleCountries.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </optgroup>
          </Select>
        ) : channel === "googlePlayIap" ? (
          <Select
            label={copy.googleProfileLabel}
            value={googleProfileCountry}
            onChange={(e) => {
              setGoogleTouched(true);
              setGoogleProfileCountry(e.target.value);
            }}
            options={googleOptions}
          />
        ) : (
          <div className="subs-readiness-grid">
            <Select
              label={copy.billingCountryLabel}
              value={billingCountry}
              onChange={(e) => setBillingCountry(e.target.value)}
              options={billingOptions}
            />
            {(channel === "googlePayWeb" || targetService === "gemini") && (
              <Select
                label={copy.googleProfileLabel}
                value={googleProfileCountry}
                onChange={(e) => {
                  setGoogleTouched(true);
                  setGoogleProfileCountry(e.target.value);
                }}
                options={googleOptions}
              />
            )}
          </div>
        )}
      </div>

      {showWalletTrap && (
        <div className="subs-block-gap">
          <Banner
            tone={hasWalletConflict ? "danger" : "warn"}
            icon="alert"
            role={hasWalletConflict ? "alert" : "status"}
            title={copy.trapTitle}
          >
            {copy.trapText}
          </Banner>
        </div>
      )}

      {report ? (
        <div className="subs-block-gap">
          <div className="subs-verdict-hero">
            <h4 className="subs-verdict-title">{copy.tiers[report.tier]}</h4>
            {reasons.length > 0 && (
              <ul className="subs-reasons">
                {reasons.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            )}
          </div>

          {report.failClosedBin && (
            <div className="subs-block-gap">
              <Banner tone="warn" icon="alert" title={copy.failClosedNote} />
            </div>
          )}

          {effectiveAction && (
            <div className="subs-block-gap">
              <Banner
                tone={bannerToneForTier(report.tier)}
                icon={report.tier === "green" ? "check" : "alert"}
                title={copy.actionTitle}
              >
                {effectiveAction}
              </Banner>
            </div>
          )}

          <details className="subs-details">
            <summary className="subs-details__summary">
              <span>{copy.detailsToggle}</span>
              <Icon name="chev" className="subs-details__chev" />
            </summary>
            <div className="subs-details__body">
              <span className="subs-details__score">
                {loading ? copy.evaluating : copy.scoreLabel(report.score)}
              </span>
              <div className="subs-axes">
                {axesList.map((axis) => (
                  <div key={axis.id} className="subs-axis">
                    <div className="subs-axis__head">
                      <span className="zs-t-body">{axis.label}</span>
                      <Badge tone={axisTone(axis.status)}>
                        <span className="subs-axis__score">
                          {axis.score} / {axis.maxScore}
                        </span>
                      </Badge>
                    </div>
                    {axis.notes[0] && <p className="subs-axis__note">{axis.notes[0]}</p>}
                  </div>
                ))}
              </div>
            </div>
          </details>
        </div>
      ) : (
        <p className="zs-t-caption subs-lead">{copy.evaluating}</p>
      )}
    </Card>
  );
}
