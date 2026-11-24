import { useState } from "react";
import type {
  AiPaymentService,
  BinReport,
  PaymentChannel,
  SubscriptionPlan,
} from "../../types";
import { Banner, Button, Card, Segmented, Select } from "../../ui";
import { subscription as copy } from "../../shared/copy/ru";
import { COMMON_COUNTRY_CODES, countryName } from "../../shared/lib/country";
import type { ShowToast } from "../../shared/hooks";
import { AddressCard } from "./AddressCard";
import { CardCheck } from "./CardCheck";
import { PaymentPassportCard } from "./PaymentPassportCard";
import { PaymentReadinessCard } from "./PaymentReadinessCard";
import { PostPaymentQuarantineCard } from "./PostPaymentQuarantineCard";

export type PaymentScenarioFlow = "app_store" | "card";

export interface PaymentFlowPanelProps {
  initialFlow?: PaymentScenarioFlow;
  profileId?: string | null;
  routeId?: string | null;
  exitIp?: string | null;
  exitAsn?: number | null;
  exitCountry: string;
  hideIpMode?: boolean;
  inCleanRoom: boolean;
  warmupStartedAt?: number | null;
  binRadarOptIn?: boolean;
  /** При true кнопка «Проверить карту» — primary (SubscriptionScreen); при false — secondary (встраивание на экран с другой primary CTA). */
  compactPrimary?: boolean;
  onNavigateToPaymentGuide?: () => void;
  onStateUpdated?: () => Promise<unknown> | void;
  onToast?: ShowToast;
}

const OTHER_APPLE_COUNTRIES = COMMON_COUNTRY_CODES.filter(
  (code) => code !== "US" && code !== "TR" && code !== "KZ",
)
  .map((code) => ({ value: code, label: countryName(code) || code }))
  .sort((a, b) => a.label.localeCompare(b.label, "ru"));

/** Единая пошаговая панель оплаты подписки: сначала сценарий, затем только нужные блоки. */
export function PaymentFlowPanel({
  initialFlow = "app_store",
  profileId,
  routeId,
  exitIp,
  exitAsn,
  exitCountry,
  hideIpMode = false,
  inCleanRoom,
  warmupStartedAt,
  binRadarOptIn,
  compactPrimary = true,
  onNavigateToPaymentGuide,
  onStateUpdated,
  onToast,
}: PaymentFlowPanelProps) {
  const [flow, setFlow] = useState<PaymentScenarioFlow>(initialFlow);
  const [appleIdCountry, setAppleIdCountry] = useState<string>("US");
  const [binReport, setBinReport] = useState<BinReport | null>(null);
  const [webChannel, setWebChannel] = useState<PaymentChannel>("directCard");
  const [targetService, setTargetService] = useState<AiPaymentService>("claude_pro");
  const [plan, setPlan] = useState<SubscriptionPlan>("pro");
  const [billingCountry, setBillingCountry] = useState<string>("");
  const [passportVersion, setPassportVersion] = useState<number>(0);

  const handleBinChecked = (report: BinReport) => {
    setBinReport(report);
    if (report.countryCode) {
      setBillingCountry(report.countryCode);
    }
  };

  const activeChannel: PaymentChannel = flow === "app_store" ? "appleIAP" : webChannel;
  const activeBillingCountry =
    flow === "app_store" ? appleIdCountry : billingCountry || binReport?.countryCode || null;
  const appleCountryLabel = countryName(appleIdCountry) || appleIdCountry;

  return (
    <div className="zs-stack">
      <Segmented<PaymentScenarioFlow>
        aria-label={copy.flow.label}
        value={flow}
        onChange={setFlow}
        options={[
          { value: "app_store", label: copy.flow.appStore },
          { value: "card", label: copy.flow.card },
        ]}
      />

      {flow === "app_store" ? (
        <>
          <Card title={copy.appStore.title}>
            <p className="zs-t-body subs-lead">{copy.appStore.subtitle}</p>

            <Select
              label={copy.appStore.countryLabel}
              value={appleIdCountry}
              onChange={(e) => setAppleIdCountry(e.target.value)}
            >
              <option value="US">{copy.appStore.countryUs}</option>
              <option value="TR">{copy.appStore.countryTr}</option>
              <option value="KZ">{copy.appStore.countryKz}</option>
              <optgroup label={copy.appStore.otherGroupLabel}>
                {OTHER_APPLE_COUNTRIES.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </optgroup>
            </Select>

            {appleIdCountry === "US" ? (
              <div className="subs-block-gap">
                <Banner
                  tone="info"
                  icon="info"
                  title={copy.appStore.guideTitle}
                  action={
                    onNavigateToPaymentGuide ? (
                      <Button variant="secondary" size="sm" onClick={onNavigateToPaymentGuide}>
                        {copy.appStore.guideButton}
                      </Button>
                    ) : undefined
                  }
                >
                  {copy.appStore.guideText}
                </Banner>
              </div>
            ) : (
              <div className="subs-block-gap">
                <Banner
                  tone="warn"
                  icon="alert"
                  title={copy.appStore.nonUsTitle(appleCountryLabel)}
                  action={
                    onNavigateToPaymentGuide ? (
                      <Button variant="secondary" size="sm" onClick={onNavigateToPaymentGuide}>
                        {copy.appStore.guideButton}
                      </Button>
                    ) : undefined
                  }
                >
                  {copy.appStore.nonUsText}
                </Banner>
              </div>
            )}
          </Card>

          {appleIdCountry === "US" && (
            <AddressCard scenario="apple_iap" onToast={onToast} />
          )}
        </>
      ) : (
        <>
          <CardCheck
            exitCountry={exitCountry}
            targetService={targetService}
            paymentChannel={webChannel}
            billingCountry={billingCountry}
            warmupStartedAt={warmupStartedAt}
            initialOptIn={binRadarOptIn}
            ctaVariant={compactPrimary ? "primary" : "secondary"}
            onToast={onToast}
            onOptInChange={() => void onStateUpdated?.()}
            onNavigateToPaymentGuide={onNavigateToPaymentGuide}
            onBinChecked={handleBinChecked}
          />
          {binReport &&
            (binReport.claudeWebVerdict === "highKycRisk" ||
              binReport.claudeWebVerdict === "blocked") && (
              <Banner
                tone="danger"
                icon="alert"
                role="alert"
                title={copy.card.radar.rescueTitle}
                action={
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => setFlow("app_store")}
                  >
                    {copy.card.radar.rescueCta}
                  </Button>
                }
              >
                {copy.card.radar.rescueText}
              </Banner>
            )}
          <PaymentReadinessCard
            binReport={binReport}
            exitCountry={exitCountry}
            inCleanRoom={inCleanRoom}
            profileId={profileId}
            channel={webChannel}
            onChannelChange={setWebChannel}
            plan={plan}
            onPlanChange={setPlan}
            targetService={targetService}
            onTargetServiceChange={setTargetService}
            billingCountry={billingCountry}
            onBillingCountryChange={setBillingCountry}
            warmupStartedAt={warmupStartedAt}
            hideChannelAppleIap
          />
          <AddressCard
            cardCountry={binReport?.countryCode ?? null}
            scenario="card"
            onToast={onToast}
          />
        </>
      )}

      <PostPaymentQuarantineCard
        profileId={profileId}
        routeId={routeId}
        exitIp={exitIp}
        exitAsn={exitAsn}
        exitCountry={exitCountry || null}
        binPrefix={flow === "card" ? (binReport?.binPrefix ?? null) : null}
        cardCountry={flow === "card" ? (binReport?.countryCode ?? null) : activeBillingCountry}
        billingCountry={activeBillingCountry}
        channel={activeChannel}
        hideIpMode={hideIpMode}
        ctaVariant="secondary"
        onStatusChange={() => void onStateUpdated?.()}
        onPassportSaved={() => setPassportVersion((v) => v + 1)}
        onToast={onToast}
      />

      <PaymentPassportCard
        profileId={profileId}
        currentBin={flow === "card" ? (binReport?.binPrefix ?? null) : null}
        currentCardCountry={flow === "card" ? (binReport?.countryCode ?? null) : activeBillingCountry}
        currentBillingCountry={activeBillingCountry}
        currentChannel={
          activeChannel === "appleIAP"
            ? "appleIAP"
            : activeChannel === "googlePlayIap"
              ? "googlePlayIap"
              : activeChannel === "api"
                ? "api"
                : "directCard"
        }
        currentExitIp={exitIp}
        currentExitAsn={exitAsn}
        hideIpMode={hideIpMode}
        refreshTrigger={passportVersion}
        onToast={onToast}
      />
    </div>
  );
}
