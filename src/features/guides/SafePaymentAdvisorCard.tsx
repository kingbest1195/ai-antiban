import { useEffect, useState } from "react";
import type {
  AdvisorPlan,
  AiPaymentService,
  KycRiskTier,
  PaymentRail,
} from "../../types";
import { getPaymentAdvice } from "../../utils/api";
import {
  Badge,
  Banner,
  Button,
  Card,
  Field,
  Row,
  Rows,
  Segmented,
  Select,
} from "../../ui";
import type { BadgeTone } from "../../ui";
import { guides as guidesCopy, subscription as subCopy } from "../../shared/copy/ru";
import { evaluateBinInput } from "../subscription/CardCheck";

const t = guidesCopy.payment.advisor;

export interface SafePaymentAdvisorCardProps {
  exitCountry?: string;
  initialBin?: string | null;
  initialPlan?: AdvisorPlan | null;
}

function tierTone(tier: KycRiskTier): BadgeTone {
  if (tier === "minimal" || tier === "low") return "ok";
  if (tier === "medium") return "warn";
  return "danger";
}

/** Интерактивный навигатор безопасной оплаты подписок ИИ (5 сценариев). */
export function SafePaymentAdvisorCard({
  exitCountry,
  initialBin,
  initialPlan,
}: SafePaymentAdvisorCardProps) {
  const [service, setService] = useState<AiPaymentService>("claude_pro");
  const [hasAppleId, setHasAppleId] = useState<"yes" | "no">("yes");
  const [rail, setRail] = useState<PaymentRail>("rub_sbp");
  const [warmup96h, setWarmup96h] = useState<"yes" | "no">("yes");
  const [binInput, setBinInput] = useState<string>(initialBin ?? "");
  const [binError, setBinError] = useState<string | null>(null);
  const [googleCountry, setGoogleCountry] = useState<string>("");
  const [plan, setPlan] = useState<AdvisorPlan | null>(initialPlan ?? null);
  const [busy, setBusy] = useState<boolean>(false);

  useEffect(() => {
    if (initialBin) {
      setBinInput(initialBin.slice(0, 8));
    }
  }, [initialBin]);

  const runAdvice = async () => {
    setBusy(true);
    try {
      const resolvedCountry =
        exitCountry && exitCountry !== "--" ? exitCountry.trim().toUpperCase() : null;
      const result = await getPaymentAdvice({
        target_service: service,
        has_iphone_apple_id: hasAppleId === "yes",
        available_bin_prefix: binInput.length >= 6 ? binInput : null,
        payment_rails: [rail],
        willing_to_warmup_96h: warmup96h === "yes",
        google_payments_country:
          service === "gemini" && googleCountry ? googleCountry : null,
        is_new_google_account: service === "gemini" ? googleCountry === "" : null,
        network_state: {
          exit_country: resolvedCountry,
          trust_score: 80,
          clean_room_ready: true,
          is_zastava_key_active: Boolean(resolvedCountry),
        },
      });
      setPlan(result);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (initialPlan !== undefined) return;
    void runAdvice();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [service, hasAppleId, rail, warmup96h, googleCountry, exitCountry]);

  return (
    <Card title={t.title}>
      <p className="guides-lead">{t.subtitle}</p>

      <div className="zs-stack">
        <Select
          label={t.serviceLabel}
          value={service}
          onChange={(e) => setService(e.target.value as AiPaymentService)}
          options={[
            { value: "claude_pro", label: subCopy.readiness.services.claude_pro },
            { value: "claude_max", label: subCopy.readiness.services.claude_max },
            { value: "chatgpt", label: subCopy.readiness.services.chatgpt },
            { value: "cursor", label: subCopy.readiness.services.cursor },
            { value: "gemini", label: subCopy.readiness.services.gemini },
          ]}
        />

        <Segmented<"yes" | "no">
          aria-label={t.iphoneLabel}
          value={hasAppleId}
          onChange={setHasAppleId}
          options={[
            { value: "yes", label: t.iphoneYes },
            { value: "no", label: t.iphoneNo },
          ]}
        />

        <Segmented<PaymentRail>
          aria-label={t.railLabel}
          value={rail}
          onChange={setRail}
          options={[
            { value: "rub_sbp", label: t.rails.rub_sbp },
            { value: "crypto_usdt", label: t.rails.crypto_usdt },
            { value: "foreign_bank_card", label: t.rails.foreign_bank_card },
          ]}
        />

        <Segmented<"yes" | "no">
          aria-label={t.warmupLabel}
          value={warmup96h}
          onChange={setWarmup96h}
          options={[
            { value: "yes", label: t.warmupYes },
            { value: "no", label: t.warmupNo },
          ]}
        />

        {service === "gemini" && (
          <Select
            label={t.googleCountryLabel}
            value={googleCountry}
            onChange={(e) => setGoogleCountry(e.target.value)}
            options={[
              { value: "", label: t.googleCountryOptions.none },
              { value: "US", label: t.googleCountryOptions.US },
              { value: "DE", label: t.googleCountryOptions.DE },
              { value: "RU", label: t.googleCountryOptions.RU },
            ]}
          />
        )}

        <Field
          label={t.binLabel}
          value={binInput}
          onChange={(e) => {
            const dec = evaluateBinInput(e.target.value, binInput);
            if (!dec.accepted) {
              setBinError(dec.error);
              return;
            }
            setBinInput(dec.nextValue);
            setBinError(null);
          }}
          placeholder={t.binPlaceholder}
          inputMode="numeric"
          autoComplete="off"
          error={binError ?? undefined}
          action={
            <Button
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() => void runAdvice()}
            >
              {t.submitBtn}
            </Button>
          }
        />

        {plan && (
          <div className="zs-stack">
            <div className="guides-alt">
              <div className="guides-mail__head">
                <p className="guides-alt__title">{t.primaryTitle}</p>
                <Badge tone={tierTone(plan.primary.kyc_risk_tier)}>
                  {t.tiers[plan.primary.kyc_risk_tier]}
                </Badge>
              </div>
              <p className="guides-alt__text">
                <strong>{plan.primary.title}</strong>
              </p>
              <p className="guides-note">
                {t.feesLabel}: {plan.primary.estimated_fees}
              </p>
              <ul className="guides-points__list">
                {plan.primary.checklist.slice(0, 4).map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </div>

            {plan.primary.warnings && plan.primary.warnings.length > 0 && (
              <Banner tone="info" icon="info" title={plan.primary.warnings[0]} />
            )}

            {plan.blocked_red_flags.length > 0 && (
              <div className="guides-points">
                <p className="guides-points__title">{t.blockedTitle}</p>
                <Rows>
                  {plan.blocked_red_flags.slice(0, 2).map((flag) => (
                    <Row
                      key={flag.route_id}
                      icon="alert"
                      tone="danger"
                      title={flag.title}
                      sub={`${flag.reason} ${flag.explanation}`}
                    />
                  ))}
                </Rows>
              </div>
            )}

            {plan.fallbacks.length > 0 && (
              <Row
                icon="info"
                tone="neutral"
                title={plan.fallbacks[0].title}
                sub={`${t.fallbackTitle} · ${plan.fallbacks[0].estimated_fees}`}
              />
            )}
          </div>
        )}
      </div>
    </Card>
  );
}
