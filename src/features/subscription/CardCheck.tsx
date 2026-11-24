import { useEffect, useState } from "react";
import type { ChangeEvent, ClipboardEvent, FormEvent } from "react";
import type { AiPaymentService, BinRadarLookupStats, BinReport, ClaudeWebVerdict } from "../../types";
import { checkCardBin, getBinRadarStats } from "../../utils/api";
import { Badge, Banner, Button, Card, Field, Row, Rows } from "../../ui";
import type { BannerTone, RowTone } from "../../ui";
import { subscription } from "../../shared/copy/ru";
import { countryName } from "../../shared/lib/country";
import type { ShowToast } from "../../shared/hooks";
import { detectBrand } from "./binBrand";

const copy = subscription.card;

export interface CardCheckProps {
  /** Страна выхода: карта проверяется относительно неё. */
  country?: string;
  /** Явный код страны выхода (алиас для встраивания в «Чистую комнату» и экран оплаты). */
  exitCountry?: string;
  targetService?: AiPaymentService;
  ctaVariant?: "primary" | "secondary";
  onToast?: ShowToast;
  onNavigateToPaymentGuide?: () => void;
  onBinChecked?: (report: BinReport) => void;
}

export interface BinInputDecision {
  accepted: boolean;
  nextValue: string;
  error: string | null;
}

/**
 * Безопасная валидация ввода первых 6–8 цифр карты на UI-уровне:
 * допускает строго до 8 цифр, жёстко отклоняет >8 цифр и нецифровые символы
 * без обрезки номера и без передачи в IPC/логи.
 */
export function evaluateBinInput(rawValue: string, previousValue: string): BinInputDecision {
  const withoutSeparators = rawValue.replace(/[\s-]+/g, "");
  if (!withoutSeparators) {
    return { accepted: true, nextValue: "", error: null };
  }
  if (!/^\d+$/.test(withoutSeparators)) {
    return { accepted: false, nextValue: previousValue, error: copy.errors.nonDigit };
  }
  if (withoutSeparators.length > 8) {
    return { accepted: false, nextValue: previousValue, error: copy.errors.tooLong };
  }
  return { accepted: true, nextValue: withoutSeparators, error: null };
}

function verdictTone(report: BinReport): BannerTone {
  if (report.status === "ok") return "ok";
  if (report.status === "warning" || report.status === "unknown") return "warn";
  return "danger";
}

function claudeVerdictLabel(verdict: ClaudeWebVerdict): string {
  return copy.claudeVerdicts[verdict] ?? copy.claudeVerdicts.highKycRisk;
}

function claudeVerdictTone(verdict: ClaudeWebVerdict): RowTone {
  if (verdict === "safeAligned") return "ok";
  if (verdict === "needsMatchingIpBilling") return "warn";
  return "danger";
}

/** Проверка карты по первым 6–8 цифрам без полного номера, срока и CVV. */
export function CardCheck({
  country,
  exitCountry,
  targetService = "claude_pro",
  ctaVariant = "primary",
  onToast,
  onNavigateToPaymentGuide,
  onBinChecked,
}: CardCheckProps) {
  // Не подставляем молча «NL», если страна не передана или равна «--».
  const rawCountry = exitCountry !== undefined ? exitCountry : country;
  const trimmedCountry = rawCountry?.trim();
  const resolvedCountry =
    trimmedCountry && trimmedCountry !== "--" ? trimmedCountry : "";

  const [binInput, setBinInput] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<BinReport | null>(null);
  const [radarStats, setRadarStats] = useState<BinRadarLookupStats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!result?.binPrefix) return;
    let cancelled = false;
    void getBinRadarStats(result.binPrefix, targetService)
      .then((stats) => {
        if (!cancelled) setRadarStats(stats);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [result?.binPrefix, targetService]);

  const handleInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    const decision = evaluateBinInput(e.target.value, binInput);
    if (!decision.accepted) {
      setError(decision.error);
      return;
    }
    setBinInput(decision.nextValue);
    setError(null);
  };

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const pasted = e.clipboardData?.getData("text") ?? "";
    const decision = evaluateBinInput(pasted, binInput);
    if (!decision.accepted) {
      e.preventDefault();
      setError(decision.error);
    }
  };

  const runBinAudit = async (rawBin: string) => {
    const cleaned = rawBin.replace(/[\s-]+/g, "");
    if (!/^\d+$/.test(cleaned)) {
      setError(copy.errors.nonDigit);
      return;
    }
    if (cleaned.length < 6) {
      setError(copy.errors.tooShort);
      return;
    }
    if (cleaned.length > 8) {
      setError(copy.errors.tooLong);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const [report, radar] = await Promise.all([
        checkCardBin(cleaned, resolvedCountry || null),
        getBinRadarStats(cleaned, targetService).catch(() => null),
      ]);
      setResult(report);
      setRadarStats(radar);
      onBinChecked?.(report);
      if (onToast) {
        const bank = report.knownFintechLabel || report.issuerName || copy.toast.okBank;
        const cardCountryText = report.countryCode ? countryName(report.countryCode) || report.countryCode : "";
        if (report.status === "ok") {
          onToast(copy.toast.ok, copy.toast.okText(bank, cardCountryText), "success");
        } else if (report.status === "warning" || report.status === "unknown") {
          onToast(copy.toast.warn, report.warnings[0] ?? claudeVerdictLabel(report.claudeWebVerdict), "warning");
        } else {
          onToast(copy.toast.danger, report.warnings[0] ?? claudeVerdictLabel(report.claudeWebVerdict), "error");
        }
      }
    } catch (err: unknown) {
      setError(typeof err === "string" ? err : err instanceof Error && err.message ? err.message : copy.errors.generic);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runBinAudit(binInput);
  };

  return (
    <>
      <Card
        title={copy.title}
        aside={<Badge>{copy.gateway(resolvedCountry)}</Badge>}
      >
        <p className="zs-t-body subs-lead">{copy.text}</p>

        <form onSubmit={handleSubmit} className="subs-form">
          <Field
            label={copy.fieldLabel}
            value={binInput}
            onChange={handleInputChange}
            onPaste={handlePaste}
            placeholder={copy.placeholder}
            inputMode="numeric"
            autoComplete="off"
            spellCheck={false}
            help={binInput ? copy.help(detectBrand(binInput)) : copy.helpEmpty}
            error={error ?? undefined}
            action={
              <Button type="submit" variant={ctaVariant} disabled={loading || binInput.length < 6}>
                {loading ? copy.checking : copy.check}
              </Button>
            }
          />
        </form>
      </Card>

      {result && (
        <Verdict
          report={result}
          radarStats={radarStats}
          onNavigateToPaymentGuide={onNavigateToPaymentGuide}
        />
      )}
    </>
  );
}

export function Verdict({
  report,
  radarStats,
  onNavigateToPaymentGuide,
}: {
  report: BinReport;
  radarStats?: BinRadarLookupStats | null;
  onNavigateToPaymentGuide?: () => void;
}) {
  const tone = verdictTone(report);
  const word =
    report.status === "unknown"
      ? copy.verdict.unknown
      : tone === "ok"
        ? copy.verdict.ok
        : tone === "warn"
          ? copy.verdict.warn
          : copy.verdict.danger;
  const d = copy.detail;
  const isUnknown = report.status === "unknown" || report.source === "fallbackUnknown";
  const isPrepaid = Boolean(report.isPrepaid) || report.funding === "prepaid";
  const isCommercial = Boolean(report.isCommercial);
  const countryLabel = report.countryCode ? countryName(report.countryCode) || d.none : d.none;
  const fundingText = copy.fundingLabels[report.funding] ?? d.typeFallback;
  const typeWithCorporate = isCommercial
    ? `${fundingText} (${d.corporateNote})`
    : fundingText;
  const bankHeader = report.knownFintechLabel || report.issuerName || copy.bankUnknown;
  const summaryText = report.warnings[0] ?? claudeVerdictLabel(report.claudeWebVerdict);

  return (
    <Card title={copy.resultTitle(report.binPrefix)} aside={bankHeader}>
      <Banner
        tone={tone}
        icon={tone === "ok" ? "check" : "alert"}
        role={tone === "danger" ? "alert" : "status"}
        title={isUnknown ? copy.failClosedTitle : word}
        action={
          report.status !== "ok" && onNavigateToPaymentGuide ? (
            <Button variant="quiet" size="sm" className="subs-banner-action" onClick={onNavigateToPaymentGuide}>
              {copy.guideLink}
            </Button>
          ) : undefined
        }
      >
        {isUnknown ? copy.failClosedText : summaryText}
      </Banner>

      <div className="subs-block-gap">
        <Rows>
          <Row icon="globe" title={countryLabel} sub={d.country} />
          <Row
            icon="key"
            tone={isPrepaid || isCommercial ? "warn" : "neutral"}
            title={typeWithCorporate}
            sub={isCommercial ? d.type : `${d.type} · ${d.personalNote}`}
            trail={
              isPrepaid ? (
                <Badge tone="warn" icon="alert">
                  {d.virtualBadge}
                </Badge>
              ) : undefined
            }
          />
          {report.knownFintechLabel && (
            <Row icon="info" title={report.knownFintechLabel} sub={d.fintech} />
          )}
          <Row
            icon="shield"
            tone={claudeVerdictTone(report.claudeWebVerdict)}
            title={claudeVerdictLabel(report.claudeWebVerdict)}
            sub={d.claudeVerdict}
          />
          {radarStats && (
            <Row
              icon={radarStats.criticalWarning ? "alert" : "info"}
              tone={radarStats.criticalWarning ? "danger" : "neutral"}
              title={radarStats.summaryRu}
              sub={copy.radar.label}
              trail={
                radarStats.criticalWarning && onNavigateToPaymentGuide ? (
                  <Button variant="secondary" size="sm" onClick={onNavigateToPaymentGuide}>
                    {copy.radar.rescueCta}
                  </Button>
                ) : undefined
              }
            />
          )}
        </Rows>
      </div>
    </Card>
  );
}
