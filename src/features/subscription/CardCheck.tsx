import { useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import type { BinAuditResult } from "../../types";
import { checkPaymentBin } from "../../utils/api";
import { Badge, Banner, Button, Card, Field, InfoTip, Mono, Row, Rows, Section } from "../../ui";
import type { BannerTone } from "../../ui";
import { subscription } from "../../shared/copy/ru";
import { countryName } from "../../shared/lib/country";
import type { ShowToast } from "../../shared/hooks";
import { detectBrand } from "./binBrand";

const copy = subscription.card;

export interface CardCheckProps {
  /** Страна выхода: BIN проверяется относительно неё. */
  country?: string;
  /** Явный код страны выхода (алиас для встраивания в «Чистую комнату»). */
  exitCountry?: string;
  onToast?: ShowToast;
  onNavigateToPaymentGuide?: () => void;
}

/** Как и раньше: ok — совместимо, warning — внимание, всё остальное — отклонено. */
function verdictTone(status: BinAuditResult["status"]): BannerTone {
  if (status === "ok") return "ok";
  if (status === "warning") return "warn";
  return "danger";
}

/** Проверка BIN: поле и кнопка, вердикт словом (Banner нужного тона) и детали строками. */
export function CardCheck({ country, exitCountry, onToast, onNavigateToPaymentGuide }: CardCheckProps) {
  const resolvedCountry =
    exitCountry && exitCountry !== "--"
      ? exitCountry
      : country && country !== "--"
        ? country
        : "NL";
  const [binInput, setBinInput] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<BinAuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    setBinInput(e.target.value.replace(/\D/g, "").slice(0, 8));
    setError(null);
  };

  const runBinAudit = async (rawBin: string) => {
    const clean = rawBin.replace(/\D/g, "");

    if (clean.length < 6) {
      setError(copy.errors.tooShort);
      return;
    }
    if (clean.length > 8) {
      setError(copy.errors.tooLong);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await checkPaymentBin(clean, resolvedCountry);
      setResult(res);
      if (onToast) {
        if (res.status === "ok") {
          onToast(copy.toast.ok, copy.toast.okText(res.bank_name || copy.toast.okBank, res.country_code ?? ""), "success");
        } else if (res.status === "warning") {
          onToast(copy.toast.warn, res.advisory, "warning");
        } else {
          onToast(copy.toast.danger, res.advisory, "error");
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

  const pickExample = (bin: string) => {
    setBinInput(bin);
    void runBinAudit(bin);
  };

  return (
    <>
      <Card
        title={copy.title}
        aside={
          <span className="zs-field-row">
            <Badge>{copy.gateway(resolvedCountry)}</Badge>
            <InfoTip
              title="Проверка BIN и IP"
              text="BIN (первые 6–8 цифр карты) определяет страну банка-эмитента и тип карты. Для Stripe важно, чтобы страна IP выхода совпадала со страной карты (IP ≈ Card)."
            />
          </span>
        }
      >
        <p className="zs-t-body subs-lead">{copy.text}</p>

        <form onSubmit={handleSubmit} className="subs-form">
          <Field
            label={copy.fieldLabel}
            value={binInput}
            onChange={handleInputChange}
            placeholder={copy.placeholder}
            inputMode="numeric"
            autoComplete="off"
            spellCheck={false}
            maxLength={8}
            help={binInput ? copy.help(detectBrand(binInput)) : copy.helpEmpty}
            error={error ?? undefined}
            action={
              <Button type="submit" variant="primary" disabled={loading || binInput.length < 6}>
                {loading ? copy.checking : copy.check}
              </Button>
            }
          />
        </form>

        <div className="subs-examples">
          <span className="zs-t-caption subs-examples__label">{copy.examples}</span>
          {copy.exampleList.map((ex) => (
            <Button key={ex.bin} size="sm" disabled={loading} onClick={() => pickExample(ex.bin)}>
              <Mono>{ex.bin}</Mono> {ex.label}
            </Button>
          ))}
        </div>
      </Card>

      {result && <Verdict result={result} onNavigateToPaymentGuide={onNavigateToPaymentGuide} />}
    </>
  );
}

export function Verdict({
  result,
  onNavigateToPaymentGuide,
}: {
  result: BinAuditResult;
  onNavigateToPaymentGuide?: () => void;
}) {
  const tone = verdictTone(result.status);
  const word = tone === "ok" ? copy.verdict.ok : tone === "warn" ? copy.verdict.warn : copy.verdict.danger;
  const d = copy.detail;
  const type = result.card_type || d.typeFallback;
  const country = result.country_code;

  return (
    <Section title={copy.analysis}>
      <Banner
        tone={tone}
        icon={tone === "ok" ? "check" : "alert"}
        role={tone === "danger" ? "alert" : "status"}
        title={word}
        action={
          result.status !== "ok" && onNavigateToPaymentGuide ? (
            <Button variant="quiet" size="sm" className="subs-banner-action" onClick={onNavigateToPaymentGuide}>
              {copy.guideLink}
            </Button>
          ) : undefined
        }
      >
        {result.advisory}
      </Banner>

      <Card title={copy.resultTitle(result.bin)} aside={result.bank_name || copy.bankUnknown}>
        <Rows>
          <Row
            icon="globe"
            title={country ? <Mono>{country}</Mono> : d.none}
            sub={countryName(country) ? `${d.country} · ${countryName(country)}` : d.country}
          />
          <Row
            icon="key"
            tone={result.is_prepaid ? "warn" : "neutral"}
            title={<Mono>{type}</Mono>}
            sub={d.type}
            trail={
              result.is_prepaid ? (
                <Badge tone="warn" icon="alert">
                  {d.prepaid}
                </Badge>
              ) : undefined
            }
          />
          <Row
            icon="lock"
            tone={result.is_prepaid ? "danger" : "ok"}
            title={d.virtual}
            trail={
              result.is_prepaid ? (
                <Badge tone="danger" icon="alert">
                  {d.virtualYes}
                </Badge>
              ) : (
                <Badge tone="ok" icon="check">
                  {d.virtualNo}
                </Badge>
              )
            }
          />
        </Rows>
      </Card>
    </Section>
  );
}
