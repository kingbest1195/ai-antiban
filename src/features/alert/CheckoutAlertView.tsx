import { useCallback, useEffect, useRef, useState } from "react";
import type { AiPaymentService, BinRadarLookupStats, RiskInterceptPayload } from "../../types";
import {
  allowCheckout15m,
  cancelAndInspect,
  fetchAppState,
  getBinRadarStats,
  getPaymentPassport,
} from "../../utils/api";
import { maskIpsInText } from "../../shared/lib/format";
import { alertDialog as copy } from "../../shared/copy/ru";
import { Badge, Button, Icon, Kbd } from "../../ui";
import type { BadgeTone } from "../../ui";

export type CheckoutResolutionAction = "cancelAndInspect" | "allowCheckout15m";

export interface CheckoutAlertViewProps {
  payload: RiskInterceptPayload;
  hideIpMode: boolean;
  initialRadarStats?: BinRadarLookupStats | null;
  onResolved?: (action: CheckoutResolutionAction) => void;
}

function tierTone(tier?: string): BadgeTone {
  if (tier === "green") return "ok";
  if (tier === "yellow") return "warn";
  return "danger";
}

function inferAiService(provider?: string, domain?: string): AiPaymentService {
  const host = (domain ?? "").toLowerCase();
  if (host.includes("pay.google") || host.includes("gemini") || host.includes("aistudio") || provider === "gemini") {
    return "gemini";
  }
  if (host.includes("openai") || host.includes("chatgpt") || provider === "openai") {
    return "chatgpt";
  }
  if (host.includes("cursor")) {
    return "cursor";
  }
  return "claude_pro";
}

function cleanBinPrefix(raw?: string | null): string | null {
  const digits = (raw ?? "").replace(/[\s-]+/g, "");
  return /^\d{6,8}$/.test(digits) ? digits : null;
}

function radarBadgeTone(stats: BinRadarLookupStats): BadgeTone {
  if (stats.criticalWarning || stats.status === "critical") return "danger";
  if (stats.status === "sufficient") return "ok";
  return "warn";
}

function radarBadgeLabel(stats: BinRadarLookupStats): string {
  if (stats.criticalWarning || stats.status === "critical") return copy.checkout.radarCritical;
  if (stats.status === "sufficient") return copy.checkout.radarOk;
  return copy.checkout.radarInsufficient;
}

/**
 * Карточка предупреждения перед оплатой (440×470) без расшифровки HTTPS.
 * Кнопки: 1 — «Отменить и проверить» (primary), 2 — «Продолжить на свой риск (15 мин)» (secondary).
 */
export function CheckoutAlertView({
  payload,
  hideIpMode,
  initialRadarStats,
  onResolved,
}: CheckoutAlertViewProps) {
  const [busy, setBusy] = useState<boolean>(false);
  const [left, setLeft] = useState<number>(payload.ttl_seconds || 60);
  const [radarStats, setRadarStats] = useState<BinRadarLookupStats | null>(initialRadarStats ?? null);
  const risk = payload.checkout_risk;
  const domain = risk?.domain || payload.host;
  const score = risk?.score ?? 35;
  const tier = risk?.tier ?? "red";
  const rawReason = risk?.reason || payload.gate_reason || copy.checkout.fallbackReason;
  const reason = maskIpsInText(rawReason, hideIpMode);
  const rawAction = risk?.recommendedAction ? maskIpsInText(risk.recommendedAction, hideIpMode) : null;
  const explicitBin = cleanBinPrefix(risk?.binPrefix);
  const service = inferAiService(payload.provider, domain);

  const firedTimeoutRef = useRef(false);

  useEffect(() => {
    if (initialRadarStats !== undefined) {
      setRadarStats(initialRadarStats);
      return;
    }
    let cancelled = false;
    const loadRadar = async () => {
      let targetBin = explicitBin;
      if (!targetBin) {
        const appState = await fetchAppState().catch(() => null);
        const candidates = Array.from(
          new Set(
            [
              appState?.clean_room?.active_profile_id ?? null,
              "default",
              ...(appState?.clean_room?.profiles.map((p) => p.id) ?? []),
            ].filter((id): id is string => Boolean(id && id.trim())),
          ),
        );
        for (const profileId of candidates) {
          const passport = await getPaymentPassport(profileId).catch(() => null);
          const candidateBin = cleanBinPrefix(passport?.binPrefix);
          if (candidateBin) {
            targetBin = candidateBin;
            break;
          }
        }
      }
      if (!targetBin || cancelled) return;
      const stats = await getBinRadarStats(targetBin, service).catch(() => null);
      if (!cancelled && stats) {
        setRadarStats(stats);
      }
    };
    void loadRadar();
    return () => {
      cancelled = true;
    };
  }, [explicitBin, initialRadarStats, payload.id, service]);

  useEffect(() => {
    firedTimeoutRef.current = false;
    setLeft(payload.ttl_seconds || 60);
    const id = window.setInterval(() => {
      setLeft((v) => (v <= 0 ? 0 : v - 1));
    }, 1000);
    return () => window.clearInterval(id);
  }, [payload.id, payload.ttl_seconds]);

  const handleCancelAndInspect = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    try {
      await cancelAndInspect(payload.id, domain);
      onResolved?.("cancelAndInspect");
    } catch (err) {
      console.error("Failed to cancel checkout interception:", err);
    } finally {
      setBusy(false);
    }
  }, [busy, payload.id, domain, onResolved]);

  const handleAllow15m = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    try {
      await allowCheckout15m(payload.id, domain);
      onResolved?.("allowCheckout15m");
    } catch (err) {
      console.error("Failed to allow checkout for 15m:", err);
    } finally {
      setBusy(false);
    }
  }, [busy, payload.id, domain, onResolved]);

  const actionsRef = useRef({
    busy,
    cancel: handleCancelAndInspect,
    allow: handleAllow15m,
  });
  actionsRef.current = {
    busy,
    cancel: handleCancelAndInspect,
    allow: handleAllow15m,
  };

  useEffect(() => {
    if (left === 0 && !firedTimeoutRef.current) {
      firedTimeoutRef.current = true;
      void actionsRef.current.cancel();
    }
  }, [left]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (actionsRef.current.busy || e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey || e.repeat) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
      if (e.key === "1" || e.key === "Escape") {
        e.preventDefault();
        void actionsRef.current.cancel();
      } else if (e.key === "2") {
        e.preventDefault();
        void actionsRef.current.allow();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="checkout-alert-title"
      aria-describedby="checkout-alert-reason"
      className="zs-dialog"
    >
      <div className="zs-dialog__head">
        <h2 className="zs-dialog__title" id="checkout-alert-title">
          {copy.checkout.title}
        </h2>
        <Badge tone="warn" role="timer" aria-label={`Осталось ${left} с`}>
          {left} с
        </Badge>
        <Button
          variant="quiet"
          size="sm"
          iconOnly
          icon="x"
          aria-label={copy.closeLabel}
          onClick={() => void handleCancelAndInspect()}
        />
      </div>

      <p className="zs-dialog__text" id="checkout-alert-reason">
        <span className="zs-alert-reason">{reason}</span>
        {rawAction && <span>{rawAction}</span>}
      </p>

      <div className="zs-route">
        <b>{copy.checkout.serviceLabel}</b>
        <Icon name="arrow" />
        <span className="zs-mono">{domain}</span>
        <Badge tone={tierTone(tier)} icon={tier === "green" ? "check" : "alert"}>
          <span className="zs-tabular">{score} / 100</span>
        </Badge>
      </div>

      {radarStats && (
        <div className="zs-checkout-radar" data-testid="checkout-bin-radar">
          <b>{copy.checkout.radarLabel}</b>
          <span className="zs-mono">{radarStats.binPrefix}</span>
          <span className="zs-checkout-radar__summary">{radarStats.summaryRu}</span>
          <Badge tone={radarBadgeTone(radarStats)} icon={radarStats.status === "sufficient" ? "check" : "alert"}>
            {radarBadgeLabel(radarStats)}
          </Badge>
        </div>
      )}

      <div className="zs-dialog__actions">
        <Button
          variant="primary"
          size="lg"
          block
          icon="shield"
          disabled={busy}
          onClick={() => void handleCancelAndInspect()}
        >
          {copy.checkout.cancelAndInspect}
          <Kbd>1</Kbd>
        </Button>
        <Button
          variant="secondary"
          size="lg"
          block
          disabled={busy}
          onClick={() => void handleAllow15m()}
        >
          {copy.checkout.allow15m}
          <Kbd>2</Kbd>
        </Button>
      </div>
    </div>
  );
}
