import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import type { ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import { isTauri } from "@tauri-apps/api/core";
import type { EnrichedPayload, GuardPauseStatus, InterceptionAction, RiskInterceptPayload } from "../../types";
import {
  MOCK_ALERT_DETECTED_EVENT,
  MOCK_ALERT_ENRICHED_EVENT,
  getGuardPauseStatus,
  getHideIpMode,
  pauseUntilNetworkChange,
  resolveInterception,
  takePendingAlert,
} from "../../utils/api";
import { formatIp, maskIpsInText } from "../../shared/lib/format";
import { Button, Dialog, Skeleton } from "../../ui";
import {
  alertReducer,
  allowErrorText,
  canAllow,
  classifyAllowError,
  initialAlertState,
  isDetecting,
  isFailed,
  isHighRiskAlert,
} from "./alertState";
import type { AlertState } from "./alertState";
import { alertDialog as copy, providers as providerCopy } from "../../shared/copy/ru";
import { formatCountryWithCode } from "../../shared/lib/country";
import { CheckoutAlertView } from "./CheckoutAlertView";
import type { CheckoutResolutionAction } from "./CheckoutAlertView";
import "./alert.css";

export type AlertResolutionAction = InterceptionAction | CheckoutResolutionAction;

export interface AlertWindowProps {
  initialPayload?: RiskInterceptPayload;
  hideIpMode?: boolean;
  onResolved?: (action?: AlertResolutionAction) => void;
}

/**
 * Диалог обрыва VPN (окно Tauri alert-popup и оверлей в браузере).
 * Клавиши совпадают с кнопками: 1 или Esc — держать на паузе до смены сети, 2 — разрешить принудительно.
 */
export function AlertWindow({ initialPayload, hideIpMode: propHideIpMode, onResolved }: AlertWindowProps) {
  const [state, dispatch] = useReducer(
    alertReducer,
    initialPayload,
    (initial): AlertState =>
      initial ? alertReducer(initialAlertState, { type: "detected", payload: initial }) : initialAlertState,
  );
  const [resolving, setResolving] = useState<boolean>(false);
  const [demoFeedback, setDemoFeedback] = useState<string | null>(null);
  const [allowError, setAllowError] = useState<string | null>(null);
  const [confirmForce, setConfirmForce] = useState<boolean>(false);
  const [persistException, setPersistException] = useState<boolean>(false);
  const [stateHideIpMode, setStateHideIpMode] = useState<boolean | null>(null);
  const guardPausedRef = useRef<boolean>(false);

  const { payload } = state;
  const generation = state.generation;
  // Пока fetchAppState() не вернул настройку, маскируем IP по умолчанию, чтобы не было вспышки сырого IP.
  const effectiveHideIpMode = propHideIpMode ?? stateHideIpMode ?? true;

  useEffect(() => {
    if (propHideIpMode !== undefined) return;
    let cancelled = false;
    getHideIpMode()
      .then((hide) => {
        if (!cancelled) setStateHideIpMode(Boolean(hide));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [propHideIpMode]);

  useEffect(() => {
    let unlistenFns: Array<() => void> = [];
    let cancelled = false;
    const track = (p: Promise<() => void>) =>
      p.then((unlisten) => {
        if (cancelled) unlisten();
        else unlistenFns.push(unlisten);
      });

    const syncPendingAlert = () => {
      takePendingAlert()
        .then((snapshot) => {
          if (!cancelled && snapshot && (!guardPausedRef.current || snapshot.is_simulation)) {
            if (snapshot.phase === "detecting") guardPausedRef.current = false;
            dispatch({ type: "detected", payload: snapshot });
          }
        })
        .catch((err) => console.error("Failed to take pending alert:", err));
    };

    if (isTauri()) {
      track(
        listen<GuardPauseStatus>("guard://pause-status-changed", (event) => {
          const paused = Boolean(event.payload?.paused);
          guardPausedRef.current = paused;
          if (paused) dispatch({ type: "cleared" });
        }),
      );
      getGuardPauseStatus()
        .then((status) => {
          if (cancelled) return;
          guardPausedRef.current = Boolean(status?.paused);
          if (guardPausedRef.current) dispatch({ type: "cleared" });
        })
        .catch(() => {});
      track(
        listen<RiskInterceptPayload>("interceptor://risk-detected", (event) => {
          if (event.payload.phase === "detecting" && !event.payload.is_simulation) {
            guardPausedRef.current = false;
          }
          if (guardPausedRef.current && !event.payload.is_simulation) return;
          dispatch({ type: "detected", payload: event.payload });
        }),
      );
      track(
        listen<EnrichedPayload>("interceptor://enriched", (event) => {
          if (guardPausedRef.current) return;
          dispatch({ type: "enriched", payload: event.payload });
        }),
      );
    }

    // Холодный старт окна и пробуждение скрытого WebView при показе: берём актуальный снимок у бэкенда.
    syncPendingAlert();
    const hasDoc = typeof document !== "undefined";
    const onWakeSync = () => {
      if (hasDoc && document.visibilityState === "visible") syncPendingAlert();
    };
    window.addEventListener("focus", syncPendingAlert);
    if (hasDoc) document.addEventListener("visibilitychange", onWakeSync);

    // Мок в браузере (без Tauri): те же события, что шлёт бэкенд.
    const onMockDetected = (e: Event) => {
      dispatch({ type: "detected", payload: (e as CustomEvent<RiskInterceptPayload>).detail });
    };
    const onMockEnriched = (e: Event) => {
      dispatch({ type: "enriched", payload: (e as CustomEvent<EnrichedPayload>).detail });
    };
    window.addEventListener(MOCK_ALERT_DETECTED_EVENT, onMockDetected);
    window.addEventListener(MOCK_ALERT_ENRICHED_EVENT, onMockEnriched);

    return () => {
      cancelled = true;
      unlistenFns.forEach((u) => u());
      unlistenFns = [];
      window.removeEventListener("focus", syncPendingAlert);
      if (hasDoc) document.removeEventListener("visibilitychange", onWakeSync);
      window.removeEventListener(MOCK_ALERT_DETECTED_EVENT, onMockDetected);
      window.removeEventListener(MOCK_ALERT_ENRICHED_EVENT, onMockEnriched);
    };
  }, []);

  // Новый алерт: сбрасываем ошибку, подтверждение и демо-подпись предыдущего.
  useEffect(() => {
    setAllowError(null);
    setDemoFeedback(null);
    setConfirmForce(false);
    setPersistException(false);
  }, [generation]);

  const isDemo = Boolean(payload && (payload.is_simulation || payload.id.startsWith("sim-")));
  const ttl = payload?.ttl_seconds || 60;
  const allowEnabled = canAllow(state);

  const handleAction = useCallback(
    async (action: InterceptionAction, immediate: boolean = false) => {
      if (resolving || !payload) return;
      if (action === "AllowSession" && !allowEnabled) return;
      setResolving(true);
      setAllowError(null);

      if (isDemo) {
        if (immediate) {
          try {
            await resolveInterception(payload.id, action, payload.provider, "simulation");
          } catch (_) {}
          if (onResolved) onResolved(action);
          setResolving(false);
          return;
        }

        setDemoFeedback(action === "AllowSession" ? copy.feedbackAllow : copy.feedbackDefault);

        setTimeout(async () => {
          try {
            await resolveInterception(payload.id, action, payload.provider, "simulation");
          } catch (err) {
            console.error("Failed to resolve demo interception:", err);
          } finally {
            if (onResolved) onResolved(action);
            setResolving(false);
          }
        }, 900);
        return;
      }

      try {
        const applied = await resolveInterception(
          payload.id,
          action,
          payload.provider,
          payload.scope,
          action === "AllowSession" ? persistException : false,
        );
        if (applied && action === "BlockUntilNetworkChange" && payload.scope !== "network") {
          await pauseUntilNetworkChange(payload.gate_reason ?? undefined).catch(() => {});
        }
        if (action === "BlockUntilNetworkChange") {
          guardPausedRef.current = true;
          dispatch({ type: "cleared" });
        }
        if (onResolved) onResolved(action);
      } catch (err) {
        console.error("Failed to resolve interception:", err);
        if (action === "AllowSession") {
          // Бэкенд отказал (алерт устарел или проверка не завершена): окно остаётся, запросы остановлены.
          setAllowError(allowErrorText(classifyAllowError(err)));
        } else if (onResolved) {
          onResolved(action);
        }
      } finally {
        setResolving(false);
      }
    },
    [resolving, isDemo, payload, allowEnabled, persistException, onResolved],
  );

  // Таймер дошёл до нуля: блокируем до смены сети.
  const handleTimeout = useCallback(() => {
    if (!payload) return;
    if (isDemo) {
      resolveInterception(payload.id, "BlockUntilNetworkChange", payload.provider, "simulation").catch(() => {});
      if (onResolved) onResolved("BlockUntilNetworkChange");
    } else {
      handleAction("BlockUntilNetworkChange");
    }
  }, [isDemo, payload, onResolved, handleAction]);

  const handleClose = () => {
    handleAction("BlockUntilNetworkChange", true);
    if (onResolved) onResolved("BlockUntilNetworkChange");
  };

  // Esc — то же, что закрытие окна. Клавиши 1, 2 обрабатывает сам Dialog.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (resolving || !payload || e.key !== "Escape") return;
      e.preventDefault();
      handleAction("BlockUntilNetworkChange", true);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [resolving, payload, handleAction]);

  // До первого события нечего показывать: ни демо-данных, ни пустого диалога.
  if (!payload) return null;

  if (payload.scope === "checkout" || payload.checkout_risk) {
    return (
      <CheckoutAlertView
        payload={payload}
        hideIpMode={effectiveHideIpMode}
        onResolved={(action) => onResolved?.(action)}
      />
    );
  }

  const { report, network_change } = payload;
  const detecting = isDetecting(state);
  const failed = isFailed(state);
  const highRisk = isHighRiskAlert(payload);
  const previousIpRaw = network_change?.old_ip;
  const previousCountry = formatCountryWithCode(network_change?.old_country) || copy.unknownCountry;
  const currentIpRaw = network_change?.new_ip || report?.telemetry?.ip;
  const currentIpNode: ReactNode = currentIpRaw ? (
    formatIp(currentIpRaw, effectiveHideIpMode)
  ) : detecting ? (
    <Skeleton width={96} height={12} />
  ) : (
    copy.unknownIp
  );
  const previousIp = previousIpRaw ? formatIp(previousIpRaw, effectiveHideIpMode) : null;
  const currentCountryCode = network_change?.new_country || report?.telemetry?.country_code || null;
  const service = providerCopy[payload.provider]?.name ?? payload.provider;

  const countryNode: ReactNode = currentCountryCode ? (
    formatCountryWithCode(currentCountryCode) || currentCountryCode
  ) : detecting ? (
    <Skeleton width={72} height={12} />
  ) : (
    copy.unknownCountry
  );

  const reason = isDemo
    ? copy.textDemo
    : previousIp
      ? copy.textDrop
      : currentCountryCode === "RU" || currentCountryCode === "BY"
        ? copy.textRegion
        : copy.textRisk;

  const incomplete = !detecting && !failed && Boolean(report?.incomplete);
  const base = failed ? copy.failedText : detecting ? `${reason} ${copy.detectingHint}` : reason;
  const textBody = incomplete ? `${base} ${copy.textIncomplete}` : base;
  const gateReasonRaw = !failed && payload.gate_reason?.trim() ? payload.gate_reason.trim() : null;
  const gateReason = gateReasonRaw ? maskIpsInText(gateReasonRaw, effectiveHideIpMode) : null;
  const text: ReactNode =
    demoFeedback ??
    allowError ??
    (gateReason ? (
      <>
        <span className="zs-alert-reason">
          {copy.gateReasonPrefix} {gateReason}
        </span>
        {textBody}
      </>
    ) : (
      textBody
    ));

  const locked = resolving || Boolean(demoFeedback);

  const inlineConfirm = confirmForce ? (
    <>
      <p className="zs-dialog__confirm-text">{copy.confirmForceText}</p>
      <label className="zs-dialog__confirm-text mt-2 flex items-start gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={persistException}
          disabled={locked}
          onChange={(e) => setPersistException(e.target.checked)}
        />
        <span>{copy.persistExceptionLabel}</span>
      </label>
      <div className="zs-dialog__confirm-actions">
        <Button size="md" onClick={() => setConfirmForce(false)} disabled={locked}>
          {copy.confirmForceCancel}
        </Button>
        <Button
          variant="danger-solid"
          size="md"
          disabled={locked}
          onClick={() => {
            setConfirmForce(false);
            void handleAction("AllowSession");
          }}
        >
          {copy.confirmForceAccept}
        </Button>
      </div>
    </>
  ) : undefined;

  return (
    <Dialog
      key={`${payload.id}:${generation}`}
      title={copy.title}
      text={text}
      service={service}
      ip={currentIpNode}
      country={countryNode}
      countryTone={detecting && !currentCountryCode ? "neutral" : highRisk ? "danger" : "warn"}
      previous={previousIp ? { ip: previousIp, country: previousCountry, label: copy.was } : null}
      currentLabel={copy.became}
      unknownCountryLabel={copy.unknownCountry}
      demo={isDemo}
      seconds={ttl}
      hotkeys={!confirmForce}
      onTimeout={handleTimeout}
      onClose={handleClose}
      closeLabel={copy.closeLabel}
      inlineConfirm={inlineConfirm}
      actions={[
        { label: copy.block, disabled: locked, onSelect: () => handleAction("BlockUntilNetworkChange") },
        {
          label: copy.allow,
          variant: highRisk ? "danger" : "secondary",
          disabled: locked || !allowEnabled,
          onSelect: () => {
            if (highRisk) setConfirmForce(true);
            else void handleAction("AllowSession");
          },
        },
      ]}
    />
  );
}

/** Страница окна alert-popup: Dialog на прозрачном фоне с полем под тень. */
export function AlertWindowPage() {
  return (
    <div className="zs-root zs-alert-win">
      <AlertWindow />
    </div>
  );
}

/** Оверлей поверх страницы для превью в браузере (без Tauri). */
export function AlertOverlay({ initialPayload, hideIpMode, onResolved }: AlertWindowProps) {
  return (
    <div className="zs-root zs-alert-overlay">
      <AlertWindow initialPayload={initialPayload} hideIpMode={hideIpMode} onResolved={onResolved} />
    </div>
  );
}
