import { useCallback, useEffect, useReducer, useState } from "react";
import type { ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import { isTauri } from "@tauri-apps/api/core";
import type { EnrichedPayload, InterceptionAction, RiskInterceptPayload } from "../../types";
import {
  MOCK_ALERT_DETECTED_EVENT,
  MOCK_ALERT_ENRICHED_EVENT,
  resolveInterception,
  takePendingAlert,
} from "../../utils/api";
import { Dialog, Skeleton } from "../../ui";
import { alertReducer, canAllow, classifyAllowError, initialAlertState, isDetecting, isFailed } from "./alertState";
import type { AlertState } from "./alertState";
import { alertDialog as copy, providers as providerCopy } from "../../shared/copy/ru";
import { countryName } from "../../shared/lib/country";
import "./alert.css";

export interface AlertWindowProps {
  initialPayload?: RiskInterceptPayload;
  onResolved?: (action?: InterceptionAction) => void;
}

/**
 * Диалог обрыва VPN (окно Tauri alert-popup и оверлей в браузере).
 * Клавиши прежние по смыслу: 1 — открыть инструкцию и держать блок, 2 — разрешить на сессию, 3 или Esc — блокировать до смены сети.
 * Теперь порядок кнопок на экране совпадает с номерами.
 */
export function AlertWindow({ initialPayload, onResolved }: AlertWindowProps) {
  const [state, dispatch] = useReducer(
    alertReducer,
    initialPayload,
    (initial): AlertState =>
      initial ? alertReducer(initialAlertState, { type: "detected", payload: initial }) : initialAlertState,
  );
  const [resolving, setResolving] = useState<boolean>(false);
  const [demoFeedback, setDemoFeedback] = useState<string | null>(null);
  const [allowError, setAllowError] = useState<string | null>(null);

  const { payload } = state;
  const generation = state.generation;

  useEffect(() => {
    let unlistenFns: Array<() => void> = [];
    let cancelled = false;
    const track = (p: Promise<() => void>) =>
      p.then((unlisten) => {
        if (cancelled) unlisten();
        else unlistenFns.push(unlisten);
      });

    if (isTauri()) {
      track(
        listen<RiskInterceptPayload>("interceptor://risk-detected", (event) => {
          dispatch({ type: "detected", payload: event.payload });
        }),
      );
      track(
        listen<EnrichedPayload>("interceptor://enriched", (event) => {
          dispatch({ type: "enriched", payload: event.payload });
        }),
      );
    }

    // Холодный старт окна: первое событие могло прийти до подписки, берём снимок у бэкенда.
    takePendingAlert()
      .then((snapshot) => {
        if (!cancelled && snapshot) dispatch({ type: "detected", payload: snapshot });
      })
      .catch((err) => console.error("Failed to take pending alert:", err));

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
      window.removeEventListener(MOCK_ALERT_DETECTED_EVENT, onMockDetected);
      window.removeEventListener(MOCK_ALERT_ENRICHED_EVENT, onMockEnriched);
    };
  }, []);

  // Новый алерт: сбрасываем ошибку и демо-подпись предыдущего.
  useEffect(() => {
    setAllowError(null);
    setDemoFeedback(null);
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
        await resolveInterception(payload.id, action, payload.provider, payload.scope);
        if (onResolved) onResolved(action);
      } catch (err) {
        console.error("Failed to resolve interception:", err);
        if (action === "AllowSession") {
          // Бэкенд отказал (алерт устарел или проверка не завершена): окно остаётся, запросы остановлены.
          const kind = classifyAllowError(err);
          setAllowError(
            kind === "stale" ? copy.allowErrorStale : kind === "pending" ? copy.allowErrorPending : copy.allowErrorGeneric,
          );
        } else if (onResolved) {
          onResolved(action);
        }
      } finally {
        setResolving(false);
      }
    },
    [resolving, isDemo, payload, allowEnabled, onResolved],
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

  // Esc — то же, что закрытие окна. Клавиши 1, 2, 3 обрабатывает сам Dialog.
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

  const { report, network_change } = payload;
  const detecting = isDetecting(state);
  const failed = isFailed(state);
  const previousIp = network_change?.old_ip;
  const currentIp = network_change?.new_ip || report?.telemetry?.ip || copy.unknownIp;
  const currentCountryCode = network_change?.new_country || report?.telemetry?.country_code || null;
  const service = providerCopy[payload.provider]?.name ?? payload.provider;

  const countryNode: ReactNode = currentCountryCode ? (
    countryName(currentCountryCode) || currentCountryCode
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

  const text: ReactNode =
    demoFeedback ??
    allowError ??
    (failed ? copy.failedText : detecting ? `${reason} ${copy.detectingHint}` : reason);

  const locked = resolving || Boolean(demoFeedback);

  return (
    <Dialog
      key={`${payload.id}:${generation}`}
      title={copy.title}
      text={text}
      service={service}
      ip={currentIp}
      country={countryNode}
      countryTone={detecting && !currentCountryCode ? "neutral" : failed ? "warn" : "danger"}
      demo={isDemo}
      seconds={ttl}
      onTimeout={handleTimeout}
      onClose={handleClose}
      closeLabel={copy.closeLabel}
      actions={[
        { label: copy.openGuide, icon: "zap", disabled: locked, onSelect: () => handleAction("OpenGuideAndBlock") },
        { label: copy.allow, disabled: locked || !allowEnabled, onSelect: () => handleAction("AllowSession") },
        { label: copy.block, disabled: locked, onSelect: () => handleAction("BlockUntilNetworkChange") },
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
export function AlertOverlay({ initialPayload, onResolved }: AlertWindowProps) {
  return (
    <div className="zs-root zs-alert-overlay">
      <AlertWindow initialPayload={initialPayload} onResolved={onResolved} />
    </div>
  );
}
