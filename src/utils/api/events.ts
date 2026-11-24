import type {
  AuditProgressEvent,
  CoworkGuardStatus,
  GuardPauseStatus,
  RiskReport,
  RouteUnavailablePayload,
  ShutdownProgressPayload,
  StartupSnapshot,
} from "../../types";
import { isTauri, tauriListen, tauriOnWindowFocusChanged } from "./client";
import {
  currentMockStartup,
  MOCK_AUDIT_PROGRESS_EVENT,
  MOCK_AUDIT_REFRESHED_EVENT,
  MOCK_STARTUP_EVENT,
} from "./mocks/audit";
import { MOCK_OPEN_PAYMENT_CHECK_EVENT } from "./mocks/payment";

/** Как доставляются куски аудита: событие Tauri или событие окна в браузере. */
export async function onAuditProgress(
  handler: (event: AuditProgressEvent) => void,
): Promise<() => void> {
  if (isTauri()) {
    return await tauriListen<AuditProgressEvent>("audit://progress", handler);
  }
  const listener = (e: Event) => handler((e as CustomEvent<AuditProgressEvent>).detail);
  window.addEventListener(MOCK_AUDIT_PROGRESS_EVENT, listener);
  return () => window.removeEventListener(MOCK_AUDIT_PROGRESS_EVENT, listener);
}

/** Фоновое обновление отчёта от стража/трея: обновляет timestamp и основной отчёт без ручного рескана. */
export async function onAuditRefreshed(
  handler: (report: RiskReport) => void,
): Promise<() => void> {
  if (isTauri()) {
    return await tauriListen<RiskReport>("audit://refreshed", handler);
  }
  const listener = (e: Event) => handler((e as CustomEvent<RiskReport>).detail);
  window.addEventListener(MOCK_AUDIT_REFRESHED_EVENT, listener);
  return () => window.removeEventListener(MOCK_AUDIT_REFRESHED_EVENT, listener);
}

export async function onStartupChanged(
  handler: (snapshot: StartupSnapshot) => void,
): Promise<() => void> {
  if (isTauri()) {
    return await tauriListen<StartupSnapshot>("startup://phase", handler);
  }
  currentMockStartup();
  const listener = (e: Event) => handler((e as CustomEvent<StartupSnapshot>).detail);
  window.addEventListener(MOCK_STARTUP_EVENT, listener);
  return () => window.removeEventListener(MOCK_STARTUP_EVENT, listener);
}

/** Фокус окна приложения: в Tauri через событие окна, в браузере — без подписки. Возвращает отписку. */
export async function onWindowFocusChanged(
  handler: (focused: boolean) => void,
): Promise<() => void> {
  return await tauriOnWindowFocusChanged(handler);
}

export async function onCoworkGuardStatus(
  handler: (status: CoworkGuardStatus) => void,
): Promise<() => void> {
  if (!isTauri()) return () => {};
  return await tauriListen<CoworkGuardStatus>("cowork-guard://status", handler);
}

export async function onRouteUnavailable(
  handler: (payload: RouteUnavailablePayload) => void,
): Promise<() => void> {
  if (!isTauri()) return () => {};
  return await tauriListen<RouteUnavailablePayload>("route://unavailable", handler);
}

export async function onGuardPauseStatusChanged(
  handler: (status: GuardPauseStatus) => void,
): Promise<() => void> {
  if (!isTauri()) return () => {};
  return await tauriListen<GuardPauseStatus>("guard://pause-status-changed", handler);
}

export async function onShutdownProgress(
  handler: (payload: ShutdownProgressPayload) => void,
): Promise<() => void> {
  if (!isTauri()) return () => {};
  return await tauriListen<ShutdownProgressPayload>("app://shutdown-progress", handler);
}

export async function onDeepLink(
  handler: (link: string) => void,
): Promise<() => void> {
  if (!isTauri()) return () => {};
  return await tauriListen<string>("zastava://deep-link", handler);
}

export async function onSysproxyAdminAuthRequired(
  handler: (message: string) => void,
): Promise<() => void> {
  if (!isTauri()) return () => {};
  return await tauriListen<string>("sysproxy://admin-auth-required", handler);
}

export async function onInterceptorResolved(
  handler: (payload?: import("../../types").InterceptorResolvedPayload) => void,
): Promise<() => void> {
  if (!isTauri()) return () => {};
  return await tauriListen<import("../../types").InterceptorResolvedPayload | undefined>(
    "interceptor://resolved",
    (payload) => handler(payload),
  );
}

/** Событие PayShield из alert-popup: открыть экран проверки оплаты в главном окне. */
export async function onOpenPaymentCheck(
  handler: (domain: string) => void,
): Promise<() => void> {
  if (isTauri()) {
    return await tauriListen<string>("payshield://open-payment-check", handler);
  }
  const listener = (e: Event) => handler((e as CustomEvent<string>).detail ?? "");
  window.addEventListener(MOCK_OPEN_PAYMENT_CHECK_EVENT, listener);
  return () => window.removeEventListener(MOCK_OPEN_PAYMENT_CHECK_EVENT, listener);
}
