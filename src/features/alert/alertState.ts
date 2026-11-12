import type { EnrichedPayload, RiskInterceptPayload } from "../../types";
import { alertDialog } from "../../shared/copy/ru";

/** Состояние окна предупреждения. Пока событий не было, payload === null и окно ничего не рисует. */
export interface AlertState {
  payload: RiskInterceptPayload | null;
  /** Последняя применённая эпоха enriched для текущего id (null — enriched ещё не было). */
  enrichedEpoch: number | null;
  /** Растёт при смене id: Dialog пересоздаётся и таймер стартует заново. */
  generation: number;
}

export type AlertEvent =
  | { type: "detected"; payload: RiskInterceptPayload }
  | { type: "enriched"; payload: EnrichedPayload }
  | { type: "cleared" };

export const initialAlertState: AlertState = { payload: null, enrichedEpoch: null, generation: 0 };

/**
 * Применяет enriched к payload. Возвращает null, если событие чужое (id) или устаревшее (epoch).
 * Общая логика для окна предупреждения и баннера главного окна.
 */
export function applyEnriched(
  payload: RiskInterceptPayload | null,
  lastEpoch: number | null,
  enriched: EnrichedPayload,
): { payload: RiskInterceptPayload; epoch: number } | null {
  if (!payload || payload.id !== enriched.id) return null;
  if (lastEpoch !== null && enriched.epoch < lastEpoch) return null;
  return {
    epoch: enriched.epoch,
    payload: {
      ...payload,
      phase: enriched.phase,
      report: enriched.report ?? payload.report ?? null,
      network_change: { ...(payload.network_change ?? {}), ...enriched.network_change },
    },
  };
}

export function alertReducer(state: AlertState, event: AlertEvent): AlertState {
  switch (event.type) {
    case "detected": {
      const incoming = event.payload;
      if (state.payload && state.payload.id === incoming.id) {
        // Тот же алерт (повтор события или снимок после enriched): более полные данные не затираем.
        const known = state.payload;
        if (known.phase !== "detecting" && incoming.phase === "detecting") return state;
        if (known.phase === "detecting" && incoming.phase === "detecting") return state;
        return { ...state, payload: incoming };
      }
      return { payload: incoming, enrichedEpoch: null, generation: state.generation + 1 };
    }
    case "enriched": {
      const applied = applyEnriched(state.payload, state.enrichedEpoch, event.payload);
      if (!applied) return state;
      return { ...state, payload: applied.payload, enrichedEpoch: applied.epoch };
    }
    case "cleared":
      return { ...initialAlertState, generation: state.generation + 1 };
  }
}

/** «Разрешить» доступна только когда проверка завершена успешно. */
export function canAllow(state: AlertState): boolean {
  return state.payload?.phase === "ready";
}

export function isFailed(state: AlertState): boolean {
  return state.payload?.phase === "failed";
}

export function isDetecting(state: AlertState): boolean {
  return state.payload?.phase === "detecting";
}

export type AllowErrorKind = "stale" | "pending" | "killswitch" | "generic";

/** Код отказа бэкенда на Allow (`AllowErrorCode` в Rust, snake_case). Решение принимается только по нему, текст не разбирается. */
export type AllowErrorCode =
  | "guard_not_running"
  | "blocked_by_manual_killswitch"
  | "alert_stale"
  | "audit_pending"
  | "internal";

/** Тело отказа: `invoke` отклоняется ровно этим объектом. `message` технический, пользователю не показывается. */
export interface AllowError {
  code: AllowErrorCode;
  message: string;
}

/** Сводит отказ бэкенда на Allow к одному из известных видов по полю `code`. Всё незнакомое — generic. */
export function classifyAllowError(err: unknown): AllowErrorKind {
  const code = typeof err === "object" && err !== null ? (err as { code?: unknown }).code : undefined;
  switch (code) {
    case "alert_stale":
      return "stale";
    case "audit_pending":
      return "pending";
    case "blocked_by_manual_killswitch":
      return "killswitch";
    default:
      return "generic";
  }
}

/** Текст для пользователя по виду отказа; единственное место, где вид превращается в слова. */
export function allowErrorText(kind: AllowErrorKind): string {
  switch (kind) {
    case "stale":
      return alertDialog.allowErrorStale;
    case "pending":
      return alertDialog.allowErrorPending;
    case "killswitch":
      return alertDialog.allowErrorKillswitch;
    default:
      return alertDialog.allowErrorGeneric;
  }
}
