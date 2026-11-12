import type { EnrichedPayload, RiskInterceptPayload } from "../../types";

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

export type AllowErrorKind = "stale" | "pending" | "generic";

/** Сводит текст отказа бэкенда на Allow к одному из известных видов (сам текст пользователю не показывается). */
export function classifyAllowError(err: unknown): AllowErrorKind {
  const msg = (err instanceof Error ? err.message : String(err ?? "")).toLowerCase();
  if (msg.includes("no longer current")) return "stale";
  if (msg.includes("audit is not finished")) return "pending";
  return "generic";
}
