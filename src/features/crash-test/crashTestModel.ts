import type { CrashTestStepResult } from "../../types";

/** Канареечный узел шлюза: Rust отправляет тестовый CONNECT именно на него и в ответе его не возвращает. */
export const CANARY_HOST = "canary-test.anthropic.zastava.local";

/** Строка списка «Последние запросы»: хост и время считаются на фронте, остальное берётся из ответа шлюза. */
export interface CrashStreamEntry {
  /** Момент получения ответа, мс; он же ключ строки вместе с порядковым номером шага. */
  at: number;
  host: string;
  latencyMs: number;
  intercepted: boolean;
}

export function toStreamEntry(step: CrashTestStepResult, now: number): CrashStreamEntry {
  return { at: now, host: CANARY_HOST, latencyMs: step.latency_ms, intercepted: step.intercepted_by_killswitch };
}
