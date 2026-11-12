import { describe, expect, it } from "vitest";
import type { CrashTestStepResult } from "../../types";
import { CANARY_HOST, toStreamEntry } from "./crashTestModel";

// Дословно то, что `serde_json` выдаёт для `CrashTestStepResult` в Rust (см. тест в commands/crash_test.rs).
const REAL_PASSED = '{"passed_through":true,"intercepted_by_killswitch":false,"latency_ms":0.42,"current_ip":"203.0.113.7","current_country":"NL","status_text":"Защищено · Маршрут чист (0.4 мс)"}';
const REAL_STOPPED = '{"passed_through":false,"intercepted_by_killswitch":true,"latency_ms":800.0,"current_ip":"203.0.113.7","current_country":"??","status_text":"Таймаут сокета · Запрос не прошёл через шлюз"}';

describe("разбор ответа теста обрыва VPN", () => {
  it("прошедший запрос: хост и время считаются на фронте, а не берутся из ответа", () => {
    const step = JSON.parse(REAL_PASSED) as CrashTestStepResult;
    expect(toStreamEntry(step, 1700000000000)).toEqual({ at: 1700000000000, host: CANARY_HOST, latencyMs: 0.42, intercepted: false });
  });
  it("остановленный запрос помечен перехваченным", () => {
    const step = JSON.parse(REAL_STOPPED) as CrashTestStepResult;
    const e = toStreamEntry(step, 5);
    expect(e.intercepted).toBe(true);
    expect(e.latencyMs).toBe(800);
    expect(e.host).toBe("canary-test.anthropic.zastava.local");
  });
  it("в строке нет undefined: все поля заданы", () => {
    const e = toStreamEntry(JSON.parse(REAL_PASSED), 1);
    expect(Object.values(e).every((v) => v !== undefined)).toBe(true);
  });
});
