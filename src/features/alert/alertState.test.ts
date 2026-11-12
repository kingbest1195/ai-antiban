import { describe, expect, it } from "vitest";
import type { EnrichedPayload, RiskInterceptPayload } from "../../types";
import { alertReducer, canAllow, classifyAllowError, initialAlertState, isFailed } from "./alertState";

function detecting(id = "a1"): RiskInterceptPayload {
  return {
    id,
    provider: "anthropic",
    host: "api.anthropic.com:443",
    report: null,
    ttl_seconds: 60,
    scope: "network",
    network_change: { old_ip: "1.1.1.1", old_country: "NL", new_ip: "2.2.2.2", new_country: null },
    detected_at_ms: 1,
    phase: "detecting",
  };
}

function enriched(over: Partial<EnrichedPayload> = {}): EnrichedPayload {
  return {
    id: "a1",
    epoch: 5,
    phase: "ready",
    report: null,
    network_change: { old_ip: "1.1.1.1", old_country: "NL", new_ip: "2.2.2.2", new_country: "DE" },
    ...over,
  };
}

describe("alertReducer", () => {
  it("пустое состояние до первого события: ничего не показывается и Allow недоступна", () => {
    expect(initialAlertState.payload).toBeNull();
    expect(canAllow(initialAlertState)).toBe(false);
    expect(alertReducer(initialAlertState, { type: "enriched", payload: enriched() })).toBe(initialAlertState);
  });

  it("detecting -> ready: страна приходит из enriched, Allow открывается", () => {
    const s1 = alertReducer(initialAlertState, { type: "detected", payload: detecting() });
    expect(s1.payload?.phase).toBe("detecting");
    expect(s1.payload?.network_change?.new_country).toBeNull();
    expect(canAllow(s1)).toBe(false);
    const s2 = alertReducer(s1, { type: "enriched", payload: enriched() });
    expect(s2.payload?.phase).toBe("ready");
    expect(s2.payload?.network_change?.new_country).toBe("DE");
    expect(canAllow(s2)).toBe(true);
    expect(s2.generation).toBe(s1.generation);
  });

  it("устаревшая эпоха игнорируется", () => {
    let s = alertReducer(initialAlertState, { type: "detected", payload: detecting() });
    s = alertReducer(s, { type: "enriched", payload: enriched({ epoch: 5 }) });
    const after = alertReducer(s, {
      type: "enriched",
      payload: enriched({ epoch: 4, phase: "failed", network_change: { new_country: "RU" } }),
    });
    expect(after).toBe(s);
    expect(canAllow(after)).toBe(true);
  });

  it("чужой id игнорируется", () => {
    const s = alertReducer(initialAlertState, { type: "detected", payload: detecting() });
    expect(alertReducer(s, { type: "enriched", payload: enriched({ id: "other" }) })).toBe(s);
  });

  it("failed блокирует Allow", () => {
    let s = alertReducer(initialAlertState, { type: "detected", payload: detecting() });
    s = alertReducer(s, { type: "enriched", payload: enriched({ phase: "failed" }) });
    expect(isFailed(s)).toBe(true);
    expect(canAllow(s)).toBe(false);
  });

  it("смена id сбрасывает состояние и эпоху", () => {
    let s = alertReducer(initialAlertState, { type: "detected", payload: detecting("a1") });
    s = alertReducer(s, { type: "enriched", payload: enriched({ epoch: 9 }) });
    const next = alertReducer(s, { type: "detected", payload: detecting("b2") });
    expect(next.payload?.id).toBe("b2");
    expect(next.payload?.phase).toBe("detecting");
    expect(next.enrichedEpoch).toBeNull();
    expect(next.generation).toBe(s.generation + 1);
    // эпоха нового алерта может быть меньше прежней
    const ok = alertReducer(next, { type: "enriched", payload: enriched({ id: "b2", epoch: 1 }) });
    expect(canAllow(ok)).toBe(true);
  });

  it("поздний снимок detecting не откатывает уже полученный ready", () => {
    let s = alertReducer(initialAlertState, { type: "detected", payload: detecting() });
    s = alertReducer(s, { type: "enriched", payload: enriched() });
    expect(alertReducer(s, { type: "detected", payload: detecting() })).toBe(s);
  });
});

describe("classifyAllowError", () => {
  it("устаревший алерт", () => {
    expect(classifyAllowError("this alert is no longer current")).toBe("stale");
  });
  it("аудит не завершён", () => {
    expect(classifyAllowError(new Error("the network audit is not finished"))).toBe("pending");
  });
  it("прочие ошибки", () => {
    expect(classifyAllowError("manual kill-switch is engaged")).toBe("generic");
    expect(classifyAllowError(undefined)).toBe("generic");
  });
});
