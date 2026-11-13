import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { EnrichedPayload, RiskInterceptPayload } from "../../types";
import { alertDialog } from "../../shared/copy/ru";
import { formatCountryWithCode } from "../../shared/lib/country";
import { Dialog } from "../../ui";
import { AlertWindow } from "./AlertWindow";
import { alertReducer, allowErrorText, canAllow, classifyAllowError, initialAlertState, isFailed, isHighRiskAlert } from "./alertState";

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
    expect(classifyAllowError({ code: "alert_stale", message: "x" })).toBe("stale");
  });
  it("аудит не завершён", () => {
    expect(classifyAllowError({ code: "audit_pending", message: "x" })).toBe("pending");
  });
  it("ручной Kill-Switch", () => {
    expect(classifyAllowError({ code: "blocked_by_manual_killswitch", message: "x" })).toBe("killswitch");
  });
  it("прочие коды и незнакомые значения", () => {
    expect(classifyAllowError({ code: "internal", message: "x" })).toBe("generic");
    expect(classifyAllowError({ code: "guard_not_running", message: "x" })).toBe("generic");
    expect(classifyAllowError({ code: "constructor", message: "x" })).toBe("generic");
    expect(classifyAllowError(undefined)).toBe("generic");
    expect(classifyAllowError(null)).toBe("generic");
  });
  it("текст сообщения больше не разбирается", () => {
    expect(classifyAllowError("this alert is no longer current")).toBe("generic");
    expect(classifyAllowError(new Error("the network audit is not finished"))).toBe("generic");
    expect(classifyAllowError({ code: "internal", message: "this alert is no longer current" })).toBe("generic");
  });
});

describe("allowErrorText", () => {
  it("у каждого вида свой текст из copy/ru", () => {
    const texts = (["stale", "pending", "killswitch", "generic"] as const).map(allowErrorText);
    expect(new Set(texts).size).toBe(4);
    expect(allowErrorText("killswitch")).toBe(alertDialog.allowErrorKillswitch);
  });
});

describe("isHighRiskAlert & formatCountryWithCode", () => {
  it("форматирует страну с ISO-кодом и не дублирует неизвестные коды", () => {
    expect(formatCountryWithCode("NL")).toBe("Нидерланды (NL)");
    expect(formatCountryWithCode("ru")).toBe("Россия (RU)");
    expect(formatCountryWithCode("--")).toBe("");
    expect(formatCountryWithCode(null)).toBe("");
  });

  it("считает RU, BY и red высоким риском", () => {
    expect(isHighRiskAlert(null)).toBe(false);
    expect(isHighRiskAlert({ ...detecting(), phase: "ready", network_change: { new_country: "RU" } })).toBe(true);
    expect(isHighRiskAlert({ ...detecting(), phase: "ready", network_change: { new_country: "BY" } })).toBe(true);
    expect(
      isHighRiskAlert({
        ...detecting(),
        phase: "ready",
        network_change: { new_country: "TR" },
        report: {
          provider: "anthropic",
          overall_status: "red",
          trust_score: 20,
          telemetry: { ip: "2.2.2.2", country_code: "TR", resolved_at: 1 },
          geo_result: { status: "ok", code: "OK", message: "ok" },
          pinning_result: { status: "critical", code: "PIN", message: "pin" },
          travel_result: { status: "ok", code: "OK", message: "ok" },
          dnsbl_result: { status: "ok", code: "OK", message: "ok" },
          dnsbl_clean_count: "",
          asn_result: { status: "ok", code: "OK", message: "ok" },
          ipv6_result: { status: "ok", code: "OK", message: "ok" },
          timezone_result: { status: "ok", code: "OK", message: "ok" },
          checks: [],
        },
      }),
    ).toBe(true);
    expect(isHighRiskAlert({ ...detecting(), phase: "ready", network_change: { new_country: "TR" } })).toBe(false);
  });
});

describe("Dialog & AlertWindow (Было → Стало, 2 кнопки)", () => {
  it("Dialog рисует 2 кнопки и блок Было → Стало при наличии previous", () => {
    const html = renderToStaticMarkup(
      createElement(Dialog, {
        title: alertDialog.title,
        text: alertDialog.textDrop,
        service: "Claude",
        ip: "185.220.101.5",
        country: "Турция (TR)",
        previous: { ip: "185.212.102.40", country: "Нидерланды (NL)", label: "Было" },
        actions: [
          { label: alertDialog.block, onSelect: () => {} },
          { label: alertDialog.allow, variant: "danger", onSelect: () => {} },
        ],
      }),
    );
    expect(html).toContain("zs-route-diff");
    expect(html).toContain("Нидерланды (NL)");
    expect(html).toContain("185.212.102.40");
    expect(html).toContain("Турция (TR)");
    expect(html).toContain("185.220.101.5");
    expect(html).toContain(alertDialog.block);
    expect(html).toContain(alertDialog.allow);
    expect(html).not.toContain("Открыть инструкцию");
  });

  it("AlertWindow показывает Было → Стало при смене IP и fallback без old_ip", () => {
    const withOld = renderToStaticMarkup(
      createElement(AlertWindow, {
        initialPayload: {
          ...detecting(),
          phase: "ready",
          network_change: { old_ip: "185.212.102.40", old_country: "NL", new_ip: "185.220.101.5", new_country: "RU" },
        },
      }),
    );
    expect(withOld).toContain("Было");
    expect(withOld).toContain("Стало");
    expect(withOld).toContain("Нидерланды (NL)");
    expect(withOld).toContain("Россия (RU)");
    expect(withOld).toContain("Держать на паузе");
    expect(withOld).toContain("Разрешить принудительно");
    expect(withOld).not.toContain("Открыть инструкцию");

    const withoutOld = renderToStaticMarkup(
      createElement(AlertWindow, {
        initialPayload: {
          ...detecting(),
          scope: "provider",
          phase: "ready",
          network_change: { old_ip: null, old_country: null, new_ip: "185.220.101.5", new_country: "TR" },
        },
      }),
    );
    expect(withoutOld).toContain("zs-route");
    expect(withoutOld).not.toContain("zs-route-diff");
    expect(withoutOld).toContain("Турция (TR)");
    expect(withoutOld).toContain("185.220.101.5");
  });

  it("пока phase === detecting, кнопка Разрешить принудительно отключена", () => {
    const html = renderToStaticMarkup(createElement(AlertWindow, { initialPayload: detecting() }));
    expect(html).toContain("disabled");
  });

  it("AlertWindow рендерит длинное название страны в Было → Стало и обе горячие клавиши 1 и 2", () => {
    const html = renderToStaticMarkup(
      createElement(AlertWindow, {
        initialPayload: {
          ...detecting(),
          phase: "ready",
          network_change: { old_ip: "185.212.102.40", old_country: "NL", new_ip: "104.28.14.99", new_country: "US" },
        },
      }),
    );
    expect(html).toContain("zs-route-diff");
    expect(html).toContain(formatCountryWithCode("US"));
    expect(html).toContain('aria-keyshortcuts="1"');
    expect(html).toContain('aria-keyshortcuts="2"');
  });
});
