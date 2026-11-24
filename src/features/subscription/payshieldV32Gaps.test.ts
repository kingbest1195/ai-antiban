import type { ReactElement } from "react";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  BinRadarLookupStats,
  BinRadarReport,
  BinReport,
  PaymentPassport,
  RiskInterceptPayload,
} from "../../types";

const hookRuntime = vi.hoisted(() => {
  type HookSlot =
    | { kind: "state"; value: unknown }
    | { kind: "ref"; value: { current: unknown } }
    | { kind: "memo"; deps: unknown[] | undefined; value: unknown }
    | { kind: "effect"; deps: unknown[] | undefined; cleanup?: () => void };

  let slots: HookSlot[] = [];
  let cursor = 0;
  let pendingEffects: Array<{ slotIdx: number; fn: () => void | (() => void); deps: unknown[] | undefined }> = [];
  let currentRender: (() => void) | null = null;

  function depsChanged(prev: unknown[] | undefined, next: unknown[] | undefined): boolean {
    if (!prev || !next || prev.length !== next.length) return true;
    for (let i = 0; i < prev.length; i++) if (!Object.is(prev[i], next[i])) return true;
    return false;
  }

  return {
    reset(renderFn: () => void) {
      for (const s of slots) if (s.kind === "effect") s.cleanup?.();
      slots = [];
      cursor = 0;
      pendingEffects = [];
      currentRender = renderFn;
    },
    beginRender() {
      cursor = 0;
    },
    flushEffects() {
      const queue = pendingEffects;
      pendingEffects = [];
      for (const item of queue) {
        const slot = slots[item.slotIdx] as Extract<HookSlot, { kind: "effect" }>;
        slot.cleanup?.();
        slot.deps = item.deps;
        const cleanup = item.fn();
        slot.cleanup = typeof cleanup === "function" ? cleanup : undefined;
      }
    },
    useState<T>(initial: T | (() => T)): [T, (next: T | ((prev: T) => T)) => void] {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = typeof initial === "function" ? (initial as () => T)() : initial;
        slots.push({ kind: "state", value: val });
      }
      const slot = slots[idx] as Extract<HookSlot, { kind: "state" }>;
      const setState = (next: T | ((prev: T) => T)) => {
        const resolved = typeof next === "function" ? (next as (prev: T) => T)(slot.value as T) : next;
        if (!Object.is(slot.value, resolved)) {
          slot.value = resolved;
          if (currentRender) {
            currentRender();
            this.flushEffects();
          }
        }
      };
      return [slot.value as T, setState];
    },
    useRef<T>(initial: T): { current: T } {
      const idx = cursor++;
      if (idx >= slots.length) slots.push({ kind: "ref", value: { current: initial } });
      return (slots[idx] as Extract<HookSlot, { kind: "ref" }>).value as { current: T };
    },
    useMemo<T>(factory: () => T, deps: unknown[]): T {
      const idx = cursor++;
      if (idx >= slots.length) {
        const value = factory();
        slots.push({ kind: "memo", deps, value });
        return value;
      }
      const slot = slots[idx] as Extract<HookSlot, { kind: "memo" }>;
      if (depsChanged(slot.deps, deps)) {
        slot.deps = deps;
        slot.value = factory();
      }
      return slot.value as T;
    },
    useCallback<T extends (...args: never[]) => unknown>(fn: T, deps: unknown[]): T {
      return this.useMemo(() => fn, deps);
    },
    useEffect(fn: () => void | (() => void), deps?: unknown[]) {
      const idx = cursor++;
      if (idx >= slots.length) {
        slots.push({ kind: "effect", deps: undefined });
        pendingEffects.push({ slotIdx: idx, fn, deps });
      } else {
        const slot = slots[idx] as Extract<HookSlot, { kind: "effect" }>;
        if (depsChanged(slot.deps, deps)) pendingEffects.push({ slotIdx: idx, fn, deps });
      }
    },
  };
});

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: hookRuntime.useState.bind(hookRuntime),
    useRef: hookRuntime.useRef.bind(hookRuntime),
    useMemo: hookRuntime.useMemo.bind(hookRuntime),
    useCallback: hookRuntime.useCallback.bind(hookRuntime),
    useEffect: hookRuntime.useEffect.bind(hookRuntime),
  };
});

const apiMocks = vi.hoisted(() => ({
  checkCardBin: vi.fn(async (bin: string): Promise<BinReport> => ({
    binPrefix: bin,
    status: "ok",
    scheme: "VISA",
    funding: "debit",
    isPrepaid: false,
    isCommercial: false,
    isReloadable: null,
    cardCategory: "CLASSIC",
    countryCode: "US",
    issuerName: "MOCK BANK",
    knownFintechLabel: null,
    source: "localOverlay",
    claudeWebVerdict: "safeAligned",
    warnings: [],
  })),
  getBinRadarStats: vi.fn(async (binPrefix: string): Promise<BinRadarLookupStats> => ({
    binPrefix,
    service: "claude_pro",
    status: "critical",
    sampleSize14d: 34,
    sampleSize30d: 61,
    window14d: {
      n: 34,
      success_pct: 14.7,
      soft_decline_pct: 20.6,
      instant_kyc_pct: 52.9,
      instant_ban_pct: 11.8,
    },
    window30d: null,
    riskPct14d: 64.7,
    criticalWarning: true,
    summaryRu: "Успех 15% · Проверка паспорта/отказ 65% · Отклонено 21% · За 14 дн., n=34",
  })),
  setBinRadarOptIn: vi.fn(async (enabled: boolean) => enabled),
  submitBinRadarReport: vi.fn(async (report: Record<string, unknown>) => report as unknown as BinRadarReport),
  evaluatePaymentReadiness: vi.fn(async (params: Record<string, unknown>) => ({
    score: 90,
    tier: "green" as const,
    axes: {
      networkBase: { id: "network_base", label: "Подключение", score: 25, maxScore: 25, status: "ok" as const, notes: [] },
      cardBin: { id: "card_bin", label: "Карта", score: 30, maxScore: 30, status: "ok" as const, notes: [] },
      geoBillingParity: { id: "geo_billing_parity", label: "Совпадение стран", score: 25, maxScore: 25, status: "ok" as const, notes: [] },
      channelEnvWarmup: { id: "channel_env_warmup", label: "Среда и прогрев", score: 20, maxScore: 20, status: "ok" as const, notes: [] },
    },
    warnings: [],
    blockers: [],
    recommendedAction: null,
    requiresMatchingBilling: false,
    failClosedBin: false,
    channel: (params.channel as "googlePlayIap" | undefined) ?? "directCard",
    evaluatedAt: 1,
  })),
  fetchAppState: vi.fn(async () => ({
    pinned_ip: "185.10.10.1",
    strict_pinning_enabled: true,
    ip_history: {},
    session_allowed_providers: [],
    blocked_providers: [],
    bin_radar_opt_in: false,
    clean_room: { active_profile_id: "cr-1", profiles: [{ id: "cr-1" }], tainted_ips: {} },
  })),
  getPaymentPassport: vi.fn(async (): Promise<PaymentPassport | null> => ({
    profileId: "cr-1",
    binPrefix: "49372400",
    cardCountry: "SG",
    channel: "directCard",
    billingCountry: "SG",
    exitIp: "185.10.10.1",
    exitAsn: null,
    paidAt: 1_760_000_000,
  })),
}));

vi.mock("../../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/api")>();
  return { ...actual, ...apiMocks };
});

import { subscription as copy } from "../../shared/copy/ru";
import { Button, Segmented, Select, Switch } from "../../ui";
import { CheckoutAlertView } from "../alert/CheckoutAlertView";
import { CardCheck, Verdict } from "./CardCheck";
import { PaymentReadinessCard } from "./PaymentReadinessCard";

function collectElements(
  node: unknown,
  predicate: (el: ReactElement<Record<string, unknown>>) => boolean,
  out: ReactElement<Record<string, unknown>>[] = [],
): ReactElement<Record<string, unknown>>[] {
  if (!node || typeof node !== "object") return out;
  if (Array.isArray(node)) {
    for (const item of node) collectElements(item, predicate, out);
    return out;
  }
  const el = node as ReactElement<Record<string, unknown>>;
  if ("type" in el && "props" in el) {
    if (predicate(el)) out.push(el);
    if (el.props?.children) collectElements(el.props.children, predicate, out);
    if (el.props?.action) collectElements(el.props.action, predicate, out);
    if (el.props?.aside) collectElements(el.props.aside, predicate, out);
    if (el.props?.trail) collectElements(el.props.trail, predicate, out);
  }
  return out;
}

function mountNode(renderFn: () => unknown) {
  let tree: unknown = null;
  const render = () => {
    hookRuntime.beginRender();
    tree = renderFn();
  };
  hookRuntime.reset(render);
  render();
  hookRuntime.flushEffects();
  return {
    get tree() {
      return tree;
    },
    async settle() {
      for (let i = 0; i < 6; i++) {
        await Promise.resolve();
      }
      hookRuntime.flushEffects();
    },
  };
}

function makeCheckoutPayload(over: Partial<RiskInterceptPayload> = {}): RiskInterceptPayload {
  return {
    id: "chk-radar-1",
    provider: "anthropic",
    host: "checkout.stripe.com",
    report: null,
    ttl_seconds: 60,
    scope: "checkout",
    checkout_risk: {
      domain: "checkout.stripe.com",
      score: 35,
      tier: "red",
      reason: "Конфликт стран карты и подключения",
      blockers: ["Конфликт стран"],
      warnings: [],
    },
    detected_at_ms: 1,
    phase: "ready",
    ...over,
  };
}

describe("Spec v3.2.0 gaps: Google Play IAP, BIN Radar opt-in/submit, and CheckoutAlertView BIN Radar", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    if (typeof (globalThis as Record<string, unknown>).window === "undefined") {
      (globalThis as Record<string, unknown>).window = {
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        setInterval: vi.fn(() => 1),
        clearInterval: vi.fn(),
      };
    }
  });

  it("PaymentReadinessCard включает googlePlayIap в channelOptions и передаёт его в evaluatePaymentReadiness", async () => {
    const mounted = mountNode(() =>
      PaymentReadinessCard({
        exitCountry: "US",
        inCleanRoom: true,
        hideChannelAppleIap: false,
      }),
    );
    await mounted.settle();

    const seg = collectElements(
      mounted.tree,
      (el) => el.type === Segmented && el.props["aria-label"] === copy.readiness.channelLabel,
    )[0];
    expect(seg).toBeDefined();
    const options = seg.props.options as Array<{ value: string; label: string }>;
    expect(options.some((o) => o.value === "googlePlayIap" && o.label === copy.readiness.channels.googlePlayIap)).toBe(true);

    (seg.props.onChange as (next: "googlePlayIap") => void)("googlePlayIap");
    await mounted.settle();

    expect(apiMocks.evaluatePaymentReadiness).toHaveBeenLastCalledWith(
      expect.objectContaining({ channel: "googlePlayIap" }),
    );
    const gpSelect = collectElements(
      mounted.tree,
      (el) => el.type === Select && el.props.label === copy.readiness.googleProfileLabel,
    )[0];
    expect(gpSelect).toBeDefined();

    // hideChannelAppleIap=true также включает googlePlayIap
    const cardFlowMount = mountNode(() =>
      PaymentReadinessCard({
        exitCountry: "US",
        inCleanRoom: true,
        hideChannelAppleIap: true,
      }),
    );
    await cardFlowMount.settle();
    const cardFlowSeg = collectElements(
      cardFlowMount.tree,
      (el) => el.type === Segmented && el.props["aria-label"] === copy.readiness.channelLabel,
    )[0];
    const cardFlowOpts = cardFlowSeg.props.options as Array<{ value: string }>;
    expect(cardFlowOpts.some((o) => o.value === "googlePlayIap")).toBe(true);
  });

  it("CardCheck переключает bin_radar_opt_in через setBinRadarOptIn и отправляет отчёт через submitBinRadarReport", async () => {
    const onToast = vi.fn();
    const mounted = mountNode(() =>
      CardCheck({
        exitCountry: "US",
        targetService: "claude_pro",
        paymentChannel: "directCard",
        billingCountry: "US",
        onToast,
      }),
    );
    await mounted.settle();

    const optInSwitch = collectElements(mounted.tree, (el) => el.type === Switch)[0];
    expect(optInSwitch).toBeDefined();
    expect(optInSwitch.props.checked).toBe(false);

    // Включаем opt-in
    await (optInSwitch.props.onChange as (next: boolean) => Promise<void>)(true);
    await mounted.settle();
    expect(apiMocks.setBinRadarOptIn).toHaveBeenCalledWith(true);

    const optInSwitchAfter = collectElements(mounted.tree, (el) => el.type === Switch)[0];
    expect(optInSwitchAfter.props.checked).toBe(true);

    // Проверяем 8-значный BIN и отправляем анонимный отчёт
    const field = collectElements(mounted.tree, (el) => typeof el.props.onChange === "function" && el.props.inputMode === "numeric")[0];
    (field.props.onChange as (e: { target: { value: string } }) => void)({ target: { value: "48331200" } });
    const form = collectElements(mounted.tree, (el) => el.type === "form")[0];
    await (form.props.onSubmit as (e: { preventDefault: () => void }) => Promise<void>)({ preventDefault: vi.fn() });
    await mounted.settle();

    const verdictEl = collectElements(mounted.tree, (el) => el.type === Verdict)[0];
    expect(verdictEl).toBeDefined();
    expect(verdictEl.props.binRadarOptIn).toBe(true);

    const verdictMount = mountNode(() =>
      Verdict(verdictEl.props as unknown as Parameters<typeof Verdict>[0]),
    );
    const outcomeSelect = collectElements(
      verdictMount.tree,
      (el) => el.type === Select && el.props.label === copy.card.radar.submitLabel,
    )[0];
    expect(outcomeSelect).toBeDefined();
    (outcomeSelect.props.onChange as (e: { target: { value: string } }) => void)({ target: { value: "instant_kyc" } });

    const submitBtn = collectElements(
      verdictMount.tree,
      (el) => el.type === Button && String(el.props.children).includes(copy.card.radar.submitButton),
    )[0];
    expect(submitBtn).toBeDefined();
    await (submitBtn.props.onClick as () => Promise<void>)();
    await mounted.settle();

    expect(apiMocks.submitBinRadarReport).toHaveBeenCalledWith(
      expect.objectContaining({
        bin_prefix: "48331200",
        service: "claude_pro",
        channel: "stripe_web_card",
        geo_match: "full_match",
        outcome: "instant_kyc",
      }),
    );

    // 6-значный BIN не даёт отправить невалидный 6-значный префикс
    const sixDigitVerdictHtml = renderToStaticMarkup(
      createElement(Verdict, {
        report: {
          binPrefix: "483312",
          status: "ok",
          scheme: "VISA",
          funding: "debit",
          isPrepaid: false,
          isCommercial: false,
          isReloadable: null,
          cardCategory: null,
          countryCode: "US",
          issuerName: "MOCK",
          knownFintechLabel: null,
          source: "localOverlay",
          claudeWebVerdict: "safeAligned",
          warnings: [],
        },
        binRadarOptIn: true,
      }),
    );
    expect(sixDigitVerdictHtml).toContain(copy.card.radar.need8DigitsHint);
    expect(sixDigitVerdictHtml).not.toContain(copy.card.radar.submitButton);
  });

  it("CheckoutAlertView подтягивает BIN из паспорта, вызывает getBinRadarStats и отображает компактный read-only статус", async () => {
    const payload = makeCheckoutPayload({
      provider: "gemini",
      host: "pay.google.com",
      checkout_risk: {
        domain: "pay.google.com",
        score: 30,
        tier: "red",
        reason: "Конфликт страны Google",
        blockers: ["Конфликт стран"],
        warnings: [],
      },
    });
    const mounted = mountNode(() => CheckoutAlertView({ payload, hideIpMode: false }));
    await mounted.settle();

    expect(apiMocks.getPaymentPassport).toHaveBeenCalledWith("cr-1");
    expect(apiMocks.getBinRadarStats).toHaveBeenCalledWith("49372400", "gemini");

    const radarEl = collectElements(
      mounted.tree,
      (el) => el.props["data-testid"] === "checkout-bin-radar",
    )[0];
    expect(radarEl).toBeDefined();

    const ssrHtml = renderToStaticMarkup(
      createElement(CheckoutAlertView, {
        payload,
        hideIpMode: false,
        initialRadarStats: {
          binPrefix: "49372400",
          service: "gemini",
          status: "critical",
          sampleSize14d: 18,
          sampleSize30d: 30,
          window14d: null,
          window30d: null,
          riskPct14d: 50,
          criticalWarning: true,
          summaryRu: "Успех 28% · Проверка паспорта/отказ 50% · Отклонено 22% · За 14 дн., n=18",
        },
      }),
    );
    expect(ssrHtml).toContain("49372400");
    expect(ssrHtml).toContain("n=18");
    expect(ssrHtml).not.toContain("PayShield");
    expect(ssrHtml).not.toContain("Чекаут");
    expect(ssrHtml).not.toContain("!");
  });
});
