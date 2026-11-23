import type { ReactElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AppStateData,
  PaymentPassport,
  PostPaymentQuarantineStatus,
  RiskInterceptPayload,
  RouteView,
  RoutesSnapshot,
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
    useReducer<S, A, I = S>(
      reducer: (state: S, action: A) => S,
      initialArg: I,
      init?: (arg: I) => S,
    ): [S, (action: A) => void] {
      const [state, setState] = this.useState<S>(() =>
        init ? init(initialArg) : (initialArg as unknown as S),
      );
      return [state, (action: A) => setState((prev) => reducer(prev, action))];
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
    useReducer: hookRuntime.useReducer.bind(hookRuntime),
    useEffect: hookRuntime.useEffect.bind(hookRuntime),
  };
});

const apiMocks = vi.hoisted(() => ({
  checkCardBin: vi.fn(async (bin: string) => ({
    binPrefix: bin,
    status: "ok" as const,
    scheme: "VISA",
    funding: "debit" as const,
    isPrepaid: false,
    isCommercial: false,
    isReloadable: null,
    cardCategory: "CLASSIC",
    countryCode: "KZ",
    issuerName: "KASPI BANK",
    knownFintechLabel: "Kaspi Gold (KZ)",
    source: "localOverlay" as const,
    claudeWebVerdict: "needsMatchingIpBilling" as const,
    warnings: [],
  })),
  evaluatePaymentReadiness: vi.fn(async () => ({
    score: 70,
    tier: "yellow" as const,
    axes: {
      networkBase: { id: "network_base", label: "Подключение", score: 25, maxScore: 25, status: "ok" as const, notes: [] },
      cardBin: { id: "card_bin", label: "Карта", score: 25, maxScore: 30, status: "ok" as const, notes: [] },
      geoBillingParity: { id: "geo_billing_parity", label: "Совпадение стран", score: 10, maxScore: 25, status: "warning" as const, notes: [] },
      channelEnvWarmup: { id: "channel_env_warmup", label: "Среда и прогрев", score: 10, maxScore: 20, status: "warning" as const, notes: [] },
    },
    warnings: [],
    blockers: [],
    recommendedAction: "Проверьте страну адреса оплаты.",
    requiresMatchingBilling: true,
    failClosedBin: false,
    channel: "directCard" as const,
    evaluatedAt: 1,
  })),
  cancelAndInspect: vi.fn(async () => true),
  allowCheckout15m: vi.fn(async () => true),
  activatePostPaymentQuarantine: vi.fn(async (): Promise<PostPaymentQuarantineStatus> => ({
    active: true,
    remainingHours: 72,
    remainingSecs: 72 * 3600,
    quarantine: { startedAt: 1000, expiresAt: 1000 + 72 * 3600, pinnedCountry: "US", pinnedExitIp: "185.10.10.1" },
    warning: null,
  })),
  getPostPaymentQuarantineStatus: vi.fn(async (): Promise<PostPaymentQuarantineStatus> => ({
    active: true,
    remainingHours: 70,
    remainingSecs: 70 * 3600,
    quarantine: { startedAt: 1000, expiresAt: 1000 + 72 * 3600, pinnedCountry: "US" },
    warning: "Активна 72-часовая защита маршрута",
  })),
  overridePostPaymentQuarantine: vi.fn(async (): Promise<PostPaymentQuarantineStatus> => ({
    active: false,
    remainingHours: 0,
    remainingSecs: 0,
    quarantine: null,
    warning: null,
  })),
  getPaymentPassport: vi.fn(async (): Promise<PaymentPassport | null> => null),
  savePaymentPassport: vi.fn(async (p: PaymentPassport): Promise<PaymentPassport> => p),
  setDefaultRoute: vi.fn(async (): Promise<RoutesSnapshot> => ({
    routes: [], provider_routes: {}, effective: {}, dangling: [],
  })),
  bindProviderRoute: vi.fn(async (): Promise<RoutesSnapshot> => ({
    routes: [], provider_routes: {}, effective: {}, dangling: [],
  })),
  toggleUpstreamProxy: vi.fn(async (enabled: boolean) => ({
    enabled, raw_key: "https://legacy.example.com:443", protocol: "https", host: "legacy.example.com", port: 443,
  })),
  clearUpstreamProxy: vi.fn(async () => {}),
  takePendingAlert: vi.fn(async () => null),
  fetchAppState: vi.fn(async () => ({
    pinned_ip: null, strict_pinning_enabled: true, ip_history: {}, session_allowed_providers: [], blocked_providers: [], hide_ip_mode: false,
  })),
}));

vi.mock("../../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/api")>();
  return { ...actual, ...apiMocks };
});

import { alertDialog, connect as connectCopy, subscription as copy } from "../../shared/copy/ru";
import { Button, Field, Segmented, Select, Switch } from "../../ui";
import { AlertWindow } from "../alert/AlertWindow";
import { CheckoutAlertView } from "../alert/CheckoutAlertView";
import { ConnectScreen } from "../connect/ConnectScreen";
import { ProviderRoutesSection } from "../connect/ProviderRoutesSection";
import { AddressCard } from "./AddressCard";
import { CardCheck } from "./CardCheck";
import { PaymentFlowPanel } from "./PaymentFlowPanel";
import { PaymentPassportCard } from "./PaymentPassportCard";
import { PaymentReadinessCard } from "./PaymentReadinessCard";
import { PostPaymentQuarantineCard } from "./PostPaymentQuarantineCard";
import { QuarantineOverrideModal } from "./QuarantineOverrideModal";
import { SubscriptionScreen } from "./SubscriptionScreen";

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
      await Promise.resolve();
      await Promise.resolve();
      hookRuntime.flushEffects();
    },
  };
}

function makeCheckoutPayload(id: string, ttlSeconds = 60): RiskInterceptPayload {
  return {
    id,
    provider: "anthropic",
    host: "checkout.stripe.com",
    report: null,
    ttl_seconds: ttlSeconds,
    scope: "checkout",
    checkout_risk: {
      domain: "checkout.stripe.com",
      score: 30,
      tier: "red",
      reason: "Конфликт стран",
      blockers: ["Конфликт стран"],
      warnings: [],
    },
    detected_at_ms: 1,
    phase: "ready",
  };
}

describe("PayShield mounted interactions", () => {
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

  it("CardCheck отклоняет >8 цифр при вводе и вставке БЕЗ вызова checkCardBin", async () => {
    const mounted = mountNode(() => CardCheck({ exitCountry: "KZ" }));
    const getField = () => collectElements(mounted.tree, (el) => el.type === Field)[0];
    const onPaste = getField().props.onPaste as (e: { clipboardData: { getData: () => string }; preventDefault: () => void }) => void;
    const preventDefault = vi.fn();
    onPaste({ clipboardData: { getData: () => "4400431234567890" }, preventDefault });
    expect(preventDefault).toHaveBeenCalledTimes(1);
    expect(getField().props.error).toBe(copy.card.errors.tooLong);
    expect(apiMocks.checkCardBin).not.toHaveBeenCalled();

    const onChange = getField().props.onChange as (e: { target: { value: string } }) => void;
    onChange({ target: { value: "440043129" } });
    expect(getField().props.value).toBe("");
    expect(getField().props.error).toBe(copy.card.errors.tooLong);
    expect(apiMocks.checkCardBin).not.toHaveBeenCalled();
  });

  it("SubscriptionScreen: переключение App Store <-> Картой на сайте, реальный inCleanRoom и автоподстановка страны", async () => {
    const stateWithCleanRoom: AppStateData = {
      pinned_ip: "185.10.10.1",
      strict_pinning_enabled: true,
      ip_history: {},
      session_allowed_providers: [],
      blocked_providers: [],
      clean_room: {
        active_profile_id: "cr-42",
        tainted_ips: {},
        profiles: [{
          id: "cr-42",
          label: "Claude Clean",
          provider: "anthropic",
          browser_engine: "chrome",
          status: "active",
          bound_route_id: null,
          launchpad_step: 4,
          completed_checklist: [],
          created_at: 1,
          last_exit_ip: "185.10.10.1",
          last_exit_country: "DE",
          last_opened_at: null,
          warmup_started_at: null,
        }],
      },
    };

    const mounted = mountNode(() => SubscriptionScreen({ state: stateWithCleanRoom, vpnCountry: "DE" }));
    await mounted.settle();

    const flowPanel = collectElements(mounted.tree, (el) => el.type === PaymentFlowPanel)[0];
    expect(flowPanel).toBeDefined();
    expect(flowPanel.props.inCleanRoom).toBe(true);

    const flowMount = mountNode(() =>
      PaymentFlowPanel(flowPanel.props as unknown as Parameters<typeof PaymentFlowPanel>[0]),
    );
    await flowMount.settle();
    expect(collectElements(flowMount.tree, (el) => el.type === AddressCard)).toHaveLength(1);
    expect(collectElements(flowMount.tree, (el) => el.type === CardCheck)).toHaveLength(0);

    // Смена страны Apple ID на TR скрывает US AddressCard
    const appleSelect = collectElements(flowMount.tree, (el) => el.type === Select)[0];
    (appleSelect.props.onChange as (e: { target: { value: string } }) => void)({ target: { value: "TR" } });
    await flowMount.settle();
    expect(collectElements(flowMount.tree, (el) => el.type === AddressCard)).toHaveLength(0);

    // Переключение на «Картой на сайте» показывает CardCheck и PaymentReadinessCard с real inCleanRoom=true
    const flowSeg = collectElements(
      flowMount.tree,
      (el) => el.type === Segmented && el.props["aria-label"] === copy.flow.label,
    )[0];
    (flowSeg.props.onChange as (next: "app_store" | "card") => void)("card");
    await flowMount.settle();

    const cardCheckEl = collectElements(flowMount.tree, (el) => el.type === CardCheck)[0];
    const readinessEl = collectElements(flowMount.tree, (el) => el.type === PaymentReadinessCard)[0];
    expect(cardCheckEl).toBeDefined();
    expect(readinessEl.props.inCleanRoom).toBe(true);
    expect(readinessEl.props.exitCountry).toBe("DE");

    (cardCheckEl.props.onBinChecked as (r: Awaited<ReturnType<typeof apiMocks.checkCardBin>>) => void)(
      await apiMocks.checkCardBin("440043"),
    );
    await flowMount.settle();

    const readinessAfter = collectElements(flowMount.tree, (el) => el.type === PaymentReadinessCard)[0];
    expect(readinessAfter.props.billingCountry).toBe("KZ");

    const readinessMount = mountNode(() =>
      PaymentReadinessCard(readinessAfter.props as unknown as Parameters<typeof PaymentReadinessCard>[0]),
    );
    await readinessMount.settle();
    expect(apiMocks.evaluatePaymentReadiness).toHaveBeenCalledWith(
      expect.objectContaining({ inCleanRoom: true, billingCountry: "KZ", bin: "440043" }),
    );

    const qCard = collectElements(flowMount.tree, (el) => el.type === PostPaymentQuarantineCard)[0];
    const qMount = mountNode(() =>
      PostPaymentQuarantineCard(qCard.props as unknown as Parameters<typeof PostPaymentQuarantineCard>[0]),
    );
    await qMount.settle();
    const paidBtn = collectElements(qMount.tree, (el) => el.type === Button)[0];
    await (paidBtn.props.onClick as () => Promise<void>)();
    expect(apiMocks.activatePostPaymentQuarantine).toHaveBeenCalledTimes(1);
    expect(apiMocks.savePaymentPassport).toHaveBeenCalledWith(
      expect.objectContaining({ profileId: "cr-42", binPrefix: "440043", cardCountry: "KZ", billingCountry: "KZ" }),
    );
    expect(PaymentPassportCard({ initialPassport: null })).toBeNull();
  });

  it("PaymentReadinessCard передаёт accountAgeConfirmed96h в evaluatePaymentReadiness и PaymentFlowPanel не хардкодит US для не-US App Store", async () => {
    const readinessMount = mountNode(() =>
      PaymentReadinessCard({
        channel: "directCard",
        exitCountry: "NL",
        inCleanRoom: true,
      }),
    );
    await readinessMount.settle();
    expect(apiMocks.evaluatePaymentReadiness).toHaveBeenLastCalledWith(
      expect.objectContaining({ accountAgeConfirmed96h: false }),
    );

    const ageSeg = collectElements(
      readinessMount.tree,
      (el) => el.type === Segmented && el.props["aria-label"] === copy.readiness.accountAgeLabel,
    )[0];
    expect(ageSeg).toBeDefined();
    (ageSeg.props.onChange as (next: "under4d" | "over4d") => void)("over4d");
    await readinessMount.settle();
    expect(apiMocks.evaluatePaymentReadiness).toHaveBeenLastCalledWith(
      expect.objectContaining({ accountAgeConfirmed96h: true }),
    );

    const flowMount = mountNode(() =>
      PaymentFlowPanel({
        initialFlow: "app_store",
        profileId: "cr-tr",
        exitIp: "185.10.10.1",
        exitCountry: "TR",
        inCleanRoom: true,
      }),
    );
    await flowMount.settle();

    const appleSelect = collectElements(flowMount.tree, (el) => el.type === Select)[0];
    (appleSelect.props.onChange as (e: { target: { value: string } }) => void)({ target: { value: "TR" } });
    await flowMount.settle();

    const qCard = collectElements(flowMount.tree, (el) => el.type === PostPaymentQuarantineCard)[0];
    const pCard = collectElements(flowMount.tree, (el) => el.type === PaymentPassportCard)[0];
    expect(qCard.props.cardCountry).toBe("TR");
    expect(qCard.props.billingCountry).toBe("TR");
    expect(pCard.props.currentCardCountry).toBe("TR");
    expect(pCard.props.currentBillingCountry).toBe("TR");

    const qMount = mountNode(() =>
      PostPaymentQuarantineCard(qCard.props as unknown as Parameters<typeof PostPaymentQuarantineCard>[0]),
    );
    await qMount.settle();
    const paidBtn = collectElements(qMount.tree, (el) => el.type === Button)[0];
    await (paidBtn.props.onClick as () => Promise<void>)();
    expect(apiMocks.savePaymentPassport).toHaveBeenLastCalledWith(
      expect.objectContaining({
        profileId: "cr-tr",
        channel: "appleIAP",
        cardCountry: "TR",
        billingCountry: "TR",
      }),
    );
  });

  it("CheckoutAlertView вызывает cancelAndInspect и allowCheckout15m при нажатии кнопок", async () => {
    const payload = makeCheckoutPayload("chk-42");
    const onResolved = vi.fn();
    const mounted = mountNode(() => CheckoutAlertView({ payload, hideIpMode: false, onResolved }));

    const buttons = collectElements(mounted.tree, (el) => el.type === Button);
    const cancelBtn = buttons.find((b) => String(b.props.children).includes(alertDialog.checkout.cancelAndInspect));
    const allowBtn = buttons.find((b) => String(b.props.children).includes(alertDialog.checkout.allow15m));

    expect(cancelBtn).toBeDefined();
    expect(allowBtn).toBeDefined();

    await (cancelBtn!.props.onClick as () => Promise<void>)();
    expect(apiMocks.cancelAndInspect).toHaveBeenCalledWith("chk-42", "checkout.stripe.com");
    expect(onResolved).toHaveBeenCalledWith("cancelAndInspect");

    await (allowBtn!.props.onClick as () => Promise<void>)();
    expect(apiMocks.allowCheckout15m).toHaveBeenCalledWith("chk-42", "checkout.stripe.com");
    expect(onResolved).toHaveBeenCalledWith("allowCheckout15m");
  });

  it("CheckoutAlertView не переподписывает keydown каждую секунду и автоотменяет на left === 0", async () => {
    const addSpy = vi.fn();
    const removeSpy = vi.fn();
    let intervalTick: (() => void) | null = null;
    const origWindow = (globalThis as Record<string, unknown>).window;
    (globalThis as Record<string, unknown>).window = {
      addEventListener: addSpy,
      removeEventListener: removeSpy,
      setInterval: vi.fn((fn: () => void) => {
        intervalTick = fn;
        return 7;
      }),
      clearInterval: vi.fn(),
    };

    try {
      const payload = makeCheckoutPayload("chk-ttl", 2);
      const onResolved = vi.fn();
      const render = () => {
        hookRuntime.beginRender();
        CheckoutAlertView({ payload, hideIpMode: false, onResolved });
      };
      hookRuntime.reset(render);
      removeSpy.mockClear();
      addSpy.mockClear();
      render();
      hookRuntime.flushEffects();

      expect(addSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).not.toHaveBeenCalled();
      expect(intervalTick).toBeTypeOf("function");

      intervalTick!();
      expect(addSpy).toHaveBeenCalledTimes(1);
      expect(removeSpy).not.toHaveBeenCalled();

      intervalTick!();
      await Promise.resolve();
      expect(addSpy).toHaveBeenCalledTimes(1);
      expect(apiMocks.cancelAndInspect).toHaveBeenCalledWith("chk-ttl", "checkout.stripe.com");
      expect(onResolved).toHaveBeenCalledWith("cancelAndInspect");
    } finally {
      (globalThis as Record<string, unknown>).window = origWindow;
    }
  });

  it("AlertWindow передаёт allowCheckout15m в onResolved (а не BlockUntilNetworkChange)", async () => {
    const payload = makeCheckoutPayload("chk-aw");
    const onResolved = vi.fn();
    const mounted = mountNode(() => AlertWindow({ initialPayload: payload, hideIpMode: false, onResolved }));

    const checkoutView = collectElements(mounted.tree, (el) => el.type === CheckoutAlertView)[0];
    expect(checkoutView).toBeDefined();
    const childTree = CheckoutAlertView(checkoutView.props as unknown as Parameters<typeof CheckoutAlertView>[0]);
    const allowBtn = collectElements(childTree, (el) => el.type === Button).find((b) =>
      String(b.props.children).includes(alertDialog.checkout.allow15m),
    );
    expect(allowBtn).toBeDefined();

    await (allowBtn!.props.onClick as () => Promise<void>)();
    expect(onResolved).toHaveBeenCalledWith("allowCheckout15m");
    expect(onResolved).not.toHaveBeenCalledWith("BlockUntilNetworkChange");
  });

  it("ConnectScreen перехватывает смену маршрута при активной 72ч защите и вызывает override при «Сменить всё равно»", async () => {
    const routes: RouteView[] = [
      {
        id: "r-us", label: "US Clean", country: "US", exit_ip: "45.10.10.1", enabled: true, added_at: 1,
        entries: [{ proto: "https", host: "us.example.com", port: 443, has_password: false }],
        status: "active", is_default: true, bound_providers: [], is_profile_route: false,
      },
      {
        id: "r-de", label: "DE Berlin", country: "DE", exit_ip: "45.10.10.2", enabled: true, added_at: 2,
        entries: [{ proto: "https", host: "de.example.com", port: 443, has_password: false }],
        status: "active", is_default: false, bound_providers: [], is_profile_route: false,
      },
    ];
    const snapshot: RoutesSnapshot = {
      routes, default_route_id: "r-us", provider_routes: {}, effective: { anthropic: "r-us", openai: "r-us", gemini: "r-us" }, dangling: [],
    };

    const mounted = mountNode(() =>
      ConnectScreen({
        state: { pinned_ip: "45.10.10.1", strict_pinning_enabled: true, ip_history: {}, session_allowed_providers: [], blocked_providers: [] },
        routesSnapshot: snapshot,
        currentIp: "45.10.10.1",
        currentCountry: "US",
        onRefreshState: vi.fn(async () => {}),
        onOpenGuide: vi.fn(),
        onToast: vi.fn(),
      }),
    );
    await mounted.settle();

    const providerSection = collectElements(mounted.tree, (el) => el.type === ProviderRoutesSection)[0];
    expect(providerSection).toBeDefined();
    (providerSection.props.onBindProvider as (provider: "anthropic", target: string) => void)("anthropic", "r-de");
    await Promise.resolve();

    expect(apiMocks.bindProviderRoute).not.toHaveBeenCalled();
    const overrideModal = collectElements(mounted.tree, (el) => el.type === QuarantineOverrideModal)[0];
    expect(overrideModal?.props.open).toBe(true);

    await (overrideModal.props.onConfirm as () => Promise<void>)();
    await Promise.resolve();
    expect(apiMocks.overridePostPaymentQuarantine).toHaveBeenCalledTimes(1);
    expect(apiMocks.bindProviderRoute).toHaveBeenCalledWith("anthropic", "r-de");
  });

  it("ConnectScreen охраняет handleLegacyToggle и handleLegacyDisconnect через quarantine.guardRouteSwitch", async () => {
    const emptySnapshot: RoutesSnapshot = { routes: [], default_route_id: null, provider_routes: {}, effective: {}, dangling: [] };
    const render = () =>
      ConnectScreen({
        state: {
          pinned_ip: "45.10.10.1",
          strict_pinning_enabled: true,
          ip_history: {},
          session_allowed_providers: [],
          blocked_providers: [],
          upstream_proxy: {
            enabled: true, raw_key: "https://legacy.example.com:443", protocol: "https", host: "legacy.example.com", port: 443, label: "Legacy Server",
          },
        },
        routesSnapshot: emptySnapshot,
        currentIp: "45.10.10.1",
        currentCountry: "US",
        onRefreshState: vi.fn(async () => {}),
        onOpenGuide: vi.fn(),
        onToast: vi.fn(),
      });

    const mounted = mountNode(render);
    await mounted.settle();

    const routeListEl = collectElements(mounted.tree, (el) => typeof el.type === "function" && el.type.name === "RouteListSection")[0];
    const routeListTree = (routeListEl.type as (p: Record<string, unknown>) => unknown)(routeListEl.props);
    const legacySwitch = collectElements(routeListTree, (el) => el.type === Switch)[0];
    (legacySwitch.props.onChange as () => void)();
    await Promise.resolve();

    expect(apiMocks.toggleUpstreamProxy).not.toHaveBeenCalled();
    let overrideModal = collectElements(mounted.tree, (el) => el.type === QuarantineOverrideModal)[0];
    expect(overrideModal?.props.open).toBe(true);

    await (overrideModal.props.onConfirm as () => Promise<void>)();
    await Promise.resolve();
    expect(apiMocks.overridePostPaymentQuarantine).toHaveBeenCalledTimes(1);
    expect(apiMocks.toggleUpstreamProxy).toHaveBeenCalledWith(false);

    apiMocks.getPostPaymentQuarantineStatus.mockResolvedValueOnce({
      active: true, remainingHours: 70, remainingSecs: 70 * 3600,
      quarantine: { startedAt: 1000, expiresAt: 1000 + 72 * 3600, pinnedCountry: "US" },
      warning: "Активна 72-часовая защита маршрута",
    });
    const mounted2 = mountNode(render);
    await mounted2.settle();

    const routeListEl2 = collectElements(mounted2.tree, (el) => typeof el.type === "function" && el.type.name === "RouteListSection")[0];
    const routeListTree2 = (routeListEl2.type as (p: Record<string, unknown>) => unknown)(routeListEl2.props);
    const disconnectBtn = collectElements(
      routeListTree2,
      (el) => el.type === Button && String(el.props.children ?? "").includes(connectCopy.key.disconnect),
    )[0];
    (disconnectBtn.props.onClick as () => void)();
    await Promise.resolve();

    expect(apiMocks.clearUpstreamProxy).not.toHaveBeenCalled();
    overrideModal = collectElements(mounted2.tree, (el) => el.type === QuarantineOverrideModal)[0];
    expect(overrideModal?.props.open).toBe(true);

    await (overrideModal.props.onConfirm as () => Promise<void>)();
    await Promise.resolve();
    expect(apiMocks.clearUpstreamProxy).toHaveBeenCalledTimes(1);
  });

  it("PaymentReadinessCard передаёт targetService=gemini и показывает поле профиля Google", async () => {
    const mounted = mountNode(() =>
      PaymentReadinessCard({
        channel: "directCard",
        exitCountry: "US",
        inCleanRoom: true,
      }),
    );
    await mounted.settle();

    const serviceSelect = collectElements(
      mounted.tree,
      (el) => el.type === Select && el.props.label === copy.readiness.serviceLabel,
    )[0];
    expect(serviceSelect).toBeDefined();
    (serviceSelect.props.onChange as (e: { target: { value: string } }) => void)({ target: { value: "gemini" } });
    await mounted.settle();

    expect(apiMocks.evaluatePaymentReadiness).toHaveBeenLastCalledWith(
      expect.objectContaining({ targetService: "gemini", provider: "gemini" }),
    );
    const gpSelect = collectElements(
      mounted.tree,
      (el) => el.type === Select && el.props.label === copy.readiness.googleProfileLabel,
    )[0];
    expect(gpSelect).toBeDefined();
  });
});
