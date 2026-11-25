import { describe, expect, it, vi } from "vitest";
import { toast as t } from "../copy/ru";
import type { CheckResult, RiskInterceptPayload, RiskReport } from "../../types";
import {
  createNetworkChangedCoalescer,
  handleInterceptorResolvedEvent,
  handleNetworkChangedEvent,
  handleRiskDetectedEvent,
  handleSysproxyAdminAuthRequired,
  handleTrayProfileSwitched,
} from "./useTrayEvents";

describe("handleTrayProfileSwitched", () => {
  it("берёт имя из payload.active_profile.name и обновляет состояние, маршруты и профили", async () => {
    const refreshState = vi.fn(async () => ({}));
    const refreshRoutes = vi.fn(async () => null);
    const refreshProfiles = vi.fn();
    const showToast = vi.fn();
    const runFullAudit = vi.fn(async () => {});

    await handleTrayProfileSwitched(
      { refreshState, refreshRoutes, refreshProfiles, showToast, runFullAudit },
      {
        previous_profile_id: "default",
        active_profile: {
          id: "work",
          name: "Рабочий профиль",
          isolated_device_id: "abc",
          created_at: 1,
          last_used_at: 2,
          is_active: true,
          has_saved_session: true,
        },
        cleaned_cache_items: 0,
        restored_files: 0,
        message: "ok",
      },
    );

    expect(refreshState).toHaveBeenCalledTimes(1);
    expect(refreshRoutes).toHaveBeenCalledTimes(1);
    expect(refreshProfiles).toHaveBeenCalledTimes(1);
    expect(showToast).toHaveBeenCalledWith(t.profile.switched, "Рабочий профиль", "info");
    expect(runFullAudit).toHaveBeenCalledWith(false);
  });

  it("падает обратно на общий текст, если active_profile отсутствует", async () => {
    const showToast = vi.fn();
    await handleTrayProfileSwitched(
      {
        refreshState: vi.fn(async () => ({})),
        refreshRoutes: vi.fn(async () => null),
        refreshProfiles: vi.fn(),
        showToast,
        runFullAudit: vi.fn(async () => {}),
      },
      null,
    );

    expect(showToast).toHaveBeenCalledWith(t.profile.switched, t.profile.switchedText, "info");
  });
});

describe("handleSysproxyAdminAuthRequired", () => {
  it("показывает warning-тост с подсказкой «Разрешить с паролем» и снимает префикс ADMIN_AUTH_REQUIRED:", () => {
    const showToast = vi.fn();
    handleSysproxyAdminAuthRequired({ showToast }, "ADMIN_AUTH_REQUIRED:Требуется пароль администратора");

    expect(showToast).toHaveBeenCalledTimes(1);
    const [title, text, tone] = showToast.mock.calls[0];
    expect(title).toBe(t.sysproxy.adminAuthTitle);
    expect(text).toContain("Требуется пароль администратора");
    expect(text).toContain("Разрешить с паролем");
    expect(tone).toBe("warning");
  });

  it("использует запасной текст, если payload пустой", () => {
    const showToast = vi.fn();
    handleSysproxyAdminAuthRequired({ showToast }, null);

    expect(showToast).toHaveBeenCalledWith(t.sysproxy.adminAuthTitle, t.sysproxy.adminAuthText, "warning");
  });
});

describe("§7.7 fail-closed invalidation on network/guard events", () => {
  it("handleNetworkChangedEvent сбрасывает устаревшие отчёты до запуска runFullAudit(true)", () => {
    const order: string[] = [];
    const invalidateReports = vi.fn(() => order.push("invalidate"));
    const runFullAudit = vi.fn(async () => {
      order.push("audit");
    });
    handleNetworkChangedEvent({ invalidateReports, runFullAudit });
    expect(invalidateReports).toHaveBeenCalledTimes(1);
    expect(runFullAudit).toHaveBeenCalledWith(true);
    expect(order).toEqual(["invalidate", "audit"]);
  });

  it("handleRiskDetectedEvent при phase=detecting НЕ сбрасывает отчёты (без шторма 0 из 14), но обновляет state и payload", () => {
    const invalidateReports = vi.fn();
    const refreshState = vi.fn(async () => ({}));
    const setInterceptPayload = vi.fn();
    const payload: RiskInterceptPayload = {
      id: "alert-1",
      provider: "anthropic",
      host: "claude.ai",
      report: null,
      ttl_seconds: 90,
      scope: "network",
      detected_at_ms: 1,
      phase: "detecting",
    };

    handleRiskDetectedEvent({ invalidateReports, refreshState, setInterceptPayload }, payload);
    expect(invalidateReports).not.toHaveBeenCalled();
    expect(refreshState).toHaveBeenCalledTimes(1);
    expect(setInterceptPayload).toHaveBeenCalledTimes(1);
  });

  it("handleRiskDetectedEvent при phase=ready (scope=network) и phase=failed сбрасывает устаревшие отчёты", () => {
    for (const phase of ["ready", "failed"] as const) {
      const invalidateReports = vi.fn();
      const refreshState = vi.fn(async () => ({}));
      const setInterceptPayload = vi.fn();
      const payload: RiskInterceptPayload = {
        id: `alert-${phase}`,
        provider: "anthropic",
        host: "claude.ai",
        report: null,
        ttl_seconds: 90,
        scope: "network",
        detected_at_ms: 1,
        phase,
      };

      handleRiskDetectedEvent({ invalidateReports, refreshState, setInterceptPayload }, payload);
      expect(invalidateReports).toHaveBeenCalledWith(undefined, false);
      expect(refreshState).toHaveBeenCalledTimes(1);
    }
  });

  it("handleInterceptorResolvedEvent сбрасывает устаревшие отчёты, обновляет state и запускает аудит", () => {
    const invalidateReports = vi.fn();
    const refreshState = vi.fn(async () => ({}));
    const setInterceptPayload = vi.fn();
    const runFullAudit = vi.fn(async () => {});

    handleInterceptorResolvedEvent({
      invalidateReports,
      refreshState,
      setInterceptPayload,
      runFullAudit,
    });
    expect(setInterceptPayload).toHaveBeenCalledWith(null);
    expect(invalidateReports).toHaveBeenCalledTimes(1);
    expect(refreshState).toHaveBeenCalledTimes(1);
    expect(runFullAudit).toHaveBeenCalledWith(false);
  });

  it("handleRiskDetectedEvent игнорирует событие и очищает payload, когда guardPauseStatus.paused === true", () => {
    const invalidateReports = vi.fn();
    const refreshState = vi.fn(async () => ({}));
    const setInterceptPayload = vi.fn();
    const payload: RiskInterceptPayload = {
      id: "alert-paused",
      provider: "anthropic",
      host: "claude.ai",
      report: null,
      ttl_seconds: 90,
      scope: "network",
      detected_at_ms: 1,
      phase: "ready",
    };

    handleRiskDetectedEvent(
      {
        invalidateReports,
        refreshState,
        setInterceptPayload,
        guardPauseStatus: {
          paused: true,
          mode: "until_network_change",
          gate: "blocked",
          gate_reason: "Пауза",
          manual_killswitch: false,
          pending_providers: [],
          blocked_providers: ["anthropic", "openai", "gemini"],
        },
      },
      payload,
    );
    expect(invalidateReports).not.toHaveBeenCalled();
    expect(refreshState).not.toHaveBeenCalled();
    expect(setInterceptPayload).toHaveBeenCalledWith(null);
  });

  it("handleInterceptorResolvedEvent при block_until_network_change / should_reaudit=false НЕ сбрасывает отчёты и НЕ запускает аудит", () => {
    for (const payload of [
      { id: "a1", provider: "anthropic", decision: "block_until_network_change", should_reaudit: false },
      { id: "a2", provider: "openai", decision: "block" },
      { id: "a3", provider: "gemini", decision: "block_always" },
      { id: "a4", should_reaudit: false },
    ]) {
      const invalidateReports = vi.fn();
      const refreshState = vi.fn(async () => ({}));
      const setInterceptPayload = vi.fn();
      const runFullAudit = vi.fn(async () => {});

      handleInterceptorResolvedEvent(
        { invalidateReports, refreshState, setInterceptPayload, runFullAudit },
        payload,
      );

      expect(setInterceptPayload).toHaveBeenCalledWith(null);
      expect(refreshState).toHaveBeenCalledTimes(1);
      expect(invalidateReports).not.toHaveBeenCalled();
      expect(runFullAudit).not.toHaveBeenCalled();
    }
  });

  it("handleInterceptorResolvedEvent при allow_session или legacy-форме { id } сбрасывает отчёты и запускает аудит", () => {
    for (const payload of [
      { id: "a1", provider: "anthropic", decision: "allow_session", should_reaudit: true },
      { id: "a2" },
    ]) {
      const invalidateReports = vi.fn();
      const refreshState = vi.fn(async () => ({}));
      const setInterceptPayload = vi.fn();
      const runFullAudit = vi.fn(async () => {});

      handleInterceptorResolvedEvent(
        { invalidateReports, refreshState, setInterceptPayload, runFullAudit },
        payload,
      );

      expect(setInterceptPayload).toHaveBeenCalledWith(null);
      expect(refreshState).toHaveBeenCalledTimes(1);
      expect(invalidateReports).toHaveBeenCalledTimes(1);
      expect(runFullAudit).toHaveBeenCalledWith(false);
    }
  });

  it("createNetworkChangedCoalescer склеивает всплеск network://changed в один runFullAudit(true) без сброса отчётов при неизвестном IP", () => {
    vi.useFakeTimers();
    try {
      const invalidateReports = vi.fn();
      const runFullAudit = vi.fn(async () => {});
      const coalescer = createNetworkChangedCoalescer(() => ({ invalidateReports, runFullAudit }), 250);

      coalescer.trigger();
      vi.advanceTimersByTime(50);
      coalescer.trigger();
      vi.advanceTimersByTime(50);
      coalescer.trigger();

      expect(invalidateReports).not.toHaveBeenCalled();
      expect(runFullAudit).not.toHaveBeenCalled();

      vi.advanceTimersByTime(249);
      expect(runFullAudit).not.toHaveBeenCalled();

      vi.advanceTimersByTime(1);
      expect(runFullAudit).toHaveBeenCalledTimes(1);
      expect(runFullAudit).toHaveBeenCalledWith(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("createNetworkChangedCoalescer НЕ сбрасывает отчёты и НЕ вызывает лишний runFullAudit(true) после audit://refreshed для того же IP", () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(100_000);
      const invalidateReports = vi.fn();
      const runFullAudit = vi.fn(async () => {});
      const ok: CheckResult = { status: "ok", code: "OK", message: "ok" };
      const report: RiskReport = {
        provider: "anthropic",
        overall_status: "green",
        trust_score: 100,
        telemetry: { ip: "178.168.12.86", country_code: "IL", resolved_at: 1 },
        geo_result: ok,
        pinning_result: ok,
        travel_result: ok,
        dnsbl_result: ok,
        dnsbl_clean_count: "4/4",
        asn_result: ok,
        ipv6_result: ok,
        timezone_result: ok,
        checks: [],
      };
      const coalescer = createNetworkChangedCoalescer(
        () => ({
          invalidateReports,
          runFullAudit,
          currentIp: "178.168.12.86",
          lastAuditRefreshed: { ip: "178.168.12.86", at: 99_800 },
        }),
        250,
      );

      coalescer.trigger(report);
      vi.advanceTimersByTime(300);

      expect(invalidateReports).not.toHaveBeenCalled();
      expect(runFullAudit).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("createNetworkChangedCoalescer инвалидирует и переаудирует при подтверждённой смене IP без свежего audit://refreshed", () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(100_000);
      const invalidateReports = vi.fn();
      const runFullAudit = vi.fn(async () => {});
      const coalescer = createNetworkChangedCoalescer(
        () => ({
          invalidateReports,
          runFullAudit,
          currentIp: "178.168.12.86",
          lastAuditRefreshed: { ip: "178.168.12.86", at: 99_800 },
        }),
        250,
      );

      coalescer.trigger({ telemetry: { ip: "185.212.102.40", country_code: "NL", resolved_at: 2 } });
      expect(invalidateReports).toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(250);
      expect(runFullAudit).toHaveBeenCalledTimes(1);
      expect(runFullAudit).toHaveBeenCalledWith(true);
    } finally {
      vi.useRealTimers();
    }
  });
});
