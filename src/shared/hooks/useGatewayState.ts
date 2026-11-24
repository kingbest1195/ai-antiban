import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  AppStateData,
  CoverageSnapshot,
  GuardPauseStatus,
  PartialAudit,
  ProviderId,
  RiskReport,
  RoutesSnapshot,
  StartupSnapshot,
} from "../../types";
import {
  auditConnection,
  fetchAppState,
  getCoverageSnapshot,
  getGuardPauseStatus,
  getRoutesSnapshot,
  getStartupState,
  getSysproxyStatus,
  onAuditProgress,
  onAuditRefreshed,
  onGuardPauseStatusChanged,
  onStartupChanged,
} from "../../utils/api";
import { toast as t } from "../copy/ru";
import {
  CHECK_SLOTS,
  FOCUS_REFRESH_MS,
  STALE_REPORT_MS,
  applyProgress,
  dataAge,
  emptyPartial,
  invalidateStaleReports,
  isValidGatewayLatency,
  mergeProviderReport,
} from "./gatewayReports";
import type { ShowToast } from "./useToasts";
import { pickWorstReport } from "../../features/checks/checksModel";

export {
  CHECK_SLOTS,
  FOCUS_REFRESH_MS,
  STALE_REPORT_MS,
  applyProgress,
  dataAge,
  emptyPartial,
  invalidateStaleReports,
  mergeProviderReport,
};

interface Options {
  showToast: ShowToast;
  refreshGatewayStats: () => Promise<void>;
  onManualKillswitchChange?: (frozen: boolean) => void;
}

/** При paused === true или gate === "blocked" отчёты не сбрасываем, чтобы экран не мигал «Проверяем сеть и защиту...». */
export function shouldInvalidateOnPauseStatus(snap: GuardPauseStatus): {
  invalidate: boolean;
  onlyProviders?: string[];
  includeAll: boolean;
} {
  if (snap.paused || snap.gate === "blocked") {
    return { invalidate: false, includeAll: false };
  }
  const pending = snap.pending_providers ?? [];
  if (snap.manual_killswitch) {
    return { invalidate: true, onlyProviders: pending.length > 0 ? pending : undefined, includeAll: true };
  }
  if (snap.gate === "pending" || pending.length > 0) {
    return { invalidate: true, onlyProviders: pending.length > 0 ? pending : undefined, includeAll: false };
  }
  return { invalidate: false, includeAll: false };
}

/** Подавляет фоновый 1.5с self-heal аудит, пока шлюз в pending или на паузе. */
export function shouldSuppressSelfHeal(guardPauseStatus: GuardPauseStatus | null | undefined): boolean {
  return guardPauseStatus?.gate === "pending" || guardPauseStatus?.paused === true;
}

/**
 * Состояние шлюза: AppStateData, отчёты аудита по трём сервисам, статус системного прокси, задержка проверки.
 * Здесь же стартовый аудит и «самолечение» — повторный опрос, пока не определились IP и провайдер.
 */
export function useGatewayState({ showToast, refreshGatewayStats, onManualKillswitchChange }: Options) {
  const [state, setState] = useState<AppStateData | null>(null);
  const [reports, setReports] = useState<Partial<Record<ProviderId, RiskReport>>>({});
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [scanLatencyMs, setScanLatencyMs] = useState<number>(38);
  const [sysproxyActive, setSysproxyActive] = useState<boolean>(false);
  const [autoUpdateEnabled, setAutoUpdateEnabled] = useState<boolean>(true);
  /** Текст последней ошибки аудита; сбрасывается при успешном проходе. Нужен экрану «нет сети». */
  const [auditError, setAuditError] = useState<string | null>(null);
  const [routesSnapshot, setRoutesSnapshot] = useState<RoutesSnapshot | null>(null);
  const [coverageSnapshot, setCoverageSnapshot] = useState<CoverageSnapshot | null>(null);
  const [guardPauseStatus, setGuardPauseStatus] = useState<GuardPauseStatus | null>(null);
  const routesSnapshotRef = useRef<RoutesSnapshot | null>(null);
  routesSnapshotRef.current = routesSnapshot;
  /** Когда пришёл последний успешный отчёт (мс) и «сейчас» для пересчёта возраста. */
  const [reportAt, setReportAt] = useState<number | null>(null);
  const [now, setNow] = useState<number>(() => Date.now());
  /** Фоновый запуск шлюза: пока `starting`, защита ещё не включена и её состояние не известно. */
  const [startup, setStartup] = useState<StartupSnapshot>({ phase: "starting" });
  const startupPending = startup.phase === "starting";
  /** Что уже готово в идущем первом аудите: показываем по мере прихода, не дожидаясь отчёта. */
  const [partials, setPartials] = useState<Partial<Record<ProviderId, PartialAudit>>>({});
  const runSeq = useRef(0);
  /** Текущий запуск по сервису: события других запусков (самолечение, повтор) игнорируются. */
  const activeRuns = useRef<Partial<Record<ProviderId, string>>>({});
  /** Сколько аудитов идёт прямо сейчас: самолечение не плодит параллельные запуски. */
  const inFlight = useRef(0);
  const reportAtRef = useRef<number | null>(null);
  reportAtRef.current = reportAt;

  /** Получить актуальный снимок покрытия приложений и цепочки PAC. */
  const refreshCoverage = useCallback(async () => {
    try {
      const snap = await getCoverageSnapshot();
      setCoverageSnapshot(snap);
      return snap;
    } catch (err) {
      console.warn("Could not fetch coverage snapshot:", err);
      return null;
    }
  }, []);

  /** Получить актуальный снимок маршрутов. */
  const refreshRoutes = useCallback(async () => {
    try {
      const snap = await getRoutesSnapshot();
      setRoutesSnapshot(snap);
      return snap;
    } catch (err) {
      console.warn("Could not fetch routes snapshot:", err);
      return null;
    }
  }, []);

  /** Инвалидирует устаревшие отчёты (по умолчанию — только unrouted-сервисы при смене сети). */
  const invalidateReports = useCallback((onlyProviders?: string[], includeAll = false) => {
    setReports((prev) =>
      invalidateStaleReports(prev, routesSnapshotRef.current, onlyProviders, includeAll),
    );
  }, []);

  /** Перечитать AppStateData, маршруты, статус шлюза и покрытие без аудита. */
  const refreshState = useCallback(async () => {
    const [st, , , pauseSnap] = await Promise.all([
      fetchAppState(),
      refreshRoutes(),
      refreshCoverage(),
      getGuardPauseStatus().catch(() => null),
    ]);
    setState(st);
    if (pauseSnap) setGuardPauseStatus(pauseSnap);
    return st;
  }, [refreshRoutes, refreshCoverage]);

  /** Начинает запуск аудита сервиса и отдаёт его id для событий прогресса. */
  const beginRun = useCallback((provider: ProviderId) => {
    const runId = `${Date.now().toString(36)}-${++runSeq.current}`;
    activeRuns.current[provider] = runId;
    setPartials((prev) => ({ ...prev, [provider]: emptyPartial(provider, runId) }));
    return runId;
  }, []);

  const runFullAudit = useCallback(
    async (force: boolean = false, silentError: boolean = false) => {
      const startTime = performance.now();
      setRefreshing(true);
      inFlight.current += 1;

      try {
        // Сопутствующие чтения идут рядом с аудитом, а не перед ним: ни одно из них не задерживает проверки.
        const sideReads = Promise.allSettled([
          fetchAppState().then((st) => {
            setState(st);
            if (st.auto_update_enabled !== undefined) setAutoUpdateEnabled(st.auto_update_enabled);
          }),
          getSysproxyStatus().then(setSysproxyActive),
          refreshRoutes(),
          refreshCoverage(),
        ]);

        let claudeReport: RiskReport;
        try {
          claudeReport = await auditConnection("anthropic", force, beginRun("anthropic"));
        } catch {
          await new Promise((r) => setTimeout(r, 600));
          claudeReport = await auditConnection("anthropic", true, beginRun("anthropic"));
        }

        // Основной отчёт сразу: IP, провайдер и проверки рисуются, не дожидаясь остальных сервисов.
        setReports((prev) => ({
          ...prev,
          anthropic: claudeReport,
        }));
        setPartials((prev) => ({ ...prev, anthropic: undefined }));
        setAuditError(null);
        const refreshedAt = Date.now();
        reportAtRef.current = refreshedAt;
        setReportAt(refreshedAt);

        const [gptSettled, geminiSettled] = await Promise.allSettled([
          auditConnection("openai", force),
          auditConnection("gemini", force),
        ]);

        setReports((prev) => ({
          ...prev,
          anthropic: claudeReport,
          ...(gptSettled.status === "fulfilled" ? { openai: gptSettled.value } : {}),
          ...(geminiSettled.status === "fulfilled" ? { gemini: geminiSettled.value } : {}),
        }));

        const gwMs = claudeReport.gateway_latency_ms;
        const elapsed = Math.round(performance.now() - startTime);
        setScanLatencyMs(
          isValidGatewayLatency(gwMs) ? Math.round(gwMs) : Math.max(18, elapsed),
        );
        await sideReads;
        // Повторно читаем AppStateData после завершения аудита, чтобы blocked_providers всегда был актуален.
        try {
          const freshState = await fetchAppState();
          setState(freshState);
          if (freshState.auto_update_enabled !== undefined) setAutoUpdateEnabled(freshState.auto_update_enabled);
        } catch {}
        await refreshGatewayStats();
      } catch (err: any) {
        console.error("Failed to run audit:", err);
        setPartials((prev) => ({ ...prev, anthropic: undefined }));
        setAuditError(err?.message || String(err));
        if (!silentError) {
          showToast(t.auditError, err?.message || String(err), "error");
        }
      } finally {
        inFlight.current -= 1;
        // Пока идёт другой запуск, «обновление» не снимаем: экран не должен мигать готовым состоянием.
        if (inFlight.current <= 0) setRefreshing(false);
        refreshGatewayStats();
      }
    },
    [showToast, refreshGatewayStats, beginRun, refreshRoutes, refreshCoverage],
  );

  /** Точечный аудит одного сервиса: обновляет только его отчёт, не трогая остальные. */
  const runProviderAudit = useCallback(
    async (providerId: ProviderId, forceRefresh: boolean = true) => {
      setRefreshing(true);
      inFlight.current += 1;
      try {
        const report = await auditConnection(providerId, forceRefresh, beginRun(providerId));
        setReports((prev) => mergeProviderReport(prev, providerId, report));
        if (isValidGatewayLatency(report.gateway_latency_ms)) {
          setScanLatencyMs(Math.round(report.gateway_latency_ms));
        }
        setPartials((prev) => ({ ...prev, [providerId]: undefined }));
        setAuditError(null);
        const refreshedAt = Date.now();
        reportAtRef.current = refreshedAt;
        setReportAt(refreshedAt);
        try {
          const freshState = await fetchAppState();
          setState(freshState);
          if (freshState.auto_update_enabled !== undefined) setAutoUpdateEnabled(freshState.auto_update_enabled);
        } catch {}
        await refreshGatewayStats();
      } catch (err: any) {
        console.error(`Failed to run audit for ${providerId}:`, err);
        setPartials((prev) => ({ ...prev, [providerId]: undefined }));
        setAuditError(err?.message || String(err));
        showToast(t.auditError, err?.message || String(err), "error");
      } finally {
        inFlight.current -= 1;
        if (inFlight.current <= 0) setRefreshing(false);
        refreshGatewayStats();
      }
    },
    [showToast, refreshGatewayStats, beginRun],
  );

  // Куски идущего аудита: адрес выхода и каждая проверка приходят, как только готовы.
  useEffect(() => {
    let off: (() => void) | undefined;
    let cancelled = false;
    onAuditProgress((event) => {
      if (activeRuns.current[event.provider] !== event.run_id) return;
      setPartials((prev) => {
        const next = applyProgress(prev[event.provider], event);
        return next === prev[event.provider] ? prev : { ...prev, [event.provider]: next };
      });
    })
      .then((un) => (cancelled ? un() : (off = un)))
      .catch(() => {});
    return () => {
      cancelled = true;
      off?.();
    };
  }, []);

  const onManualKillswitchChangeRef = useRef(onManualKillswitchChange);
  onManualKillswitchChangeRef.current = onManualKillswitchChange;

  // Подписка на смену gate/паузы шлюза: при pending (без паузы/блокировки) сбрасываем устаревшие отчёты.
  useEffect(() => {
    let off: (() => void) | undefined;
    let cancelled = false;
    let pauseSeq = 0;
    getGuardPauseStatus()
      .then((snap) => {
        if (cancelled) return;
        setGuardPauseStatus(snap);
        onManualKillswitchChangeRef.current?.(Boolean(snap.manual_killswitch));
      })
      .catch(() => {});
    onGuardPauseStatusChanged((snap) => {
      const seq = ++pauseSeq;
      setGuardPauseStatus(snap);
      onManualKillswitchChangeRef.current?.(Boolean(snap.manual_killswitch));
      setState((prev) =>
        prev
          ? { ...prev, manual_killswitch: snap.manual_killswitch, blocked_providers: snap.blocked_providers ?? prev.blocked_providers }
          : prev,
      );
      const decision = shouldInvalidateOnPauseStatus(snap);
      if (decision.invalidate) {
        invalidateReports(decision.onlyProviders, decision.includeAll);
      }
      fetchAppState()
        .then((st) => {
          if (!cancelled && seq === pauseSeq) setState(st);
        })
        .catch(() => {});
    })
      .then((un) => (cancelled ? un() : (off = un)))
      .catch(() => {});
    return () => {
      cancelled = true;
      off?.();
    };
  }, [invalidateReports]);

  // Фоновый запуск шлюза: узнаём стартовое состояние и ловим его окончание.
  useEffect(() => {
    let off: (() => void) | undefined;
    let cancelled = false;
    onStartupChanged((snapshot) => setStartup(snapshot))
      .then((un) => (cancelled ? un() : (off = un)))
      .catch(() => {});
    getStartupState()
      .then((snapshot) => setStartup((prev) => (prev.phase === "ready" ? prev : snapshot)))
      // Не смогли спросить: считаем, что запуск закончен, а не держим «Проверяем…» вечно.
      .catch(() => setStartup({ phase: "ready" }));
    return () => {
      cancelled = true;
      off?.();
    };
  }, []);

  // Запуск закончился: защита уже включена (или нет), перечитываем то, что до этого описывало «ещё не включено».
  useEffect(() => {
    if (startupPending) return;
    getSysproxyStatus()
      .then(setSysproxyActive)
      .catch(() => {});
    refreshCoverage();
  }, [startupPending, refreshCoverage]);

  // Стартовый аудит.
  useEffect(() => {
    runFullAudit(true, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const disabledSet = useMemo(
    () => new Set((state?.disabled_providers ?? []).map((p) => p.toLowerCase())),
    [state?.disabled_providers],
  );
  const activeReport =
    (!disabledSet.has("anthropic") && reports.anthropic) ||
    (!disabledSet.has("openai") && reports.openai) ||
    (!disabledSet.has("gemini") && reports.gemini) ||
    reports.anthropic ||
    reports.openai ||
    reports.gemini ||
    null;
  /** Худший из трёх отчётов: его показывает «Проверки» без выбранного сервиса, по нему считается бейдж вкладки. */
  const checksReport = useMemo(
    () => pickWorstReport(reports, state?.disabled_providers)?.report ?? null,
    [reports, state?.disabled_providers],
  );

  const guardSuppressedRef = useRef(false);
  guardSuppressedRef.current = shouldSuppressSelfHeal(guardPauseStatus);

  // Самолечение на старте: если первый аудит упёрся в холодный старт сети/PAC и вернулся без IP или провайдера,
  // перепроверяем сами, до шести раз с шагом 1,5 с. При pending/paused шлюзе не запускаем.
  useEffect(() => {
    if (shouldSuppressSelfHeal(guardPauseStatus)) {
      return;
    }

    const missingIp = !activeReport || !activeReport.telemetry?.ip || activeReport.telemetry.ip === "--";
    const missingProvider =
      activeReport &&
      !activeReport.telemetry?.asn &&
      !activeReport.telemetry?.isp &&
      !activeReport.telemetry?.org;

    if (!missingIp && !missingProvider) {
      return;
    }

    let attempts = 0;
    const maxAttempts = 6;
    const timer = setInterval(() => {
      // Пока идёт аудит или шлюз в pending/paused, новый не запускаем.
      if (inFlight.current > 0 || guardSuppressedRef.current) return;
      attempts += 1;
      if (attempts > maxAttempts) {
        clearInterval(timer);
        return;
      }
      runFullAudit(true, true);
    }, 1500);

    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    activeReport?.telemetry?.ip, activeReport?.telemetry?.asn,
    activeReport?.telemetry?.isp, activeReport?.telemetry?.org,
    guardPauseStatus?.gate, guardPauseStatus?.paused,
  ]);

  // Раз в 30 секунд пересчитываем возраст отчёта.
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30000);
    return () => clearInterval(timer);
  }, []);

  // Фоновое обновление отчёта из стража/трея: сбрасывает возраст данных и подтягивает свежий отчёт.
  useEffect(() => {
    let off: (() => void) | undefined;
    let cancelled = false;
    onAuditRefreshed((report) => {
      const provider = report.provider || "anthropic";
      setReports((prev) => ({ ...prev, [provider]: report }));
      if (isValidGatewayLatency(report.gateway_latency_ms)) {
        setScanLatencyMs(Math.round(report.gateway_latency_ms));
      }
      setAuditError(null);
      const ts = Date.now();
      reportAtRef.current = ts;
      setReportAt(ts);
      fetchAppState()
        .then((st) => {
          setState(st);
          if (st.auto_update_enabled !== undefined) setAutoUpdateEnabled(st.auto_update_enabled);
        })
        .catch(() => {});
    })
      .then((un) => (cancelled ? un() : (off = un)))
      .catch(() => {});
    return () => {
      cancelled = true;
      off?.();
    };
  }, []);

  // Возврат фокуса/видимости окна: перепроверяем, если с последнего отчёта прошло > 3 минут.
  const runFullAuditRef = useRef(runFullAudit);
  runFullAuditRef.current = runFullAudit;
  useEffect(() => {
    const maybeRefresh = () => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
      if (inFlight.current > 0) return;
      const last = reportAtRef.current;
      if (last == null || Date.now() - last <= FOCUS_REFRESH_MS) return;
      void runFullAuditRef.current(false, true);
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") maybeRefresh();
    };
    window.addEventListener("focus", maybeRefresh);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.removeEventListener("focus", maybeRefresh);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  /** «Данные N мин назад»: показываем только при ошибке обновления или если отчёт старше 15 минут. */
  const dataAgeMinutes = useMemo<number | null>(() => {
    if (!activeReport || reportAt == null) return null;
    return dataAge(now - reportAt, auditError != null);
  }, [activeReport, reportAt, now, auditError]);

  /** Что уже известно о первом аудите, пока отчёта нет (для экранов «Обзор» и «Проверки»). */
  const partialAudit = !activeReport ? (partials.anthropic ?? null) : null;

  const currentIp = activeReport?.telemetry.ip || "--";
  const currentCountry = activeReport?.telemetry.country_code || "--";
  const trustScore = activeReport?.trust_score ?? 100;

  return {
    state, setState, reports, refreshing, scanLatencyMs,
    sysproxyActive, setSysproxyActive, autoUpdateEnabled, setAutoUpdateEnabled,
    auditError, startupPending, partialAudit, dataAgeMinutes,
    activeReport, checksReport, currentIp, currentCountry, trustScore,
    routesSnapshot, setRoutesSnapshot, refreshRoutes, runFullAudit, runProviderAudit,
    refreshState, coverageSnapshot, setCoverageSnapshot, refreshCoverage,
    guardPauseStatus, setGuardPauseStatus, invalidateReports,
  };
}

export type GatewayState = ReturnType<typeof useGatewayState>;
