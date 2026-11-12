import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  AppStateData,
  AuditProgressEvent,
  CoverageSnapshot,
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
  getRoutesSnapshot,
  getStartupState,
  getSysproxyStatus,
  onAuditProgress,
  onStartupChanged,
} from "../../utils/api";
import { toast as t } from "../copy/ru";
import type { ShowToast } from "./useToasts";
import { pickWorstReport } from "../../features/checks/checksModel";

/** Возраст отчёта в минутах для подписи или null, если данные свежие. Вынесено для тестов. */
export function dataAge(ageMs: number, auditFailed: boolean): number | null {
  const minutes = Math.max(1, Math.floor(ageMs / 60000));
  return ageMs > 2 * 60000 || auditFailed ? minutes : null;
}

/** Число проверок в отчёте шлюза (места 0..12 в `RiskReport.checks`). */
export const CHECK_SLOTS = 13;

/** Новый идущий аудит: ничего ещё не готово. */
export function emptyPartial(provider: ProviderId, runId: string): PartialAudit {
  return { runId, provider, telemetry: null, checks: Array.from({ length: CHECK_SLOTS }, () => null) };
}

/** Вносит кусок аудита в накопленное; события чужого запуска (устаревшего) игнорируются. */
export function applyProgress(prev: PartialAudit | undefined, event: AuditProgressEvent): PartialAudit | undefined {
  if (!prev || prev.runId !== event.run_id) return prev;
  if (event.kind === "telemetry") return { ...prev, telemetry: event.telemetry };
  if (event.index < 0 || event.index >= prev.checks.length) return prev;
  const checks = prev.checks.slice();
  checks[event.index] = event.result;
  return { ...prev, checks };
}

interface Options {
  showToast: ShowToast;
  refreshGatewayStats: () => Promise<void>;
}

/**
 * Состояние шлюза: AppStateData, отчёты аудита по трём сервисам, статус системного прокси, задержка проверки.
 * Здесь же стартовый аудит и «самолечение» — повторный опрос, пока не определились IP и провайдер.
 */
export function useGatewayState({ showToast, refreshGatewayStats }: Options) {
  const [state, setState] = useState<AppStateData | null>(null);
  const [reports, setReports] = useState<Partial<Record<ProviderId, RiskReport>>>({});
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [scanLatencyMs, setScanLatencyMs] = useState<number>(38);
  const [sysproxyActive, setSysproxyActive] = useState<boolean>(true);
  const [autoUpdateEnabled, setAutoUpdateEnabled] = useState<boolean>(true);
  /** Текст последней ошибки аудита; сбрасывается при успешном проходе. Нужен экрану «нет сети». */
  const [auditError, setAuditError] = useState<string | null>(null);
  const [routesSnapshot, setRoutesSnapshot] = useState<RoutesSnapshot | null>(null);
  const [coverageSnapshot, setCoverageSnapshot] = useState<CoverageSnapshot | null>(null);
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

  /** Перечитать AppStateData, маршруты и покрытие без аудита (тихо: ошибки только в консоль). */
  const refreshState = useCallback(async () => {
    const [st] = await Promise.all([fetchAppState(), refreshRoutes(), refreshCoverage()]);
    setState(st);
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
        setReportAt(Date.now());

        const [gptSettled, geminiSettled] = await Promise.allSettled([
          auditConnection("openai", false),
          auditConnection("gemini", false),
        ]);

        setReports((prev) => ({
          ...prev,
          anthropic: claudeReport,
          ...(gptSettled.status === "fulfilled" ? { openai: gptSettled.value } : {}),
          ...(geminiSettled.status === "fulfilled" ? { gemini: geminiSettled.value } : {}),
        }));

        const elapsed = Math.round(performance.now() - startTime);
        setScanLatencyMs(Math.max(18, elapsed));
        await sideReads;
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

  const activeReport = reports.anthropic || reports.openai || reports.gemini || null;
  /** Худший из трёх отчётов: его показывает «Проверки» без выбранного сервиса, по нему считается бейдж вкладки. */
  const checksReport = useMemo(() => pickWorstReport(reports)?.report ?? null, [reports]);

  // Самолечение на старте: если первый аудит упёрся в холодный старт сети/PAC и вернулся без IP или провайдера,
  // перепроверяем сами, до шести раз с шагом 1,5 с.
  useEffect(() => {
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
      // Пока идёт аудит, новый не запускаем: параллельные принудительные запуски только замедляют старт.
      if (inFlight.current > 0) return;
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
    activeReport?.telemetry?.ip,
    activeReport?.telemetry?.asn,
    activeReport?.telemetry?.isp,
    activeReport?.telemetry?.org,
  ]);

  // Раз в 30 секунд пересчитываем возраст отчёта.
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30000);
    return () => clearInterval(timer);
  }, []);

  /** «Данные N мин назад»: показываем, если отчёту больше двух минут или последний аудит упал. */
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
    state,
    setState,
    reports,
    refreshing,
    scanLatencyMs,
    sysproxyActive,
    setSysproxyActive,
    autoUpdateEnabled,
    setAutoUpdateEnabled,
    auditError,
    startupPending,
    partialAudit,
    dataAgeMinutes,
    activeReport,
    checksReport,
    currentIp,
    currentCountry,
    trustScore,
    routesSnapshot,
    setRoutesSnapshot,
    refreshRoutes,
    refreshState,
    runFullAudit,
    coverageSnapshot,
    setCoverageSnapshot,
    refreshCoverage,
  };
}

export type GatewayState = ReturnType<typeof useGatewayState>;
