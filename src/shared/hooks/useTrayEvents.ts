import { useEffect, useRef } from "react";
import type { Dispatch, SetStateAction } from "react";
import { listen } from "@tauri-apps/api/event";
import { isTauri } from "@tauri-apps/api/core";
import type {
  EnrichedPayload,
  ProfileSwitchResult,
  RiskInterceptPayload,
  UpdateCheckResult,
  UpdateProgressPayload,
  UpdateStatusPayload,
} from "../../types";
import { applyEnriched } from "../../features/alert/alertState";
import { auditConnection, pinCurrentIp } from "../../utils/api";
import { toast as t } from "../copy/ru";
import { parseAdminAuthError } from "./useProtectionToggles";
import type { ShowToast } from "./useToasts";

/** Обработчики событий Tauri. Хук держит их в ref, поэтому подписки ставятся один раз и вызывают свежие версии. */
export interface TrayEventHandlers {
  showToast: ShowToast;
  /** interceptor://open-guide: открыть вкладку «Гайды» на нужном гайде. */
  openGuide: (guideId: string) => void;
  /** tray://open-profiles: открыть «Бэкап». */
  openBackup: () => void;
  runFullAudit: (force?: boolean, silentError?: boolean) => Promise<void>;
  /** Перечитать AppStateData (tray://state-changed, tray://profile-switched). */
  refreshState: () => Promise<unknown>;
  /** Перечитать снимок маршрутов. */
  refreshRoutes?: () => Promise<unknown>;
  /** Перечитать фактический статус системного прокси и защиты CLI. */
  syncProtectionStatus?: () => Promise<void>;
  /** Обновить список профилей Claude в интерфейсе. */
  refreshProfiles?: () => void;
  checkUpdates: (silent?: boolean) => Promise<void>;
  syncTimezone: () => Promise<void>;
  exportClaude: () => Promise<void>;
  openCrashTest: () => void;
  setKillswitchFrozen: (frozen: boolean) => void;
  setInterceptPayload: Dispatch<SetStateAction<RiskInterceptPayload | null>>;
  invalidateReports?: (onlyProviders?: string[], includeAll?: boolean) => void;
  applyUpdateProgress: (payload: UpdateProgressPayload) => void;
  applyUpdateAvailable: (payload: UpdateCheckResult) => void;
  applyUpdateStatus: (payload: UpdateStatusPayload) => void;
}

/** Обработчик события `tray://profile-switched`: читает имя из `active_profile.name` и обновляет состояние, маршруты и профили. */
export async function handleTrayProfileSwitched(
  handlers: Pick<TrayEventHandlers, "refreshState" | "refreshRoutes" | "refreshProfiles" | "showToast" | "runFullAudit">,
  payload?: Partial<ProfileSwitchResult> | null,
): Promise<void> {
  try {
    await Promise.all([handlers.refreshState(), handlers.refreshRoutes?.()]);
  } catch {}
  handlers.refreshProfiles?.();
  handlers.showToast(t.profile.switched, payload?.active_profile?.name || t.profile.switchedText, "info");
  handlers.runFullAudit(false);
}

/** Обработчик события `sysproxy://admin-auth-required`: предупреждает о неполной защите PAC при старте и подсказывает «Разрешить с паролем». */
export function handleSysproxyAdminAuthRequired(
  handlers: Pick<TrayEventHandlers, "showToast">,
  payload?: string | null,
): void {
  const parsed = payload ? parseAdminAuthError(payload) : null;
  const detail = parsed ? `${parsed} Откройте «Нейросети и защита» → «Разрешить с паролем».` : t.sysproxy.adminAuthText;
  handlers.showToast(t.sysproxy.adminAuthTitle, detail, "warning");
}

/** Инвалидирует устаревшие отчёты при смене сети и запускает перепроверку. */
export function handleNetworkChangedEvent(
  handlers: Pick<TrayEventHandlers, "invalidateReports" | "runFullAudit">,
): void {
  handlers.invalidateReports?.();
  void handlers.runFullAudit(true);
}

/** При `detecting` / `failed` / сетевом риске сбрасывает устаревшие отчёты, чтобы сервис не выглядел «Доступен». */
export function handleRiskDetectedEvent(
  handlers: Pick<TrayEventHandlers, "invalidateReports" | "refreshState" | "setInterceptPayload">,
  payload: RiskInterceptPayload,
): void {
  if (payload.phase === "detecting" || payload.phase === "failed" || payload.scope === "network") {
    const only = payload.scope === "provider" ? [payload.provider] : undefined;
    handlers.invalidateReports?.(only, false);
    void handlers.refreshState();
  }
  handlers.setInterceptPayload((prev) =>
    prev && prev.id === payload.id && prev.phase !== "detecting" && payload.phase === "detecting" ? prev : payload,
  );
}

/** После закрытия/разрешения алерта очищает устаревшие отчёты, обновляет state и запускает аудит. */
export function handleInterceptorResolvedEvent(
  handlers: Pick<TrayEventHandlers, "invalidateReports" | "refreshState" | "setInterceptPayload" | "runFullAudit">,
): void {
  handlers.setInterceptPayload(null);
  handlers.invalidateReports?.();
  void handlers.refreshState();
  void handlers.runFullAudit(false);
}

/**
 * Все подписки главного окна на события Rust (только в Tauri):
 * interceptor://open-guide, tray://rescan, tray://check-updates, tray://sync-tz, tray://backup-claude,
 * tray://open-crash-test, tray://killswitch-toggled, tray://state-changed, tray://profile-switched,
 * tray://open-profiles, updater://progress, updater://available, updater://status, tray://pin-current-ip,
 * network://changed, interceptor://risk-detected, interceptor://resolved.
 */
export function useTrayEvents(handlers: TrayEventHandlers) {
  const ref = useRef(handlers);
  ref.current = handlers;

  useEffect(() => {
    if (!isTauri()) return;

    let cancelled = false;
    const unlisteners: Array<() => void> = [];
    const on = <P = unknown>(event: string, cb: (payload: P) => void | Promise<void>) => {
      listen<P>(event, (e) => {
        void cb(e.payload);
      }).then((un) => {
        // Если эффект уже снят, подписку закрываем сразу — иначе она осталась бы висеть.
        if (cancelled) un();
        else unlisteners.push(un);
      });
    };

    on<string>("interceptor://open-guide", (payload) => {
      ref.current.openGuide(payload || "01-personal-vpn-15min");
    });

    on("tray://rescan", () => {
      ref.current.runFullAudit(true);
    });

    on("tray://check-updates", () => {
      ref.current.checkUpdates(false);
    });

    on("tray://sync-tz", () => {
      ref.current.syncTimezone();
    });

    on("tray://backup-claude", () => {
      ref.current.exportClaude();
    });

    on("tray://open-crash-test", () => {
      ref.current.openCrashTest();
    });

    on<boolean>("tray://killswitch-toggled", (frozen) => {
      ref.current.setKillswitchFrozen(frozen);
      ref.current.showToast(
        frozen ? t.killswitch.onTitle : t.killswitch.offTitle,
        frozen ? t.killswitch.onText : t.killswitch.offText,
        frozen ? "warning" : "success",
      );
    });

    on("tray://state-changed", async () => {
      try {
        await Promise.all([
          ref.current.refreshState(),
          ref.current.refreshRoutes?.(),
          ref.current.syncProtectionStatus?.(),
        ]);
      } catch {}
    });

    on("tray://sysproxy-toggled", async () => {
      try {
        await ref.current.syncProtectionStatus?.();
      } catch {}
    });

    on("tray://cli-toggled", async () => {
      try {
        await ref.current.syncProtectionStatus?.();
      } catch {}
    });

    on<ProfileSwitchResult>("tray://profile-switched", (payload) =>
      handleTrayProfileSwitched(ref.current, payload),
    );

    on("tray://open-profiles", () => {
      ref.current.openBackup();
    });

    on<UpdateProgressPayload>("updater://progress", (payload) => {
      ref.current.applyUpdateProgress(payload);
    });

    on<UpdateCheckResult>("updater://available", (payload) => {
      ref.current.applyUpdateAvailable(payload);
    });

    on<UpdateStatusPayload>("updater://status", (payload) => {
      ref.current.applyUpdateStatus(payload);
    });

    on("tray://pin-current-ip", async () => {
      try {
        const rep = await auditConnection("anthropic", false);
        if (rep.telemetry.ip) {
          await pinCurrentIp(rep.telemetry.ip);
          ref.current.runFullAudit(false);
        }
      } catch (err) {
        console.warn("Could not pin current IP from tray:", err);
      }
    });

    on("network://changed", () => {
      handleNetworkChangedEvent(ref.current);
    });

    on<string>("sysproxy://admin-auth-required", (payload) => {
      handleSysproxyAdminAuthRequired(ref.current, payload);
    });

    // Эпоха последнего enriched по текущему алерту: чужие и устаревшие события игнорируются.
    let enrichedEpoch: number | null = null;
    on<RiskInterceptPayload>("interceptor://risk-detected", (payload) => {
      enrichedEpoch = null;
      handleRiskDetectedEvent(ref.current, payload);
    });

    on<EnrichedPayload>("interceptor://enriched", (enriched) => {
      ref.current.setInterceptPayload((prev) => {
        const applied = applyEnriched(prev, enrichedEpoch, enriched);
        if (!applied) return prev;
        enrichedEpoch = applied.epoch;
        return applied.payload;
      });
    });

    on("interceptor://resolved", () => {
      handleInterceptorResolvedEvent(ref.current);
    });

    return () => {
      cancelled = true;
      unlisteners.forEach((u) => u());
    };
  }, []);
}
