import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import type { AutostartStatus, CliMode, CoworkGuardStatus, InterceptionBehavior, PopupPosition } from "../../types";
import type { ShowToast } from "../../shared/hooks";
import { parseTempDnsDeferredError } from "../../shared/hooks/useProtectionToggles";
import {
  addCustomAiDomain,
  forceCleanOsProxy,
  getAutostartStatus,
  getCliSettings,
  getCoworkGuardStatus,
  getCustomAiDomains,
  getInterceptionBehavior,
  getPopupPosition,
  getSplitTunnelMode,
  installOrRepairCoworkGuard,
  onCoworkGuardStatus,
  removeCustomAiDomain,
  setAutostartEnabled,
  setCliMode,
  setInterceptionBehavior,
  setPopupPosition,
  setSplitTunnelMode,
  setSyncAiTzEnabled,
} from "../../utils/api";
import { useOsTimezoneSync } from "../../shared/hooks/useTimezoneSync";
import { openExternal } from "../../utils/opener";
import { Badge, Banner, Button, ConfirmModal, Field, Link, Modal, Mono, Row, Rows, Section, Segmented, Switch } from "../../ui";
import type { SegmentedOption } from "../../ui";
import { settings as copy } from "../../shared/copy/ru";

import "./settings.css";

const SOURCE_URL = "https://github.com/kingbest1195/ai-antiban";

export interface SettingsModalProps {
  open: boolean;
  onClose: () => void;
  autoUpdateEnabled: boolean;
  onToggleAutoUpdate: (enabled: boolean) => Promise<void>;
  interceptionBehavior?: InterceptionBehavior;
  popupPosition?: PopupPosition;
  customAiDomains?: string[];
  onStateUpdated?: () => void;
  onToast?: ShowToast;
}

const BEHAVIOR_OPTIONS: SegmentedOption<InterceptionBehavior>[] = (
  ["ask_popup", "auto_lock_silent", "auto_allow_trusted"] as const
).map((value) => ({ value, label: copy.behavior.options[value] }));

const CLI_MODE_OPTIONS: SegmentedOption<CliMode>[] = (["ai_only", "global_terminal"] as const).map((value) => ({
  value,
  label: copy.terminal.mode.options[value],
}));

const POSITION_OPTIONS: SegmentedOption<PopupPosition>[] = (["top_right", "top_center"] as const).map((value) => ({
  value,
  label: copy.position.options[value],
}));

const errText = (err: unknown) => (err instanceof Error ? err.message : String(err));

/** Настройки: поведение при обрыве VPN, домены ИИ, автообновление, приватность, сброс системного прокси. */
export function SettingsModal({
  open,
  onClose,
  autoUpdateEnabled,
  onToggleAutoUpdate,
  interceptionBehavior: propBehavior,
  popupPosition: propPosition,
  customAiDomains: propCustomDomains,
  onStateUpdated,
  onToast,
}: SettingsModalProps) {
  const [updatingToggle, setUpdatingToggle] = useState(false);
  const [behavior, setBehavior] = useState<InterceptionBehavior>(propBehavior || "ask_popup");
  const [position, setPosition] = useState<PopupPosition>(propPosition || "top_right");
  const [customDomains, setCustomDomains] = useState<string[]>(propCustomDomains || []);
  const [newDomainInput, setNewDomainInput] = useState("");
  const [domainBusy, setDomainBusy] = useState(false);
  const [confirmProxy, setConfirmProxy] = useState(false);
  const [cleaningProxy, setCleaningProxy] = useState(false);
  const [cliMode, setCliModeState] = useState<CliMode>("ai_only");
  const [syncTz, setSyncTz] = useState(false);
  const [terminalBusy, setTerminalBusy] = useState(false);
  const [splitTunnelMode, setSplitTunnelModeState] = useState(false);
  const [splitTunnelBusy, setSplitTunnelBusy] = useState(false);
  const { osTzStatus, osTzLoading, osTzError, syncOsTimezone, restoreOsTimezone, refreshOsTzStatus } =
    useOsTimezoneSync();
  const [confirmGlobal, setConfirmGlobal] = useState(false);
  const [proxyResult, setProxyResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [autostartStatus, setAutostartStatus] = useState<AutostartStatus | null>(null);
  const [autostartBusy, setAutostartBusy] = useState(false);
  const [coworkStatus, setCoworkStatus] = useState<CoworkGuardStatus | null>(null);
  const [coworkBusy, setCoworkBusy] = useState(false);

  // При открытии окна подтягиваем сохранённые значения из шлюза.
  useEffect(() => {
    if (!open) return;
    if (propBehavior) setBehavior(propBehavior);
    if (propPosition) setPosition(propPosition);
    if (propCustomDomains) setCustomDomains(propCustomDomains);
    getInterceptionBehavior()
      .then(setBehavior)
      .catch(() => {});
    getPopupPosition()
      .then(setPosition)
      .catch(() => {});
    getCustomAiDomains()
      .then(setCustomDomains)
      .catch(() => {});
    getCliSettings()
      .then((cli) => {
        setCliModeState(cli.cli_mode);
        setSyncTz(cli.sync_ai_tz_enabled);
      })
      .catch(() => {});
    getSplitTunnelMode()
      .then(setSplitTunnelModeState)
      .catch(() => {});
    void refreshOsTzStatus();
    getAutostartStatus()
      .then(setAutostartStatus)
      .catch(() => {});
    getCoworkGuardStatus()
      .then(setCoworkStatus)
      .catch(() => {});
    setProxyResult(null);

    let unlisten: (() => void) | undefined;
    let active = true;
    onCoworkGuardStatus((status) => {
      if (active) setCoworkStatus(status);
    })
      .then((fn) => {
        if (active) unlisten = fn;
        else fn();
      })
      .catch(() => {});

    return () => {
      active = false;
      unlisten?.();
    };
  }, [open, propBehavior, propPosition, propCustomDomains]);

  const handleToggleAutostart = async () => {
    if (autostartBusy) return;
    const next = !(autostartStatus?.active_in_os ?? autostartStatus?.enabled ?? false);
    setAutostartBusy(true);
    try {
      const updated = await setAutostartEnabled(next);
      setAutostartStatus(updated);
      onStateUpdated?.();
      if (updated.active_in_os) {
        onToast?.(copy.autostart.toastOnTitle, copy.autostart.toastOnText, "success");
      } else {
        onToast?.(copy.autostart.toastOffTitle, copy.autostart.toastOffText, "info");
      }
    } catch (err) {
      onToast?.(copy.autostart.error, errText(err), "warning");
    } finally {
      setAutostartBusy(false);
    }
  };

  const handleInstallCoworkGuard = async () => {
    if (coworkBusy) return;
    setCoworkBusy(true);
    try {
      const updated = await installOrRepairCoworkGuard();
      setCoworkStatus(updated);
      onStateUpdated?.();
      onToast?.(copy.coworkGuard.toastOkTitle, updated.summary, updated.needs_repair ? "warning" : "success");
    } catch (err) {
      onToast?.(copy.coworkGuard.toastErrTitle, errText(err), "warning");
    } finally {
      setCoworkBusy(false);
    }
  };

  const handleRefreshCoworkGuard = async () => {
    if (coworkBusy) return;
    setCoworkBusy(true);
    try {
      const updated = await getCoworkGuardStatus();
      setCoworkStatus(updated);
    } catch {
      // ignore
    } finally {
      setCoworkBusy(false);
    }
  };

  const handleToggleAutoUpdate = async () => {
    if (updatingToggle) return;
    setUpdatingToggle(true);
    try {
      await onToggleAutoUpdate(!autoUpdateEnabled);
    } finally {
      setUpdatingToggle(false);
    }
  };

  /** Тумблер выборочной маршрутизации VPN (split tunneling). */
  const handleToggleSplitTunnel = async () => {
    if (splitTunnelBusy) return;
    const next = !splitTunnelMode;
    setSplitTunnelBusy(true);
    try {
      await setSplitTunnelMode(next);
      setSplitTunnelModeState(next);
      onStateUpdated?.();
      if (next) onToast?.(copy.splitTunnel.toastOnTitle, copy.splitTunnel.toastOnText, "success");
      else onToast?.(copy.splitTunnel.toastOffTitle, copy.splitTunnel.toastOffText, "info");
    } catch (err) {
      onToast?.(copy.splitTunnel.error, errText(err), "warning");
    } finally {
      setSplitTunnelBusy(false);
    }
  };

  /** Тумблер подмены TZ/локали: независим от защиты CLI; при ошибке показываем текст и оставляем прежнее значение. */
  const handleToggleSyncTz = async () => {
    if (terminalBusy) return;
    const next = !syncTz;
    setTerminalBusy(true);
    try {
      const res = await setSyncAiTzEnabled(next);
      setSyncTz(res.sync_ai_tz_enabled);
      onStateUpdated?.();
      if (res.sync_ai_tz_enabled) onToast?.(copy.terminal.tz.toastOnTitle, copy.terminal.tz.toastOnText, "success");
      else onToast?.(copy.terminal.tz.toastOffTitle, copy.terminal.tz.toastOffText, "info");
    } catch (err) {
      onToast?.(copy.terminal.tz.error, errText(err), "warning");
    } finally {
      setTerminalBusy(false);
    }
  };

  const applyCliMode = async (next: CliMode) => {
    setTerminalBusy(true);
    try {
      const res = await setCliMode(next);
      setCliModeState(res.cli_mode);
      onStateUpdated?.();
      onToast?.(copy.terminal.mode.toastTitle, copy.terminal.mode.toastText[res.cli_mode], "success");
    } catch (err) {
      // Режим не изменился: показываем текст отказа и остаёмся на прежнем значении.
      onToast?.(copy.terminal.mode.error, errText(err), "warning");
    } finally {
      setTerminalBusy(false);
    }
  };

  const handleCliModeChange = (next: CliMode) => {
    if (terminalBusy || next === cliMode) return;
    if (next === "global_terminal") setConfirmGlobal(true);
    else void applyCliMode(next);
  };

  const handleBehaviorChange = async (next: InterceptionBehavior) => {
    setBehavior(next);
    try {
      await setInterceptionBehavior(next);
      onStateUpdated?.();
      onToast?.(copy.behavior.toastTitle, copy.behavior.toastText[next], "success");
    } catch (err) {
      onToast?.(copy.behavior.saveError, errText(err), "warning");
    }
  };

  const handlePositionChange = async (next: PopupPosition) => {
    setPosition(next);
    try {
      await setPopupPosition(next);
      onStateUpdated?.();
      onToast?.(copy.position.toastTitle, copy.position.toastText[next], "info");
    } catch (err) {
      onToast?.(copy.behavior.saveError, errText(err), "warning");
    }
  };

  const handleAddDomain = async (e: FormEvent) => {
    e.preventDefault();
    // Протокол, порт и путь убираем: пользователь мог вставить адрес целиком.
    const domain = newDomainInput
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//i, "")
      .replace(/\/.*$/, "")
      .replace(/:\d+$/, "")
      .trim();
    if (!domain) return;
    setDomainBusy(true);
    try {
      const updated = await addCustomAiDomain(domain);
      setCustomDomains(updated);
      setNewDomainInput("");
      onStateUpdated?.();
      onToast?.(copy.domains.addedTitle, copy.domains.addedText(domain), "success");
    } catch (err) {
      onToast?.(copy.domains.addError, errText(err), "warning");
    } finally {
      setDomainBusy(false);
    }
  };

  const handleRemoveDomain = async (domain: string) => {
    setDomainBusy(true);
    try {
      const updated = await removeCustomAiDomain(domain);
      setCustomDomains(updated);
      onStateUpdated?.();
      onToast?.(copy.domains.removedTitle, copy.domains.removedText(domain), "info");
    } catch (err) {
      onToast?.(copy.domains.removeError, errText(err), "warning");
    } finally {
      setDomainBusy(false);
    }
  };

  const handleCleanOsProxy = async () => {
    setCleaningProxy(true);
    setProxyResult(null);
    try {
      const results = await forceCleanOsProxy();
      setProxyResult({ ok: true, text: results.length > 0 ? results.join(" · ") : copy.proxy.doneDefault });
      onToast?.(copy.proxy.toastTitle, copy.proxy.toastText, "success");
    } catch (err) {
      const deferred = parseTempDnsDeferredError(err);
      if (deferred !== null) {
        setProxyResult({ ok: true, text: deferred });
        onToast?.(copy.proxy.toastTitle, deferred, "info");
        return;
      }
      const message = errText(err);
      setProxyResult({ ok: false, text: message });
      onToast?.(copy.proxy.toastError, message, "warning");
    } finally {
      setCleaningProxy(false);
      setConfirmProxy(false);
    }
  };

  return (
    <>
      <Modal
        open={open}
        onClose={onClose}
        title={copy.title}
        footer={<Button onClick={onClose}>{copy.close}</Button>}
      >
        <div className="zs-settings">
          {/* Если VPN отключился */}
          <Section title={copy.behavior.section}>
            <p className="zs-t-body zs-settings__lead">{copy.behavior.text}</p>
            <Segmented
              aria-label={copy.behavior.label}
              options={BEHAVIOR_OPTIONS}
              value={behavior}
              onChange={handleBehaviorChange}
            />
            <p className="zs-settings__hint" aria-live="polite">
              {copy.behavior.hints[behavior]}
            </p>
            {behavior === "ask_popup" && (
              <>
                <p className="zs-settings__label">{copy.position.label}</p>
                <Segmented
                  aria-label={copy.position.label}
                  options={POSITION_OPTIONS}
                  value={position}
                  onChange={handlePositionChange}
                />
              </>
            )}
          </Section>

          {/* Выборочная маршрутизация VPN (split tunneling) */}
          <Section title={copy.splitTunnel.section}>
            <Rows className="zs-settings__rows">
              <Row
                icon="shield"
                title={copy.splitTunnel.title}
                sub={copy.splitTunnel.sub}
                trail={
                  <Switch
                    checked={splitTunnelMode}
                    disabled={splitTunnelBusy}
                    onChange={handleToggleSplitTunnel}
                    aria-label={copy.splitTunnel.label}
                  />
                }
              />
            </Rows>
          </Section>

          {/* Терминал и редакторы: режим покрытия CLI и подмена часового пояса */}
          <Section title={copy.terminal.section}>
            <p className="zs-settings__label">{copy.terminal.mode.title}</p>
            <Segmented
              aria-label={copy.terminal.mode.label}
              options={CLI_MODE_OPTIONS}
              value={cliMode}
              onChange={handleCliModeChange}
            />
            <p className="zs-settings__hint" aria-live="polite">
              {copy.terminal.mode.hints[cliMode]}
            </p>
            <Rows className="zs-settings__rows">
              <Row
                icon="refresh"
                title={copy.terminal.tz.title}
                sub={copy.terminal.tz.sub}
                trail={
                  <Switch
                    checked={syncTz}
                    disabled={terminalBusy}
                    onChange={handleToggleSyncTz}
                    aria-label={copy.terminal.tz.label}
                  />
                }
              />
              <Row
                icon="globe"
                title={copy.terminal.osTz.title}
                sub={
                  osTzStatus?.synced
                    ? `${copy.terminal.osTz.synced(osTzStatus.original_os_tz, osTzStatus.synced_target_tz)} — ${copy.terminal.osTz.restartHint}`
                    : copy.terminal.osTz.notSynced(osTzStatus?.current_os_tz ?? null)
                }
                trail={
                  osTzStatus?.synced ? (
                    <Button
                      size="sm"
                      variant="secondary"
                      disabled={osTzLoading}
                      onClick={() => void restoreOsTimezone()}
                    >
                      {osTzLoading ? copy.terminal.osTz.restoringAction : copy.terminal.osTz.restoreAction}
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      variant="primary"
                      disabled={osTzLoading}
                      onClick={() => void syncOsTimezone()}
                    >
                      {osTzLoading ? copy.terminal.osTz.syncingAction : copy.terminal.osTz.syncAction}
                    </Button>
                  )
                }
              />
            </Rows>
            {osTzError && (
              <p className="zs-settings__hint" role="alert">
                {osTzError}
              </p>
            )}
          </Section>

          {/* Сервисы ИИ и свои домены */}
          <Section title={copy.domains.section}>
            <p className="zs-t-body zs-settings__lead">{copy.domains.text}</p>
            <p className="zs-settings__sub">{copy.domains.builtinTitle}</p>
            <ul className="zs-settings__list">
              {copy.domains.builtin.map((name) => (
                <li key={name}>{name}</li>
              ))}
            </ul>

            <p className="zs-settings__sub">
              {copy.domains.ownTitle} <Badge>{copy.domains.ownCount(customDomains.length)}</Badge>
            </p>
            <form className="zs-settings__form" onSubmit={handleAddDomain}>
              <Field
                label={copy.domains.fieldLabel}
                placeholder={copy.domains.placeholder}
                help={copy.domains.help}
                value={newDomainInput}
                onChange={(e) => setNewDomainInput(e.target.value)}
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                action={
                  <Button type="submit" disabled={domainBusy || !newDomainInput.trim()}>
                    {domainBusy ? copy.domains.adding : copy.domains.add}
                  </Button>
                }
              />
            </form>
            {customDomains.length > 0 ? (
              <Rows className="zs-settings__rows">
                {customDomains.map((domain) => (
                  <Row
                    key={domain}
                    icon="globe"
                    title={<Mono>{domain}</Mono>}
                    trail={
                      <Button
                        variant="quiet"
                        size="sm"
                        iconOnly
                        icon="x"
                        aria-label={copy.domains.remove(domain)}
                        disabled={domainBusy}
                        onClick={() => handleRemoveDomain(domain)}
                      />
                    }
                  />
                ))}
              </Rows>
            ) : (
              <p className="zs-settings__empty">{copy.domains.empty}</p>
            )}
          </Section>

          {/* Обновления */}
          <Section title={copy.updates.section}>
            <Rows>
              <Row
                icon="refresh"
                title={copy.updates.title}
                sub={autoUpdateEnabled ? copy.updates.on : copy.updates.off}
                trail={
                  <Switch
                    checked={autoUpdateEnabled}
                    disabled={updatingToggle}
                    onChange={handleToggleAutoUpdate}
                    aria-label={copy.updates.label}
                  />
                }
              />
            </Rows>
          </Section>

          {/* Автозапуск ОС */}
          <Section title={copy.autostart.section}>
            <Rows>
              <Row
                icon="power"
                title={copy.autostart.title}
                sub={
                  (autostartStatus?.active_in_os ?? autostartStatus?.enabled)
                    ? copy.autostart.subOn
                    : copy.autostart.subOff
                }
                trail={
                  <Switch
                    checked={Boolean(autostartStatus?.active_in_os ?? autostartStatus?.enabled)}
                    disabled={autostartBusy || (autostartStatus !== null && !autostartStatus.supported)}
                    onChange={handleToggleAutostart}
                    aria-label={copy.autostart.label}
                  />
                }
              />
            </Rows>
            {autostartStatus?.target && (
              <p className="zs-settings__hint">
                <Mono>{autostartStatus.target}</Mono>
              </p>
            )}
          </Section>

          {/* Защита от фонового запуска ИИ-служб (Windows CoworkVMService / macOS) */}
          <Section title={copy.coworkGuard.section}>
            {!coworkStatus ? (
              <p className="zs-settings__hint">{copy.coworkGuard.loading}</p>
            ) : (
              <>
                <Banner
                  tone={
                    coworkStatus.needs_repair
                      ? "warn"
                      : coworkStatus.platform === "windows" && coworkStatus.task_healthy
                      ? "ok"
                      : "info"
                  }
                  title={
                    coworkStatus.needs_repair
                      ? copy.coworkGuard.statusNeedsRepair
                      : coworkStatus.platform === "windows" && coworkStatus.task_healthy
                      ? copy.coworkGuard.statusHealthy
                      : copy.coworkGuard.statusInfo
                  }
                >
                  {coworkStatus.summary}
                </Banner>

                {coworkStatus.platform === "windows" && (
                  <div className="zs-settings__form" style={{ marginTop: "var(--space-2)", gap: "var(--space-2)", flexWrap: "wrap" }}>
                    {coworkStatus.service_present && coworkStatus.start_type !== null && (
                      <Badge
                        tone={
                          coworkStatus.start_type === 3
                            ? "ok"
                            : coworkStatus.start_type === 2
                            ? "warn"
                            : "danger"
                        }
                      >
                        {coworkStatus.start_type === 2
                          ? copy.coworkGuard.startAutoBadge
                          : coworkStatus.start_type === 3
                          ? copy.coworkGuard.startManualBadge
                          : copy.coworkGuard.startDisabledBadge}
                      </Badge>
                    )}
                    {coworkStatus.service_present && (
                      <Badge tone={coworkStatus.service_running ? "warn" : "ok"}>
                        {coworkStatus.service_running
                          ? copy.coworkGuard.serviceRunningBadge
                          : copy.coworkGuard.serviceStoppedBadge}
                      </Badge>
                    )}
                    <Badge tone={coworkStatus.task_healthy ? "ok" : "warn"}>
                      {coworkStatus.task_healthy
                        ? copy.coworkGuard.taskHealthyBadge
                        : copy.coworkGuard.taskMissingBadge}
                    </Badge>
                  </div>
                )}

                {coworkStatus.detected_ai_apps.length > 0 && (
                  <>
                    <p className="zs-settings__sub">{copy.coworkGuard.macosDetectedTitle}</p>
                    <Rows>
                      {coworkStatus.detected_ai_apps.map((item) => (
                        <Row
                          key={`${item.kind}:${item.name}:${item.detail}`}
                          icon="shield"
                          title={item.name}
                          sub={<Mono>{item.detail}</Mono>}
                          trail={<Badge tone="info">{item.kind === "process" ? "Процесс" : "LaunchAgent"}</Badge>}
                        />
                      ))}
                    </Rows>
                  </>
                )}

                <div className="zs-settings__form" style={{ marginTop: "var(--space-2)", flexWrap: "wrap" }}>
                  {coworkStatus.platform === "windows" && coworkStatus.supported && (
                    <Button
                      variant={coworkStatus.needs_repair ? "primary" : "secondary"}
                      size="sm"
                      disabled={coworkBusy}
                      onClick={handleInstallCoworkGuard}
                    >
                      {coworkBusy ? copy.coworkGuard.actionRepairing : copy.coworkGuard.actionInstall}
                    </Button>
                  )}
                  <Button
                    variant="quiet"
                    size="sm"
                    disabled={coworkBusy}
                    onClick={handleRefreshCoworkGuard}
                  >
                    {copy.coworkGuard.actionRecheck}
                  </Button>
                </div>
              </>
            )}
          </Section>

          {/* Приватность */}
          <Section title={copy.privacy.section}>
            <Rows>
              <Row icon="lock" title={copy.privacy.local} sub={copy.privacy.localText} />
              <Row icon="shield" title={copy.privacy.selectiveTitle} sub={copy.privacy.selectiveText} />
            </Rows>
            <p className="zs-settings__sub">{copy.privacy.networkTitle}</p>
            <Rows>
              {copy.privacy.network.map((n) => (
                <Row
                  key={n.what}
                  icon="globe"
                  title={n.what}
                  sub={
                    <>
                      <Mono>{n.where}</Mono>: {n.note}
                    </>
                  }
                />
              ))}
            </Rows>
            <p className="zs-settings__source">
              <Link
                href={SOURCE_URL}
                chevron
                onClick={(e) => {
                  e.preventDefault();
                  openExternal(SOURCE_URL);
                }}
              >
                {copy.privacy.source}
              </Link>
            </p>
          </Section>

          {/* Сброс системного прокси */}
          <Section title={copy.proxy.section}>
            <p className="zs-t-body zs-settings__lead">{copy.proxy.text}</p>
            <div className="zs-settings__danger">
              <Button variant="danger" icon="power" disabled={cleaningProxy} onClick={() => setConfirmProxy(true)}>
                {cleaningProxy ? copy.proxy.working : copy.proxy.action}
              </Button>
            </div>
            {proxyResult && (
              <Banner
                className="zs-settings__result"
                tone={proxyResult.ok ? "ok" : "danger"}
                role={proxyResult.ok ? "status" : "alert"}
                title={proxyResult.ok ? copy.proxy.done : copy.proxy.failed}
              >
                {proxyResult.text}
              </Banner>
            )}
          </Section>
        </div>
      </Modal>

      <ConfirmModal
        open={open && confirmGlobal}
        title={copy.terminal.mode.confirmTitle}
        confirmLabel={copy.terminal.mode.confirmAction}
        busy={terminalBusy}
        onConfirm={async () => {
          await applyCliMode("global_terminal");
          setConfirmGlobal(false);
        }}
        onCancel={() => setConfirmGlobal(false)}
      >
        {copy.terminal.mode.confirmText}
      </ConfirmModal>

      <ConfirmModal
        open={open && confirmProxy}
        title={copy.proxy.confirmTitle}
        confirmLabel={copy.proxy.confirmAction}
        busy={cleaningProxy}
        busyLabel={copy.proxy.working}
        onConfirm={handleCleanOsProxy}
        onCancel={() => setConfirmProxy(false)}
      >
        {copy.proxy.confirmText}
      </ConfirmModal>
    </>
  );
}
