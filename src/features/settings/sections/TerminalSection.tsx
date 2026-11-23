import { useEffect, useState } from "react";
import type { CliMode, OsTzSyncStatus } from "../../../types";
import { Button, Row, Rows, Section, Segmented, Switch } from "../../../ui";
import type { SegmentedOption } from "../../../ui";
import { settings as copy } from "../../../shared/copy/ru";
import { getKeepSystemTzOnExit, setKeepSystemTzOnExit } from "../../../utils/api";

const CLI_MODE_OPTIONS: SegmentedOption<CliMode>[] = (
  ["ai_only", "global_terminal"] as const
).map((value) => ({
  value,
  label: copy.terminal.mode.options[value],
}));

interface TerminalSectionProps {
  cliMode: CliMode;
  syncTz: boolean;
  keepOsTzOnExit?: boolean;
  keepOsTzBusy?: boolean;
  terminalBusy: boolean;
  osTzStatus: OsTzSyncStatus | null;
  osTzLoading: boolean;
  osTzError: string | null;
  onCliModeChange: (next: CliMode) => void;
  onToggleSyncTz: () => void;
  onToggleKeepOsTzOnExit?: () => void;
  onSyncOsTimezone: () => Promise<unknown>;
  onRestoreOsTimezone: () => Promise<unknown>;
}

export function TerminalSection({
  cliMode,
  syncTz,
  keepOsTzOnExit,
  keepOsTzBusy = false,
  terminalBusy,
  osTzStatus,
  osTzLoading,
  osTzError,
  onCliModeChange,
  onToggleSyncTz,
  onToggleKeepOsTzOnExit,
  onSyncOsTimezone,
  onRestoreOsTimezone,
}: TerminalSectionProps) {
  const isControlledKeep = keepOsTzOnExit !== undefined && onToggleKeepOsTzOnExit !== undefined;
  const [localKeep, setLocalKeep] = useState(false);
  const [localKeepBusy, setLocalKeepBusy] = useState(false);

  useEffect(() => {
    if (isControlledKeep) return;
    let active = true;
    getKeepSystemTzOnExit()
      .then((val) => {
        if (active) setLocalKeep(val);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [isControlledKeep]);

  const resolvedKeep = keepOsTzOnExit !== undefined ? keepOsTzOnExit : localKeep;
  const resolvedKeepBusy = isControlledKeep ? keepOsTzBusy : localKeepBusy;

  const handleToggleKeep = () => {
    if (onToggleKeepOsTzOnExit) {
      onToggleKeepOsTzOnExit();
      return;
    }
    if (localKeepBusy) return;
    const next = !localKeep;
    setLocalKeepBusy(true);
    void setKeepSystemTzOnExit(next)
      .then((saved) => setLocalKeep(saved))
      .catch(() => {})
      .finally(() => setLocalKeepBusy(false));
  };

  return (
    <Section title={copy.terminal.section}>
      <p className="zs-settings__label">{copy.terminal.mode.title}</p>
      <Segmented
        aria-label={copy.terminal.mode.label}
        options={CLI_MODE_OPTIONS}
        value={cliMode}
        onChange={onCliModeChange}
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
              onChange={onToggleSyncTz}
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
              : osTzStatus?.already_matches_target
                ? copy.terminal.osTz.alreadyMatches(osTzStatus.current_os_tz ?? osTzStatus.target_tz ?? null)
                : copy.terminal.osTz.notSynced(osTzStatus?.current_os_tz ?? null)
          }
          trail={
            osTzStatus?.synced ? (
              <Button
                size="sm"
                variant="secondary"
                disabled={osTzLoading}
                onClick={() => void onRestoreOsTimezone()}
              >
                {osTzLoading ? copy.terminal.osTz.restoringAction : copy.terminal.osTz.restoreAction}
              </Button>
            ) : osTzStatus?.already_matches_target ? null : (
              <Button
                size="sm"
                variant="secondary"
                disabled={osTzLoading}
                onClick={() => void onSyncOsTimezone()}
              >
                {osTzLoading ? copy.terminal.osTz.syncingAction : copy.terminal.osTz.syncAction}
              </Button>
            )
          }
        />
        <Row
          icon="lock"
          title={copy.terminal.keepOsTzOnExit.title}
          sub={copy.terminal.keepOsTzOnExit.sub}
          trail={
            <Switch
              checked={resolvedKeep}
              disabled={resolvedKeepBusy}
              onChange={handleToggleKeep}
              aria-label={copy.terminal.keepOsTzOnExit.label}
            />
          }
        />
      </Rows>
      {osTzError && (
        <p className="zs-settings__hint" role="alert">
          {osTzError}
        </p>
      )}
    </Section>
  );
}
