import type { CliMode, OsTzSyncStatus } from "../../../types";
import { Button, Row, Rows, Section, Segmented, Switch } from "../../../ui";
import type { SegmentedOption } from "../../../ui";
import { settings as copy } from "../../../shared/copy/ru";

const CLI_MODE_OPTIONS: SegmentedOption<CliMode>[] = (
  ["ai_only", "global_terminal"] as const
).map((value) => ({
  value,
  label: copy.terminal.mode.options[value],
}));

interface TerminalSectionProps {
  cliMode: CliMode;
  syncTz: boolean;
  terminalBusy: boolean;
  osTzStatus: OsTzSyncStatus | null;
  osTzLoading: boolean;
  osTzError: string | null;
  onCliModeChange: (next: CliMode) => void;
  onToggleSyncTz: () => void;
  onSyncOsTimezone: () => Promise<unknown>;
  onRestoreOsTimezone: () => Promise<unknown>;
}

export function TerminalSection({
  cliMode,
  syncTz,
  terminalBusy,
  osTzStatus,
  osTzLoading,
  osTzError,
  onCliModeChange,
  onToggleSyncTz,
  onSyncOsTimezone,
  onRestoreOsTimezone,
}: TerminalSectionProps) {
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
            ) : (
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
      </Rows>
      {osTzError && (
        <p className="zs-settings__hint" role="alert">
          {osTzError}
        </p>
      )}
    </Section>
  );
}
