import type { InterceptionBehavior, PopupPosition } from "../../../types";
import { Row, Rows, Section, Segmented, Switch } from "../../../ui";
import type { SegmentedOption } from "../../../ui";
import { settings as copy } from "../../../shared/copy/ru";

const BEHAVIOR_OPTIONS: SegmentedOption<InterceptionBehavior>[] = (
  ["ask_popup", "auto_lock_silent", "auto_allow_trusted"] as const
).map((value) => ({ value, label: copy.behavior.options[value] }));

const POSITION_OPTIONS: SegmentedOption<PopupPosition>[] = (
  ["top_right", "top_center"] as const
).map((value) => ({ value, label: copy.position.options[value] }));

interface BehaviorSectionProps {
  behavior: InterceptionBehavior;
  position: PopupPosition;
  splitTunnelMode: boolean;
  splitTunnelBusy: boolean;
  onBehaviorChange: (next: InterceptionBehavior) => void;
  onPositionChange: (next: PopupPosition) => void;
  onToggleSplitTunnel: () => void;
}

export function BehaviorSection({
  behavior,
  position,
  splitTunnelMode,
  splitTunnelBusy,
  onBehaviorChange,
  onPositionChange,
  onToggleSplitTunnel,
}: BehaviorSectionProps) {
  return (
    <>
      <Section title={copy.behavior.section}>
        <p className="zs-t-body zs-settings__lead">{copy.behavior.text}</p>
        <Segmented
          aria-label={copy.behavior.label}
          options={BEHAVIOR_OPTIONS}
          value={behavior}
          onChange={onBehaviorChange}
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
              onChange={onPositionChange}
            />
          </>
        )}
      </Section>

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
                onChange={onToggleSplitTunnel}
                aria-label={copy.splitTunnel.label}
              />
            }
          />
        </Rows>
      </Section>
    </>
  );
}
