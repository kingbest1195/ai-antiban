import { Button, InfoTip } from "../../ui";
import { overview as copy } from "../../shared/copy/ru";
import type { OverviewScreenProps } from "../overview/OverviewScreen";

/** Аварийная кнопка «Остановить сеть для ИИ / Возобновить» внизу Home Hub. */
export function StopNetwork({ p }: { p: OverviewScreenProps }) {
  const frozen = p.killswitchFrozen;
  return (
    <div className="zs-v3-stop">
      <Button
        variant={frozen ? "primary" : "danger"}
        icon={frozen ? "refresh" : "power"}
        onClick={p.onToggleKillswitch}
      >
        {frozen ? copy.actions.resumeNetwork : copy.actions.stopNetwork}
      </Button>
      <InfoTip
        title={frozen ? copy.actions.resumeTooltipTitle : copy.actions.stopTooltipTitle}
        text={frozen ? copy.actions.resumeTooltipText : copy.actions.stopTooltipText}
      />
    </div>
  );
}
