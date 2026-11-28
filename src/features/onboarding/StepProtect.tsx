import { Banner, Card, Row, Rows, Switch } from "../../ui";
import { onboarding as copy } from "../../shared/copy/ru";
import { CleanRoomRadarAnim } from "../mascot";
import { StepFooter, StepFrame } from "./parts";

export interface StepProtectProps {
  sysproxyActive: boolean;
  cliProtected: boolean;
  /** Те же обработчики, что у тумблеров защиты. */
  onToggleSysproxy: () => void;
  onToggleCli: () => void;
  onNext: () => void;
  onBack: () => void;
}

/** Шаг 3: слои защиты (браузеры, редакторы/CLI, часовой пояс) и бесплатный локальный Бункер данных. */
export function StepProtect({ sysproxyActive, cliProtected, onToggleSysproxy, onToggleCli, onNext, onBack }: StepProtectProps) {
  const state =
    sysproxyActive && cliProtected
      ? copy.protect.state.both
      : sysproxyActive
        ? copy.protect.state.browsers
        : cliProtected
          ? copy.protect.state.editors
          : copy.protect.state.none;

  return (
    <StepFrame
      title={copy.protect.title}
      lead={copy.protect.lead}
      footer={<StepFooter back={onBack} primary={{ onClick: onNext, children: copy.protect.next }} />}
    >
      <CleanRoomRadarAnim
        scanning={sysproxyActive || cliProtected}
        layers={[
          { id: "browsers", label: "Браузеры", status: sysproxyActive ? "ok" : "pending" },
          { id: "editors", label: "CLI и IDE", status: cliProtected ? "ok" : "pending" },
          { id: "bunker", label: "Бункер", status: "ok" },
          { id: "os_tz", label: "Часовой пояс", status: "pending" },
        ]}
      />
      <Card>
        <Rows>
          <Row
            icon="globe"
            title={copy.protect.browsers.title}
            sub={copy.protect.browsers.sub}
            trail={<Switch checked={sysproxyActive} onChange={onToggleSysproxy} aria-label={copy.protect.browsers.title} />}
          />
          <Row
            icon="term"
            title={copy.protect.appsCliIde.title}
            sub={copy.protect.appsCliIde.sub}
            trail={<Switch checked={cliProtected} onChange={onToggleCli} aria-label={copy.protect.appsCliIde.title} />}
          />
          <Row
            icon="shield"
            title={copy.protect.timezone.title}
            sub={copy.protect.timezone.sub}
          />
          <Row icon="lock" title={copy.protect.bunker.title} sub={copy.protect.bunker.sub} />
        </Rows>
      </Card>
      <p className="zs-onb__note" aria-live="polite">
        {state}
      </p>
      <Banner tone="info" title={copy.protect.restore} />
    </StepFrame>
  );
}
