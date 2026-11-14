import { Badge, Banner, Card, Row, Rows, Switch } from "../../ui";
import { onboarding as copy } from "../../shared/copy/ru";
import { StepFooter, StepFrame } from "./parts";

export interface StepProtectProps {
  sysproxyActive: boolean;
  cliProtected: boolean;
  /** Те же обработчики, что у тумблеров «Обзора» (useProtectionToggles). */
  onToggleSysproxy: () => void;
  onToggleCli: () => void;
  onNext: () => void;
  onBack: () => void;
}

/** Шаг 3: три слоя защиты v2.2 — браузеры (PAC + QUIC/DoH), приложения/CLI/IDE (ai_only) и часовой пояс для ИИ. */
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
            trail={<Badge tone="neutral">{copy.protect.timezone.badge}</Badge>}
          />
        </Rows>
      </Card>
      <p className="zs-onb__note" aria-live="polite">
        {state}
      </p>
      <Banner tone="info" title={copy.protect.restore} />
    </StepFrame>
  );
}
