import type { ProtectionActions } from "../../shared/hooks";
import { Badge, Banner, Button, Card, InfoTip, Row, Rows, Section, Switch, cx } from "../../ui";
import { CopyErrorLogButton } from "../../shared/components/CopyErrorLogButton";
import { coverage as coverageCopy, overview as copy } from "../../shared/copy/ru";

interface ProtectedSectionProps {
  startupPending: boolean;
  sysproxyActive: boolean;
  cliProtected: boolean;
  protection?: ProtectionActions;
  onToggleSysproxy: () => void;
  onToggleCli: () => void;
}

function PendingBadge() {
  return <Badge busy>{copy.service.checking}</Badge>;
}

export function ProtectedSection({
  startupPending,
  sysproxyActive,
  cliProtected,
  protection,
  onToggleSysproxy,
  onToggleCli,
}: ProtectedSectionProps) {
  return (
    <Section title={copy.sectionProtected}>
      {protection?.adminAuthMessage && (
        <Banner
          tone="warn"
          title={coverageCopy.protection.adminAuthTitle}
          action={
            <div className="zs-banner__actions">
              <Button
                size="sm"
                variant="primary"
                disabled={protection.retryingAdminAuth}
                onClick={() => void protection.enableSysproxyPrivileged()}
              >
                {protection.retryingAdminAuth
                  ? coverageCopy.protection.adminAuthBusy
                  : coverageCopy.protection.adminAuthRetry}
              </Button>
              <CopyErrorLogButton
                title={coverageCopy.protection.adminAuthTitle}
                message={protection.adminAuthMessage}
                variant="secondary"
              />
            </div>
          }
        >
          {protection.adminAuthMessage}
        </Banner>
      )}
      <Card>
        <Rows>
          <li className={cx("zs-linked-group", sysproxyActive && !startupPending && "zs-linked-group--on")}>
            <div className="zs-linked-group__head">
              <span>{copy.linkedProxy.label}</span>
              <InfoTip
                title={copy.linkedProxy.tooltipTitle}
                text={copy.linkedProxy.tooltipText}
              />
            </div>
            <ul className="zs-rows zs-linked-group__rows">
              <Row
                icon="globe"
                tone={startupPending ? "neutral" : sysproxyActive ? "ok" : "neutral"}
                title={copy.browsers.title}
                sub={copy.browsers.sub}
                trail={startupPending ? <PendingBadge /> : <Switch checked={sysproxyActive} onChange={onToggleSysproxy} aria-label={copy.browsers.title} />}
              />
              <Row
                icon="shield"
                tone={startupPending ? "neutral" : sysproxyActive ? "ok" : "neutral"}
                title={copy.desktopApps.title}
                sub={copy.desktopApps.sub}
                trail={startupPending ? <PendingBadge /> : <Switch checked={sysproxyActive} onChange={onToggleSysproxy} aria-label={copy.desktopApps.title} />}
              />
            </ul>
          </li>
          <Row
            icon="term"
            tone={startupPending ? "neutral" : cliProtected ? "ok" : "neutral"}
            title={copy.editors.title}
            sub={copy.editors.sub}
            trail={startupPending ? <PendingBadge /> : <Switch checked={cliProtected} onChange={onToggleCli} aria-label={copy.editors.title} />}
          />
        </Rows>
      </Card>
    </Section>
  );
}
