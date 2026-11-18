import { openOsNetworkSettings } from "../../utils/api";
import { Banner, Button, Spinner } from "../../ui";
import { coverage as copy } from "../../shared/copy/ru";
import type { browserPacStatus, vpnNotice } from "./coverageModel";

interface CoverageVpnBannerProps {
  vpn: ReturnType<typeof vpnNotice>;
  browserPac: ReturnType<typeof browserPacStatus> | null;
  relaunchingBrowsers: boolean;
  linkingBrowsers: boolean;
  checking: boolean;
  onRelaunchBrowsers: () => void;
  onLinkBrowsers: () => void;
  onRecheck: () => void;
}

export function CoverageVpnBanner({
  vpn,
  browserPac,
  relaunchingBrowsers,
  linkingBrowsers,
  checking,
  onRelaunchBrowsers,
  onLinkBrowsers,
  onRecheck,
}: CoverageVpnBannerProps) {
  if (browserPac && browserPac.pacOverridden && browserPac.browsersNeedingRestart.length > 0) {
    return (
      <Banner
        tone="warn"
        title={copy.vpn.restartNeeded.title(browserPac.browsersNeedingRestart.join(", "))}
        className="zs-cov__vpn"
        action={
          <div className="zs-banner__actions">
            <Button
              size="sm"
              variant="primary"
              disabled={relaunchingBrowsers || linkingBrowsers || checking}
              aria-busy={relaunchingBrowsers}
              onClick={onRelaunchBrowsers}
            >
              {relaunchingBrowsers ? (
                <>
                  <Spinner /> {copy.vpn.restartNeeded.relaunchingButton}
                </>
              ) : (
                copy.vpn.restartNeeded.relaunchButton
              )}
            </Button>
            <Button size="sm" variant="secondary" disabled={checking || relaunchingBrowsers} onClick={onRecheck}>
              {checking ? copy.rechecking : copy.vpn.actions.recheck}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={linkingBrowsers || relaunchingBrowsers || checking}
              onClick={onLinkBrowsers}
            >
              {linkingBrowsers
                ? copy.vpn.actions.relinkingBrowsers
                : browserPac.pacPolicyActive
                  ? copy.vpn.actions.relinkBrowsers
                  : copy.vpn.actions.linkBrowsers}
            </Button>
            <Button size="sm" variant="quiet" onClick={() => void openOsNetworkSettings().catch(() => {})}>
              {copy.vpn.actions.osNetworkSettings}
            </Button>
          </div>
        }
      >
        {vpn
          ? copy.vpn.restartNeeded.textWithVpn(vpn.names, browserPac.browsersNeedingRestart.join(", "))
          : copy.vpn.restartNeeded.textWithoutVpn(browserPac.browsersNeedingRestart.join(", "))}
      </Banner>
    );
  }

  if (vpn?.overridden) {
    return (
      <Banner
        tone={vpn.pacPolicyActive ? "info" : "warn"}
        title={vpn.pacPolicyActive ? copy.vpn.pacLinked.title(vpn.names) : copy.vpn.overridden.title(vpn.names)}
        className="zs-cov__vpn"
        action={
          <div className="zs-banner__actions">
            <Button
              size="sm"
              variant={vpn.pacPolicyActive ? "secondary" : "primary"}
              disabled={linkingBrowsers || checking}
              onClick={onLinkBrowsers}
            >
              {linkingBrowsers
                ? copy.vpn.actions.relinkingBrowsers
                : vpn.pacPolicyActive
                  ? copy.vpn.actions.relinkBrowsers
                  : copy.vpn.actions.linkBrowsers}
            </Button>
            <Button size="sm" variant="secondary" disabled={checking} onClick={onRecheck}>
              {checking ? copy.rechecking : copy.vpn.actions.recheck}
            </Button>
            <Button size="sm" variant="quiet" onClick={() => void openOsNetworkSettings().catch(() => {})}>
              {copy.vpn.actions.osNetworkSettings}
            </Button>
          </div>
        }
      >
        {vpn.pacPolicyActive
          ? browserPac && browserPac.browsersPacActive.length > 0
            ? copy.vpn.pacLinked.textWithBrowsers(browserPac.browsersPacActive.join(", "))
            : copy.vpn.pacLinked.text
          : copy.vpn.overridden.text}
      </Banner>
    );
  }

  return null;
}
