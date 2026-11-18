import type { OsTzSyncStatus } from "../../types";
import { Banner, Button } from "../../ui";
import { overview as copy } from "../../shared/copy/ru";
import type { OverviewScreenProps } from "./OverviewScreen";
import type { useOverviewModel } from "./useOverviewModel";

interface ProblemBannerProps extends OverviewScreenProps {
  kind: ReturnType<typeof useOverviewModel>["banner"];
  targetTz?: string;
  tzCode?: string;
  osTzStatus: OsTzSyncStatus | null;
  osTzLoading: boolean;
  onSyncOsTimezone: () => void;
  onRestoreOsTimezone: () => void;
}

export function ProblemBanner({
  kind,
  targetTz,
  tzCode,
  osTzStatus,
  osTzLoading,
  onSyncOsTimezone,
  onRestoreOsTimezone,
  ...props
}: ProblemBannerProps) {
  if (!kind) return null;
  const openChecks = (
    <Button size="sm" onClick={props.onOpenChecks}>
      {copy.banner.openChecks}
    </Button>
  );
  switch (kind) {
    case "frozen":
      return (
        <Banner tone="warn" title={copy.banner.frozen.title}>
          {copy.banner.frozen.text}
        </Banner>
      );
    case "stopped":
      return (
        <Banner tone="danger" role="alert" title={copy.banner.stopped.title} action={openChecks}>
          {copy.banner.stopped.text}
        </Banner>
      );
    case "leak":
      return (
        <Banner tone="danger" title={copy.banner.leak.title} action={openChecks}>
          {copy.banner.leak.text}
        </Banner>
      );
    case "timezone": {
      const cliOnly = tzCode === "TIMEZONE_SYNCED_CLI_ONLY";
      const title = cliOnly ? copy.banner.timezone.cliOnlyTitle : copy.banner.timezone.title;
      const baseText = cliOnly ? copy.banner.timezone.cliOnlyText : copy.banner.timezone.text;
      const text = osTzStatus?.synced ? `${baseText} ${copy.banner.timezone.restartHint}` : baseText;
      return (
        <Banner
          tone="warn"
          title={title}
          action={
            <div className="zs-banner__actions">
              {osTzStatus?.synced ? (
                <Button size="sm" variant="secondary" disabled={osTzLoading} onClick={onRestoreOsTimezone}>
                  {copy.banner.timezone.restoreOs}
                </Button>
              ) : (
                <Button
                  size="sm"
                  variant="primary"
                  disabled={osTzLoading || !targetTz}
                  onClick={onSyncOsTimezone}
                >
                  {osTzLoading ? copy.banner.timezone.syncingOs : copy.banner.timezone.syncOs}
                </Button>
              )}
              <Button size="sm" variant="secondary" onClick={props.onOpenTimezone}>
                {copy.banner.timezone.action}
              </Button>
            </div>
          }
        >
          {text}
        </Banner>
      );
    }
    case "review":
      return (
        <Banner tone="warn" title={copy.banner.review.title} action={openChecks}>
          {copy.banner.review.text}
        </Banner>
      );
    case "incomplete":
      return (
        <Banner
          tone="neutral"
          title={copy.banner.incomplete.title}
          action={
            <Button size="sm" onClick={props.onRetry}>
              {copy.banner.incomplete.action}
            </Button>
          }
        >
          {copy.banner.incomplete.text}
        </Banner>
      );
    case "update":
      return (
        <Banner
          tone="info"
          icon="zap"
          title={copy.banner.update.title(props.updateInfo?.latest_version ?? "")}
          action={
            <Button size="sm" onClick={props.onOpenUpdate}>
              {copy.banner.update.action}
            </Button>
          }
        >
          {copy.banner.update.text}
        </Banner>
      );
  }
}
