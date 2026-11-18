import type { ReactNode } from "react";
import { Badge, Menu } from "../../ui";
import type { MenuEntry } from "../../ui";
import { checks as checksCopy, overview as copy } from "../../shared/copy/ru";
import { resolvePinnedIp } from "../../shared/lib/format";
import type { OverviewScreenProps } from "./OverviewScreen";
import type { useOverviewModel } from "./useOverviewModel";

export function HeroFacts({
  model,
  ...props
}: { model: ReturnType<typeof useOverviewModel> } & OverviewScreenProps) {
  const allPassed = model.checksTotal > 0 && model.checksPassed === model.checksTotal;
  const activeProvider = props.activeReport?.provider;
  const pinned = resolvePinnedIp(props.state, activeProvider) != null;
  const strict = Boolean(props.state?.strict_pinning_enabled);
  const explicitProviderPin = Boolean(activeProvider && props.state?.pinned_ips?.[activeProvider]);

  const menu: MenuEntry[] = [
    { id: "copy", label: copy.ipMenu.copy, icon: "copy", onSelect: props.onCopyIp },
    ...(pinned
      ? ([
          {
            id: "strict",
            label: strict ? copy.ipMenu.strictOff : copy.ipMenu.strictOn,
            icon: "lock",
            onSelect: props.onToggleStrict,
          },
          {
            id: "unpin",
            label: copy.ipMenu.unpin,
            icon: "x",
            onSelect: () => props.onUnpinIp(explicitProviderPin ? activeProvider : undefined),
          },
        ] as MenuEntry[])
      : ([
          {
            id: "pin",
            label: copy.ipMenu.pin,
            icon: "lock",
            disabled: props.currentIp === "--",
            onSelect: () => props.onPinIp(props.currentIp, activeProvider),
          },
        ] as MenuEntry[])),
  ];

  const hasActiveRoute = Boolean(
    props.routesSnapshot &&
      (Object.values(props.routesSnapshot.effective || {}).some(Boolean) ||
        props.routesSnapshot.routes.some((r) => r.enabled && r.status === "active")),
  );

  const extra: ReactNode =
    model.pinState === "pinned" ? (
      <Badge icon="lock">{copy.facts.pinned}</Badge>
    ) : model.pinState === "changed" ? (
      <Badge tone="warn" icon="alert">
        {copy.facts.pinChanged}
      </Badge>
    ) : props.state?.upstream_proxy?.enabled || hasActiveRoute ? (
      <Badge icon="key">{copy.facts.key}</Badge>
    ) : null;

  return (
    <>
      <Badge tone={allPassed ? "ok" : "warn"} icon={allPassed ? "check" : "alert"}>
        {model.checksLabel}
      </Badge>
      {props.dataAgeMinutes != null && (
        <Badge tone={props.auditError ? "warn" : "neutral"} icon={props.auditError ? "alert" : undefined}>
          {checksCopy.dataAge(props.dataAgeMinutes, Boolean(props.auditError))}
        </Badge>
      )}
      {model.providerName && <Badge>{model.providerName}</Badge>}
      {extra}
      <Menu items={menu} label={copy.ipMenu.label} align="end" className="-my-1" />
    </>
  );
}
