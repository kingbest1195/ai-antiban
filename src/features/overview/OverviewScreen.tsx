import type { ReactNode } from "react";
import type { AppStateData, CoverageSnapshot, GatewayStatsSnapshot, ProviderId, RiskReport, UpdateCheckResult } from "../../types";
import {
  Badge,
  Banner,
  Button,
  Card,
  EmptyState,
  Menu,
  Row,
  Rows,
  Section,
  Skeleton,
  Stat,
  Stats,
  StatusHero,
  Switch,
} from "../../ui";
import type { IconName, MenuEntry } from "../../ui";
import { overview as copy, providers as providerCopy, status as words } from "../../shared/copy/ru";
import { countryName } from "../../shared/lib/country";
import { formatNumber } from "../../shared/lib/format";
import { useOverviewModel } from "./useOverviewModel";
import type { ServiceModel } from "./useOverviewModel";

export interface OverviewScreenProps {
  reports: Partial<Record<ProviderId, RiskReport>>;
  activeReport: RiskReport | null;
  state: AppStateData | null;
  refreshing: boolean;
  auditError: string | null;
  currentIp: string;
  trustScore: number;
  gatewayStats: GatewayStatsSnapshot | null;
  updateInfo: UpdateCheckResult | null;
  coverageSnapshot?: CoverageSnapshot | null;

  sysproxyActive: boolean;
  cliProtected: boolean;
  killswitchFrozen: boolean;
  onToggleSysproxy: () => void;
  onToggleCli: () => void;
  onToggleKillswitch: () => void;

  onCopyIp: () => void;
  onPinIp: (ip: string) => void;
  onUnpinIp: () => void;
  onToggleStrict: () => void;
  onAllowProvider: (provider: ProviderId) => void;
  onUnblockProvider: (provider: ProviderId) => void;

  onRetry: () => void;
  onOpenChecks: () => void;
  onOpenTimezone: () => void;
  onOpenUpdate: () => void;
  onOpenCrashTest: () => void;
}

/** Экран «Обзор»: вердикт, сервисы ИИ, что под защитой, цифры за день, два действия. */
export function OverviewScreen(props: OverviewScreenProps) {
  const {
    reports,
    activeReport,
    state,
    refreshing,
    auditError,
    currentIp,
    trustScore,
    gatewayStats,
    updateInfo,
    coverageSnapshot,
    sysproxyActive,
    cliProtected,
    killswitchFrozen,
  } = props;

  const model = useOverviewModel({
    reports,
    activeReport,
    state,
    currentIp,
    sysproxyActive,
    killswitchFrozen,
    updateInfo,
    refreshing,
  });

  const loading = !activeReport && !auditError;
  const failed = !activeReport && Boolean(auditError);

  return (
    <>
      {!loading && !failed && <ProblemBanner kind={model.banner} {...props} />}

      {loading ? (
        <HeroSkeleton />
      ) : failed ? (
        <Card>
          <EmptyState
            icon="alert"
            title={copy.error.title}
            action={
              <Button variant="primary" icon="refresh" onClick={props.onRetry} disabled={refreshing}>
                {copy.error.action}
              </Button>
            }
          >
            {copy.error.text}
          </EmptyState>
        </Card>
      ) : (
        <StatusHero
          score={trustScore}
          tone={model.tone}
          title={model.verdict}
          ip={currentIp !== "--" ? currentIp : undefined}
          country={currentIp !== "--" ? countryName(activeReport?.telemetry.country_code) || undefined : undefined}
          facts={<HeroFacts model={model} {...props} />}
        >
          <Row
            as="div"
            className="zs-hero__switch"
            title={copy.guard.title}
            sub={sysproxyActive ? copy.guard.onText : copy.guard.offText}
            trail={<Switch checked={sysproxyActive} onChange={props.onToggleSysproxy} aria-label={copy.guard.label} />}
          />
        </StatusHero>
      )}

      {!failed && (
        <Section title={copy.sectionServices}>
          <Card>
            {loading ? (
              <ServicesSkeleton />
            ) : (
              <Rows>
                {model.services.map((service) => (
                  <ServiceRow
                    key={service.id}
                    service={service}
                    onAllow={props.onAllowProvider}
                    onUnblock={props.onUnblockProvider}
                    blockedByUser={Boolean(state?.blocked_providers?.includes(service.id))}
                  />
                ))}
              </Rows>
            )}
          </Card>
        </Section>
      )}

      <Section title={copy.sectionProtected}>
        <Card>
          <Rows>
            <Row
              icon="globe"
              title={copy.browsers.title}
              sub={copy.browsers.sub}
              trail={<Switch checked={sysproxyActive} onChange={props.onToggleSysproxy} aria-label={copy.browsers.title} />}
            />
            <Row
              icon="shield"
              title={copy.desktopApps.title}
              sub={copy.desktopApps.sub}
              trail={<Switch checked={sysproxyActive} onChange={props.onToggleSysproxy} aria-label={copy.desktopApps.title} />}
            />
            <Row
              icon="term"
              title={copy.editors.title}
              sub={copy.editors.sub}
              trail={<Switch checked={cliProtected} onChange={props.onToggleCli} aria-label={copy.editors.title} />}
            />
          </Rows>
        </Card>
      </Section>

      {coverageSnapshot && (
        <Section title="Покрытие приложений">
          <Card>
            <Rows>
              {coverageSnapshot.chained_proxy && (
                <Row
                  icon="pulse"
                  title={`Цепочка PAC: не-ИИ трафик идёт через ${coverageSnapshot.chained_proxy}`}
                  sub="Маршрутизация обычного веб-трафика через внешний прокси"
                  trail={<Badge tone="info">Внешний прокси</Badge>}
                />
              )}
              {coverageSnapshot.apps
                .filter((item) => item.installed || item.requests_seen > 0)
                .map((item) => {
                  const icon: IconName =
                    item.category === "browser"
                      ? "globe"
                      : item.category === "desktop"
                      ? "shield"
                      : "term";

                  return (
                    <Row
                      key={item.id}
                      icon={icon}
                      title={item.name}
                      sub={item.detail}
                      trail={
                        item.status === "verified" ? (
                          <Badge tone="ok" icon="check">
                            Проверено ({item.requests_seen})
                          </Badge>
                        ) : item.status === "configured" ? (
                          <Badge tone="ok">Настроено</Badge>
                        ) : (
                          <Badge tone="warn">Не настроено</Badge>
                        )
                      }
                    />
                  );
                })}
            </Rows>
          </Card>
        </Section>
      )}

      <Section title={copy.sectionToday}>
        <Stats>
          <Stat layer={1} value={formatNumber(gatewayStats?.protected_ai_requests ?? 0)} label={copy.stats.requests} />
          <Stat
            layer={1}
            tone={(gatewayStats?.intercepted_leaks ?? 0) > 0 ? "danger" : "neutral"}
            value={formatNumber(gatewayStats?.intercepted_leaks ?? 0)}
            label={copy.stats.leaks}
          />
          <Stat layer={1} value={formatNumber(gatewayStats?.direct_bypassed_requests ?? 0)} label={copy.stats.direct} />
        </Stats>
      </Section>

      <div className="zs-app__actions">
        <Button icon="pulse" onClick={props.onOpenCrashTest}>
          {copy.actions.crashTest}
        </Button>
        {killswitchFrozen ? (
          <Button variant="primary" icon="refresh" onClick={props.onToggleKillswitch}>
            {copy.actions.resumeNetwork}
          </Button>
        ) : (
          <Button variant="danger" icon="power" onClick={props.onToggleKillswitch}>
            {copy.actions.stopNetwork}
          </Button>
        )}
      </div>
    </>
  );
}

/* ---------- Баннер: один на экран, одно действие ---------- */

function ProblemBanner({ kind, ...props }: { kind: ReturnType<typeof useOverviewModel>["banner"] } & OverviewScreenProps) {
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
    case "timezone":
      return (
        <Banner
          tone="warn"
          title={copy.banner.timezone.title}
          action={
            <Button size="sm" onClick={props.onOpenTimezone}>
              {copy.banner.timezone.action}
            </Button>
          }
        >
          {copy.banner.timezone.text}
        </Banner>
      );
    case "review":
      return (
        <Banner tone="warn" title={copy.banner.review.title} action={openChecks}>
          {copy.banner.review.text}
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

/* ---------- Бейджи под вердиктом ---------- */

function HeroFacts({ model, ...props }: { model: ReturnType<typeof useOverviewModel> } & OverviewScreenProps) {
  const allPassed = model.checksTotal > 0 && model.checksPassed === model.checksTotal;
  const pinned = props.state?.pinned_ip != null;
  const strict = Boolean(props.state?.strict_pinning_enabled);

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
          { id: "unpin", label: copy.ipMenu.unpin, icon: "x", onSelect: props.onUnpinIp },
        ] as MenuEntry[])
      : ([
          {
            id: "pin",
            label: copy.ipMenu.pin,
            icon: "lock",
            disabled: props.currentIp === "--",
            onSelect: () => props.onPinIp(props.currentIp),
          },
        ] as MenuEntry[])),
  ];

  const extra: ReactNode =
    model.pinState === "pinned" ? (
      <Badge icon="lock">{copy.facts.pinned}</Badge>
    ) : model.pinState === "changed" ? (
      <Badge tone="warn" icon="alert">
        {copy.facts.pinChanged}
      </Badge>
    ) : props.state?.upstream_proxy?.enabled ? (
      <Badge icon="key">{copy.facts.key}</Badge>
    ) : null;

  return (
    <>
      <Badge tone={allPassed ? "ok" : "warn"} icon={allPassed ? "check" : "alert"}>
        {model.checksLabel}
      </Badge>
      {model.providerName && <Badge>{model.providerName}</Badge>}
      {extra}
      <Menu items={menu} label={copy.ipMenu.label} align="end" className="-my-1" />
    </>
  );
}

/* ---------- Строка сервиса ---------- */

function ServiceRow({
  service,
  blockedByUser,
  onAllow,
  onUnblock,
}: {
  service: ServiceModel;
  blockedByUser: boolean;
  onAllow: (provider: ProviderId) => void;
  onUnblock: (provider: ProviderId) => void;
}) {
  const meta = providerCopy[service.id];
  const { status } = service;

  let badge: ReactNode;
  let note: string | null = null;
  let actionLabel: string | null = null;
  let tone: "neutral" | "ok" | "warn" | "danger" = "ok";

  switch (status) {
    case "ok":
      badge = <Badge tone="ok">{words.available}</Badge>;
      break;
    case "allowed":
      badge = <Badge tone="ok">{words.available}</Badge>;
      note = copy.service.session;
      break;
    case "warn":
      badge = (
        <Badge tone="warn" icon="alert">
          {words.review}
        </Badge>
      );
      note = copy.service.review;
      actionLabel = copy.service.allow;
      tone = "warn";
      break;
    case "critical":
      badge = (
        <Badge tone="danger" icon="alert">
          {words.blocked}
        </Badge>
      );
      note = copy.service.blocked;
      actionLabel = copy.service.unblock;
      tone = "danger";
      break;
    case "checking":
      badge = <Badge>{copy.service.checking}</Badge>;
      tone = "neutral";
      break;
    case "missing":
      badge = (
        <Badge tone="warn" icon="alert">
          {words.review}
        </Badge>
      );
      note = copy.service.missing;
      tone = "warn";
      break;
  }

  const handleAction = () => {
    // Как раньше: снятие блока — сначала unblock (если блок поставлен вручную), затем разрешение на сессию.
    if (blockedByUser) onUnblock(service.id);
    onAllow(service.id);
  };

  return (
    <Row
      icon={status === "ok" || status === "allowed" || status === "checking" ? "shield" : "alert"}
      tone={tone}
      title={meta.name}
      sub={
        <>
          <span className="block">{meta.domains}</span>
          {note && <span className="block">{note}</span>}
          {actionLabel && (
            <Button variant="quiet" size="sm" className="-ml-3" onClick={handleAction}>
              {actionLabel}
            </Button>
          )}
        </>
      }
      trail={badge}
    />
  );
}

/* ---------- Загрузка ---------- */

function HeroSkeleton() {
  return (
    <Card aria-label="Загрузка">
      <div className="zs-hero">
        <Skeleton variant="circle" width={64} />
        <div className="zs-hero__body">
          <Skeleton width="70%" height={22} />
          <Skeleton width="50%" className="mt-2" />
        </div>
      </div>
      <Skeleton variant="block" height={24} className="mt-3" />
      <Skeleton variant="block" height={40} className="mt-4" />
    </Card>
  );
}

function ServicesSkeleton() {
  return (
    <Rows>
      {[0, 1, 2].map((i) => (
        <li key={i} className="zs-row">
          <Skeleton variant="circle" width={32} />
          <div className="zs-row__body">
            <Skeleton width="40%" />
            <Skeleton width="70%" className="mt-1" />
          </div>
          <Skeleton width={72} height={24} />
        </li>
      ))}
    </Rows>
  );
}
