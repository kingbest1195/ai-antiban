import { useEffect, useState } from "react";
import type { AppStateData, ProviderId, RoutesSnapshot } from "../../types";
import {
  bindProviderRoute,
  clearUpstreamProxy,
  getRoutesSnapshot,
  removeRoute,
  setDefaultRoute,
  setRouteEnabled,
  testRoute,
  toggleUpstreamProxy,
  upsertRoute,
} from "../../utils/api";
import { openExternal, openZastavaBot } from "../../utils/opener";
import {
  Badge,
  Banner,
  Button,
  Card,
  Field,
  Mono,
  Row,
  Rows,
  Segmented,
  Select,
  Switch,
} from "../../ui";
import type { BadgeTone, RowTone, SegmentedOption } from "../../ui";
import { connect as copy } from "../../shared/copy/ru";
import { countryName } from "../../shared/lib/country";
import { formatRemainingTimeRu, getRouteExpiryUrgency } from "../../shared/lib/zastavaKey";
import type { ShowToast } from "../../shared/hooks";
import { HOSTINGS } from "./hostings";

export interface ConnectScreenProps {
  state: AppStateData | null;
  routesSnapshot?: RoutesSnapshot | null;
  currentIp: string;
  currentCountry: string;
  onRefreshState: () => Promise<unknown>;
  onRefreshRoutes?: () => Promise<unknown>;
  onAuditRefresh: () => Promise<void>;
  onOpenGuide: (guideId: string) => void;
  onToast: ShowToast;
}

const VPN_GUIDE = "01-personal-vpn-15min";

const PROVIDERS: { id: ProviderId; name: string }[] = [
  { id: "anthropic", name: copy.routes.services.anthropic },
  { id: "openai", name: copy.routes.services.openai },
  { id: "gemini", name: copy.routes.services.gemini },
];

type AddKeyScope = "all" | "save_only";

const ADD_SCOPE_OPTIONS: SegmentedOption<AddKeyScope>[] = [
  { value: "all", label: copy.key.scopeOptions.all },
  { value: "save_only", label: copy.key.scopeOptions.save_only },
];

/** Экран «Подключение»: личный VPN, ключ Заставы, список маршрутов и привязки по сервисам. */
export function ConnectScreen({
  state,
  routesSnapshot: propSnapshot,
  currentIp,
  currentCountry,
  onRefreshState,
  onRefreshRoutes,
  onAuditRefresh,
  onOpenGuide,
  onToast,
}: ConnectScreenProps) {
  const [localSnapshot, setLocalSnapshot] = useState<RoutesSnapshot | null>(null);
  const [inputKey, setInputKey] = useState<string>("");
  const [addScope, setAddScope] = useState<AddKeyScope>("all");
  const [error, setError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState<boolean>(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const snapshot = propSnapshot ?? localSnapshot;

  const refresh = async () => {
    try {
      if (onRefreshRoutes) {
        await onRefreshRoutes();
      } else {
        const snap = await getRoutesSnapshot();
        setLocalSnapshot(snap);
      }
    } catch {
      // Игнорируем ошибки при обновлении снимка
    }
    await onRefreshState();
    await onAuditRefresh();
  };

  useEffect(() => {
    if (!propSnapshot) {
      getRoutesSnapshot()
        .then(setLocalSnapshot)
        .catch(() => null);
    }
  }, [propSnapshot]);

  const upstream = state?.upstream_proxy ?? null;
  const routes = snapshot?.routes ?? [];
  const hasRoutes = routes.length > 0;
  const isLegacyConfigured = Boolean(upstream);
  const isLegacyActive = upstream?.enabled ?? false;

  const handleAddKey = async () => {
    const key = inputKey.trim();
    if (!key) {
      setError(copy.key.empty);
      return;
    }
    setError(null);
    setConnecting(true);
    try {
      const applyToAll = addScope === "all";
      await upsertRoute(key, null, applyToAll);
      await refresh();
      setInputKey("");
      onToast(
        copy.key.toast.connected,
        applyToAll ? copy.key.toast.connectedText : copy.key.toast.savedOnlyText,
        "success",
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      onToast(copy.key.toast.connectError, msg, "error");
    } finally {
      setConnecting(false);
    }
  };

  const handleToggleRoute = async (routeId: string, enabled: boolean) => {
    setTogglingId(routeId);
    try {
      await setRouteEnabled(routeId, enabled);
      await refresh();
      onToast(
        enabled ? copy.key.toast.on : copy.key.toast.off,
        enabled ? copy.key.toast.onText : copy.key.toast.offText,
        "info",
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      onToast(copy.key.toast.toggleError, msg, "error");
    } finally {
      setTogglingId(null);
    }
  };

  const handleTestRoute = async (routeId: string) => {
    setTestingId(routeId);
    try {
      const res = await testRoute(routeId);
      if (res.ok) {
        onToast(
          copy.key.toast.testSuccess,
          copy.key.toast.testSuccessText(res.exit_ip || "—", res.latency_ms),
          "success",
        );
      } else {
        onToast(copy.key.toast.testError, res.error || copy.key.unreachable, "error");
      }
      await refresh();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      onToast(copy.key.toast.testError, msg, "error");
    } finally {
      setTestingId(null);
    }
  };

  const handleRemoveRoute = async (routeId: string) => {
    setDeletingId(routeId);
    try {
      await removeRoute(routeId);
      if (routes.length <= 1) {
        try {
          await clearUpstreamProxy();
        } catch {
          // Игнорируем
        }
      }
      await refresh();
      onToast(copy.key.toast.disconnected, copy.key.toast.disconnectedText, "info");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      onToast(copy.key.toast.disconnectError, msg, "error");
    } finally {
      setDeletingId(null);
    }
  };

  const handleSetDefaultRoute = async (routeId: string) => {
    try {
      await setDefaultRoute(routeId);
      await refresh();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      onToast(copy.routes.toast.boundError, msg, "error");
    }
  };

  const handleBindProvider = async (provider: ProviderId, target: string) => {
    try {
      await bindProviderRoute(provider, target);
      await refresh();
      onToast(
        copy.routes.toast.boundSuccess,
        copy.routes.toast.boundSuccessText(copy.routes.services[provider]),
        "success",
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      onToast(copy.routes.toast.boundError, msg, "error");
    }
  };

  const handleResetAllDangling = async () => {
    try {
      const dangling = snapshot?.dangling || [];
      let clearedDefault = false;
      for (const item of dangling) {
        if (item.kind === "default" && !clearedDefault) {
          await setDefaultRoute(null);
          clearedDefault = true;
        } else if (item.provider) {
          await bindProviderRoute(item.provider as ProviderId, "direct");
        }
      }
      await refresh();
      onToast(copy.routes.toast.resetSuccess, copy.routes.toast.resetSuccessText, "info");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      onToast(copy.routes.toast.boundError, msg, "error");
    }
  };

  const handleLegacyToggle = async () => {
    if (!upstream) return;
    try {
      const next = !upstream.enabled;
      await toggleUpstreamProxy(next);
      await refresh();
      onToast(
        next ? copy.key.toast.on : copy.key.toast.off,
        next ? copy.key.toast.onText : copy.key.toast.offText,
        "info",
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      onToast(copy.key.toast.toggleError, msg, "error");
    }
  };

  const handleLegacyDisconnect = async () => {
    try {
      await clearUpstreamProxy();
      await refresh();
      onToast(copy.key.toast.disconnected, copy.key.toast.disconnectedText, "info");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      onToast(copy.key.toast.disconnectError, msg, "error");
    }
  };

  const exitKnown = currentIp !== "--";
  const hasDangling = Boolean(snapshot?.dangling && snapshot.dangling.length > 0);
  const hasProfileError = Boolean(snapshot?.profile_route_error);

  return (
    <>
      {hasDangling && (
        <Banner
          tone="danger"
          title={copy.routes.danglingTitle}
          action={
            <Button variant="secondary" size="sm" onClick={handleResetAllDangling}>
              {copy.routes.resetToDirect}
            </Button>
          }
        >
          {copy.routes.danglingText}
        </Banner>
      )}

      {hasProfileError && (
        <Banner tone="danger" title={copy.routes.profileErrorTitle}>
          {snapshot?.profile_route_error || copy.routes.profileErrorText}
        </Banner>
      )}

      <Card title={copy.vpn.title} aside={<Badge tone="ok">{copy.vpn.badge}</Badge>}>
        <p className="zs-t-body mb-3 text-ink-2">{copy.vpn.text}</p>
        <Rows>
          {HOSTINGS.map((h) => (
            <Row key={h.id} icon="globe" title={h.name} sub={h.sub} onClick={() => openExternal(h.url)} />
          ))}
        </Rows>
        <Button
          variant={hasRoutes || isLegacyConfigured ? "secondary" : "primary"}
          block
          className="mt-3"
          onClick={() => onOpenGuide(VPN_GUIDE)}
        >
          {copy.vpn.open}
        </Button>
      </Card>

      <Card title={copy.key.title}>
        <p className="zs-t-body mb-3 text-ink-2">{copy.key.text}</p>

        {hasRoutes ? (
          <>
            <Rows>
              {routes.map((r) => {
                const isTesting = testingId === r.id;
                const isToggling = togglingId === r.id;
                const isDeleting = deletingId === r.id;
                const expiryUrgency = getRouteExpiryUrgency(r.expires_at);
                const isExpired = r.status === "expired" || expiryUrgency === "expired";
                const showRenew = expiryUrgency !== "none" || isExpired;

                const statusTone: BadgeTone =
                  r.status === "active"
                    ? "ok"
                    : r.status === "unreachable" || isExpired
                    ? "danger"
                    : r.status === "exit_ip_mismatch"
                    ? "warn"
                    : "neutral";

                const rowTone: RowTone = statusTone;

                const statusText =
                  r.status === "active"
                    ? copy.key.switchOn
                    : isExpired
                    ? copy.key.expired
                    : r.status === "unreachable"
                    ? copy.key.unreachable
                    : r.status === "exit_ip_mismatch"
                    ? copy.key.ipMismatch
                    : copy.key.switchOff;

                const locationText = r.country ? countryName(r.country) || r.country : "";
                const latencyText = r.health?.latency_ms ? copy.key.latency(r.health.latency_ms) : "";
                const dateText = r.expires_at ? copy.key.expires(new Date(r.expires_at * 1000).toLocaleDateString()) : "";

                return (
                  <div key={r.id} className="zs-stack gap-2 py-2 border-b border-line last:border-b-0">
                    <Row
                      icon="key"
                      tone={rowTone}
                      title={
                        <span className="inline-flex items-center gap-2 flex-wrap">
                          <span>{r.label || copy.key.defaultLabel}</span>
                          {r.is_default && <Badge tone="info">{copy.key.defaultBadge}</Badge>}
                          {r.is_profile_route && <Badge tone="neutral">{copy.key.profileBadge}</Badge>}
                          <Badge tone={statusTone}>{statusText}</Badge>
                          {(expiryUrgency === "soon" || expiryUrgency === "critical") && r.expires_at && (
                            <Badge tone={expiryUrgency === "critical" ? "danger" : "warn"}>
                              {copy.key.expiringSoon(formatRemainingTimeRu(r.expires_at))}
                            </Badge>
                          )}
                        </span>
                      }
                      sub={
                        <span className="inline-flex items-center gap-2 flex-wrap">
                          {r.exit_ip && <Mono>{r.exit_ip}</Mono>}
                          {locationText && <span>· {locationText}</span>}
                          {latencyText && <span>· {latencyText}</span>}
                          {dateText && <span>· {dateText}</span>}
                        </span>
                      }
                      trail={
                        <Switch
                          checked={r.enabled}
                          disabled={isToggling}
                          onChange={() => handleToggleRoute(r.id, !r.enabled)}
                          aria-label={copy.key.switchLabel}
                        />
                      }
                    />

                    <div className="flex items-center gap-2 pl-9 flex-wrap">
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={isTesting}
                        onClick={() => handleTestRoute(r.id)}
                      >
                        {isTesting ? copy.key.testing : copy.key.test}
                      </Button>
                      {showRenew && (
                        <Button
                          size="sm"
                          variant={expiryUrgency === "critical" || isExpired ? "primary" : "secondary"}
                          onClick={() => openZastavaBot(r.id)}
                        >
                          {copy.key.renew}
                        </Button>
                      )}
                      {!r.is_default && (
                        <Button
                          size="sm"
                          variant="quiet"
                          onClick={() => handleSetDefaultRoute(r.id)}
                        >
                          {copy.key.makeDefault}
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="quiet"
                        disabled={isDeleting}
                        onClick={() => handleRemoveRoute(r.id)}
                      >
                        {copy.key.remove}
                      </Button>
                    </div>
                  </div>
                );
              })}
            </Rows>

            <div className="mt-4 pt-3 border-t border-line zs-stack gap-3">
              <div className="zs-stack gap-1">
                <span className="zs-t-label text-ink-2">{copy.key.scopeLabel}</span>
                <Segmented
                  aria-label={copy.key.scopeLabel}
                  options={ADD_SCOPE_OPTIONS}
                  value={addScope}
                  onChange={setAddScope}
                />
              </div>
              <Field
                label={copy.key.fieldLabel}
                placeholder={copy.key.placeholder}
                value={inputKey}
                onChange={(e) => {
                  setInputKey(e.target.value);
                  if (error) setError(null);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleAddKey();
                }}
                autoComplete="off"
                spellCheck={false}
                help={copy.key.caption}
                error={error ?? undefined}
                action={
                  <Button onClick={handleAddKey} disabled={connecting}>
                    {connecting ? copy.key.connecting : copy.key.connect}
                  </Button>
                }
              />
              <div>
                <Button variant="quiet" size="sm" className="-ml-3" onClick={() => openZastavaBot()}>
                  {copy.key.get}
                </Button>
              </div>
            </div>
          </>
        ) : isLegacyConfigured && upstream ? (
          <>
            <Rows>
              <Row
                icon="key"
                tone={isLegacyActive ? "ok" : "neutral"}
                title={upstream.label || copy.key.defaultLabel}
                sub={isLegacyActive ? copy.key.switchOn : copy.key.switchOff}
                trail={
                  <Switch
                    checked={isLegacyActive}
                    onChange={handleLegacyToggle}
                    aria-label={copy.key.switchLabel}
                  />
                }
              />
              <Row
                icon="globe"
                title={copy.key.exit}
                sub={
                  exitKnown ? (
                    <>
                      <Mono>{currentIp}</Mono>
                      {countryName(currentCountry) ? ` · ${countryName(currentCountry)}` : ""}
                    </>
                  ) : (
                    copy.key.exitUnknown
                  )
                }
              />
            </Rows>
            <Button variant="danger" block className="mt-3" onClick={handleLegacyDisconnect}>
              {copy.key.disconnect}
            </Button>
          </>
        ) : (
          <div className="zs-stack gap-3">
            <div className="zs-stack gap-1">
              <span className="zs-t-label text-ink-2">{copy.key.scopeLabel}</span>
              <Segmented
                aria-label={copy.key.scopeLabel}
                options={ADD_SCOPE_OPTIONS}
                value={addScope}
                onChange={setAddScope}
              />
            </div>
            <Field
              label={copy.key.fieldLabel}
              placeholder={copy.key.placeholder}
              value={inputKey}
              onChange={(e) => {
                setInputKey(e.target.value);
                if (error) setError(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleAddKey();
              }}
              autoComplete="off"
              spellCheck={false}
              help={copy.key.caption}
              error={error ?? undefined}
              action={
                <Button onClick={handleAddKey} disabled={connecting}>
                  {connecting ? copy.key.connecting : copy.key.connect}
                </Button>
              }
            />
            <div>
              <Button variant="quiet" size="sm" className="-ml-3" onClick={() => openZastavaBot()}>
                {copy.key.get}
              </Button>
            </div>
          </div>
        )}
      </Card>

      {hasRoutes && (
        <Card title={copy.routes.title}>
          <p className="zs-t-body mb-3 text-ink-2">{copy.routes.text}</p>
          <div className="zs-stack gap-3">
            {PROVIDERS.map((p) => {
              const explicitBinding = snapshot?.provider_routes[p.id];
              const isDefaultEffective = !explicitBinding && Boolean(snapshot?.default_route_id);
              const currentValue = explicitBinding || (isDefaultEffective ? "default" : "direct");

              const selectOptions = [
                { value: "direct", label: copy.routes.direct },
                ...(snapshot?.default_route_id
                  ? [{ value: "default", label: copy.routes.default }]
                  : []),
                ...routes.map((r) => {
                  const country = r.country ? `${r.country} · ` : "";
                  const ipOrHost = r.exit_ip || r.entries[0]?.host || "";
                  return {
                    value: r.id,
                    label: `${r.label || copy.key.defaultLabel} (${country}${ipOrHost})`,
                  };
                }),
              ];

              return (
                <div key={p.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2 rounded-lg bg-bg-2">
                  <span className="font-medium text-ink">{p.name}</span>
                  <div className="w-full sm:w-64">
                    <Select
                      options={selectOptions}
                      value={currentValue}
                      onChange={(e) => handleBindProvider(p.id, e.target.value)}
                      aria-label={p.name}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </>
  );
}
