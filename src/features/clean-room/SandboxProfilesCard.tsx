import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import type { CleanProfileStatus, CleanRoomProfile, CleanRoomState, DetectedBrowser, RouteView } from "../../types";
import { createCleanProfile, deleteCleanProfile, discoverCleanBrowsers, launchCleanBrowser, markCleanProfileTainted } from "../../utils/api";
import { openExternal } from "../../utils/opener";
import { Badge, Banner, Button, Card, ConfirmModal, EmptyState, Field, InfoTip, Mono, Select } from "../../ui";
import type { BadgeTone } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";
import { formatRouteOptionLabel } from "../../shared/lib/country";

export interface SandboxProfilesCardProps {
  profiles: readonly CleanRoomProfile[];
  activeProfileId: string | null;
  routes?: readonly RouteView[];
  readyToLaunch: boolean;
  manualKillswitch?: boolean;
  /** Предзагруженный список браузеров (для тестов и SSR). */
  initialBrowsers?: DetectedBrowser[];
  onSelectProfile: (profileId: string) => void;
  onProfilesChanged?: (nextState?: CleanRoomState) => Promise<unknown> | void;
  onProfileLaunched?: (profile: CleanRoomProfile) => void;
  openCreateTrigger?: number;
  toast?: ShowToast;
}

const DIRECT_VALUE = "__direct__";
const STATUS_TONE: Record<CleanProfileStatus, BadgeTone> = {
  active: "info",
  warming_up: "warn",
  ready: "ok",
  tainted: "danger",
};

/** Возвращает причину блокировки запуска песочницы или null, если запуск разрешён. */
export function resolveSandboxBlockReason(
  profile: Pick<CleanRoomProfile, "status">,
  readyToLaunch: boolean,
  manualKillswitch: boolean,
): string | null {
  if (manualKillswitch) return copy.sandbox.profileCard.blockedReasonKillswitch;
  if (profile.status === "tainted") return copy.sandbox.profileCard.blockedReasonTainted;
  if (!readyToLaunch) return copy.sandbox.profileCard.blockedReasonAudit;
  return null;
}

function providerLabel(provider: string): string {
  const key = provider.toLowerCase();
  if (key === "anthropic" || key === "claude") return copy.sandbox.providers.anthropic;
  if (key === "openai" || key === "chatgpt") return copy.sandbox.providers.openai;
  if (key === "gemini") return copy.sandbox.providers.gemini;
  return copy.sandbox.providers.custom;
}

function resolveBoundRouteLabel(boundRouteId: string | null, routes: readonly RouteView[]): string {
  if (!boundRouteId) return copy.sandbox.profileCard.routeDirect;
  const found = routes.find((r) => r.id === boundRouteId);
  if (!found) return copy.sandbox.profileCard.routeMissing;
  return formatRouteOptionLabel({
    label: found.label,
    country: found.country,
    ipOrHost: found.exit_ip,
    fallbackLabel: found.id,
  });
}

/** Карточка «Браузерная песочница (для веба)»: обнаружение Chromium, создание и запуск изолированных профилей. */
export function SandboxProfilesCard({
  profiles,
  activeProfileId,
  routes = [],
  readyToLaunch,
  manualKillswitch = false,
  initialBrowsers,
  onSelectProfile,
  onProfilesChanged,
  onProfileLaunched,
  openCreateTrigger = 0,
  toast,
}: SandboxProfilesCardProps) {
  const [browsers, setBrowsers] = useState<DetectedBrowser[]>(initialBrowsers ?? []);
  const [browsersLoaded, setBrowsersLoaded] = useState<boolean>(initialBrowsers !== undefined);
  const [showCreate, setShowCreate] = useState<boolean>(false);
  const [label, setLabel] = useState<string>("");
  const [provider, setProvider] = useState<string>("anthropic");
  const [engine, setEngine] = useState<string>(initialBrowsers?.find((b) => b.available)?.engine ?? "chrome");
  const [routeChoice, setRouteChoice] = useState<string>(routes[0]?.id ?? DIRECT_VALUE);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<CleanRoomProfile | null>(null);

  const loadBrowsers = useCallback(async () => {
    try {
      const list = await discoverCleanBrowsers();
      setBrowsers(list);
      const firstAvail = list.find((b) => b.available);
      if (firstAvail) {
        setEngine((prev) => (list.some((b) => b.engine === prev && b.available) ? prev : firstAvail.engine));
      }
    } finally {
      setBrowsersLoaded(true);
    }
  }, []);

  useEffect(() => {
    if (initialBrowsers === undefined) void loadBrowsers();
  }, [initialBrowsers, loadBrowsers]);

  useEffect(() => {
    if (openCreateTrigger > 0) setShowCreate(true);
  }, [openCreateTrigger]);

  useEffect(() => {
    if (routeChoice === DIRECT_VALUE && routes.length > 0) setRouteChoice(routes[0].id);
  }, [routes, routeChoice]);

  const availableBrowsers = browsers.filter((b) => b.available);
  const noBrowsers = browsersLoaded && availableBrowsers.length === 0;

  const runAction = async (key: string, fn: () => Promise<void>) => {
    if (busyId) return;
    setBusyId(key);
    try {
      await fn();
    } catch (err) {
      toast?.(copy.sandbox.toast.error, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setBusyId(null);
    }
  };

  const handleCreate = (e: FormEvent) => {
    e.preventDefault();
    void runAction("__create__", async () => {
      const created = await createCleanProfile({
        label: label.trim() || providerLabel(provider),
        provider,
        browser_engine: engine,
        bound_route_id: routeChoice === DIRECT_VALUE ? null : routeChoice,
      });
      setLabel("");
      setShowCreate(false);
      onSelectProfile(created.id);
      toast?.(copy.sandbox.toast.created, created.label, "success");
      await onProfilesChanged?.();
    });
  };

  const handleDeleteConfirm = () => {
    if (!confirmDelete) return;
    const target = confirmDelete;
    void runAction("__delete__", async () => {
      const nextState = await deleteCleanProfile(target.id);
      toast?.(copy.sandbox.toast.deleted, target.label, "info");
      setConfirmDelete(null);
      await onProfilesChanged?.(nextState);
    });
  };

  return (
    <Card
      title={
        <span className="cr-row-inline">
          <span>{copy.sandbox.title}</span>
          <InfoTip title={copy.sandbox.tipTitle} text={copy.sandbox.tipText} />
        </span>
      }
      aside={
        !noBrowsers ? (
          <Button size="sm" variant={showCreate ? "quiet" : "secondary"} onClick={() => setShowCreate((v) => !v)}>
            {showCreate ? copy.sandbox.cancelBtn : copy.sandbox.createBtn}
          </Button>
        ) : undefined
      }
    >
      <p className="zs-t-caption cr-lead">{copy.sandbox.subtitle}</p>

      {noBrowsers ? (
        <EmptyState
          mascotState="sleep"
          mascotSize={64}
          title={copy.sandbox.noBrowsers.title}
          description={copy.sandbox.noBrowsers.text}
          primaryAction={
            <div className="cr-row-inline">
              {copy.sandbox.noBrowsers.downloads.map((d) => (
                <Button key={d.id} size="sm" icon="download" onClick={() => void openExternal(d.url)}>{d.label}</Button>
              ))}
            </div>
          }
          secondaryAction={
            <Button size="sm" variant="quiet" icon="refresh" onClick={() => void loadBrowsers()}>{copy.sandbox.noBrowsers.refresh}</Button>
          }
        />
      ) : (
        <>
          {showCreate && (
            <form className="cr-form" onSubmit={handleCreate}>
              <p className="cr-form__title">{copy.sandbox.form.title}</p>
              <Field label={copy.sandbox.form.labelField} value={label} onChange={(e) => setLabel(e.target.value)} placeholder={copy.sandbox.form.labelPlaceholder} />
              <Select
                label={copy.sandbox.form.providerField}
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                options={[
                  { value: "anthropic", label: copy.sandbox.providers.anthropic },
                  { value: "openai", label: copy.sandbox.providers.openai },
                  { value: "gemini", label: copy.sandbox.providers.gemini },
                  { value: "custom", label: copy.sandbox.providers.custom },
                ]}
              />
              <Select
                label={copy.sandbox.form.browserField}
                value={engine}
                onChange={(e) => setEngine(e.target.value)}
                options={(availableBrowsers.length > 0 ? availableBrowsers : browsers).map((b) => ({
                  value: b.engine,
                  label: b.available ? b.display_name : `${b.display_name} (не найден)`,
                  disabled: !b.available,
                }))}
              />
              <Select
                label={copy.sandbox.form.routeField}
                value={routeChoice}
                onChange={(e) => setRouteChoice(e.target.value)}
                help={
                  <span className="cr-row-inline">
                    <InfoTip title={copy.sandbox.form.routeTipTitle} text={copy.sandbox.form.routeTipText} />
                    <span>{routeChoice === DIRECT_VALUE ? copy.sandbox.form.directWarning : ""}</span>
                  </span>
                }
                options={[
                  ...routes.map((r) => ({ value: r.id, label: formatRouteOptionLabel({ label: r.label, country: r.country, ipOrHost: r.exit_ip }) })),
                  { value: DIRECT_VALUE, label: copy.sandbox.form.directOption },
                ]}
              />
              {routeChoice === DIRECT_VALUE && <Banner tone="warn" title={copy.sandbox.profileCard.routeDirect}>{copy.sandbox.form.directWarning}</Banner>}
              <Button type="submit" variant="primary" disabled={busyId === "__create__"}>
                {busyId === "__create__" ? copy.sandbox.form.creating : copy.sandbox.form.submit}
              </Button>
            </form>
          )}

          {profiles.length === 0 ? (
            <EmptyState
              icon="globe"
              title={copy.sandbox.emptyProfiles.title}
              description={copy.sandbox.emptyProfiles.text}
              primaryAction={<Button variant="primary" onClick={() => setShowCreate(true)}>{copy.sandbox.emptyProfiles.cta}</Button>}
            />
          ) : (
            <ul className="cr-profile-list">
              {profiles.map((profile) => {
                const isActive = profile.id === activeProfileId;
                const blockReason = resolveSandboxBlockReason(profile, readyToLaunch, manualKillswitch);
                const canLaunch = blockReason === null;
                const ipMeta = profile.last_exit_ip
                  ? `${profile.last_exit_ip}${profile.last_exit_country ? ` (${profile.last_exit_country})` : ""}`
                  : copy.sandbox.profileCard.neverOpened;
                return (
                  <li
                    key={profile.id}
                    className={`cr-profile-card ${isActive ? "cr-profile-card--active" : ""} ${profile.status === "tainted" ? "cr-profile-card--tainted" : ""}`.trim()}
                  >
                    <div className="cr-row-between">
                      <p className="cr-profile-card__title">{profile.label}</p>
                      <Badge tone={STATUS_TONE[profile.status]} icon={profile.status === "tainted" ? "alert" : profile.status === "ready" ? "check" : undefined}>
                        {copy.sandbox.status[profile.status]}
                      </Badge>
                    </div>
                    <div className="cr-profile-card__meta">
                      <span>{providerLabel(profile.provider)}</span>
                      <span>·</span>
                      <Mono>{profile.browser_engine}</Mono>
                      <span>·</span>
                      <span>{resolveBoundRouteLabel(profile.bound_route_id, routes)}</span>
                    </div>
                    <div className="cr-profile-card__meta">
                      <span>{copy.sandbox.profileCard.lastIp}</span>
                      <Mono>{ipMeta}</Mono>
                    </div>
                    {blockReason && <p className="cr-blocked-reason">{blockReason}</p>}
                    <div className="cr-row-inline">
                      <Button
                        size="sm"
                        variant="primary"
                        icon="shield"
                        disabled={!canLaunch || busyId === profile.id}
                        aria-disabled={!canLaunch ? "true" : undefined}
                        title={blockReason ?? undefined}
                        onClick={() =>
                          void runAction(profile.id, async () => {
                            const res = await launchCleanBrowser(profile.id);
                            toast?.(copy.sandbox.toast.launched, copy.sandbox.toast.launchedText(res.browser_engine, res.alias_port), "success");
                            onProfileLaunched?.(profile);
                            await onProfilesChanged?.();
                          })
                        }
                      >
                        {busyId === profile.id ? copy.sandbox.profileCard.launching : copy.sandbox.profileCard.launchBtn}
                      </Button>
                      {!isActive && (
                        <Button size="sm" variant="secondary" onClick={() => onSelectProfile(profile.id)}>
                          {copy.sandbox.profileCard.select}
                        </Button>
                      )}
                      {profile.status !== "tainted" && (
                        <Button
                          size="sm"
                          variant="danger"
                          disabled={busyId === profile.id}
                          onClick={() =>
                            void runAction(profile.id, async () => {
                              await markCleanProfileTainted(profile.id, "marked_by_user");
                              toast?.(copy.sandbox.toast.tainted, copy.sandbox.toast.taintedText, "warning");
                              await onProfilesChanged?.();
                            })
                          }
                        >
                          {copy.sandbox.profileCard.taintBtn}
                        </Button>
                      )}
                      <Button size="sm" variant="quiet" onClick={() => setConfirmDelete(profile)}>
                        {copy.sandbox.profileCard.deleteBtn}
                      </Button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </>
      )}

      <ConfirmModal
        open={confirmDelete !== null}
        title={copy.sandbox.profileCard.deleteTitle}
        confirmLabel={copy.sandbox.profileCard.deleteConfirm}
        busy={busyId === "__delete__"}
        onConfirm={handleDeleteConfirm}
        onCancel={() => setConfirmDelete(null)}
      >
        {confirmDelete ? copy.sandbox.profileCard.deleteText(confirmDelete.label) : ""}
      </ConfirmModal>
    </Card>
  );
}
