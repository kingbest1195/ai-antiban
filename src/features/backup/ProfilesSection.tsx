import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import type { ClaudeProfile, RouteView, RoutesSnapshot } from "../../types";
import {
  bindIpToClaudeProfile,
  bindRouteToClaudeProfile,
  bindUpstreamToClaudeProfile,
  createClaudeProfile,
  deleteClaudeProfile,
  getRoutesSnapshot,
  listClaudeProfiles,
  safeLogoutClaude,
  switchClaudeProfile,
} from "../../utils/api";
import { Badge, Button, Card, EmptyState, Menu, Mono, Row, Rows, Section, Skeleton } from "../../ui";
import type { MenuEntry } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { backup as copy } from "../../shared/copy/ru";
import { countryName } from "../../shared/lib/country";
import { formatIp } from "../../shared/lib/format";
import {
  KEY_OPTION_NEW,
  KEY_OPTION_NONE,
  formatCooldownDuration,
  hasProfileKeyBinding,
  isProfileRouteMissing,
  resolveBoundBadge,
  resolveCreateProfileIpBinding,
  resolveInitialBindChoice,
} from "./profileModel";
import { ProfileModals } from "./ProfileModals";
import { QuarantineOverrideModal } from "../subscription/QuarantineOverrideModal";
import { useQuarantineGuard } from "../subscription/useQuarantineGuard";

export {
  KEY_OPTION_NEW,
  KEY_OPTION_NONE,
  hasProfileKeyBinding,
  isProfileRouteMissing,
  resolveCreateProfileIpBinding,
  resolveInitialBindChoice,
};

export interface ProfilesSectionProps {
  currentIp: string;
  currentCountry: string;
  hideIpMode?: boolean;
  activeUpstreamKey?: string | null;
  routesSnapshot?: RoutesSnapshot | null;
  refreshTrigger?: number;
  onRoutesUpdated?: () => Promise<unknown> | void;
  onProfileSwitched: (profileName: string, pinnedIp?: string | null) => Promise<unknown> | void;
  onToast: ShowToast;
}

/** Профили Claude: строка на профиль, переключение, привязка IP и ключа, удаление с подтверждением, создание. */
export function ProfilesSection({
  currentIp,
  currentCountry,
  hideIpMode = false,
  routesSnapshot: propRoutesSnapshot,
  refreshTrigger = 0,
  onRoutesUpdated,
  onProfileSwitched,
  onToast,
}: ProfilesSectionProps) {
  const [profiles, setProfiles] = useState<ClaudeProfile[]>([]);
  const [activeProfileId, setActiveProfileId] = useState<string>("default");
  const [routes, setRoutes] = useState<RouteView[]>(propRoutesSnapshot?.routes ?? []);
  const [routesLoaded, setRoutesLoaded] = useState<boolean>(Boolean(propRoutesSnapshot?.routes));
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [switchingId, setSwitchingId] = useState<string | null>(null);
  const [bindingId, setBindingId] = useState<string | null>(null);
  const [bindingProxyId, setBindingProxyId] = useState<string | null>(null);
  const [removing, setRemoving] = useState<ClaudeProfile | null>(null);
  const [removeBusy, setRemoveBusy] = useState(false);
  const [safeLogoutOpen, setSafeLogoutOpen] = useState(false);
  const [safeLogoutBusy, setSafeLogoutBusy] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [bindCurrentOnCreate, setBindCurrentOnCreate] = useState(true);
  const [createKeyChoice, setCreateKeyChoice] = useState<string>(KEY_OPTION_NONE);
  const [createKeyInput, setCreateKeyInput] = useState("");
  const [creating, setCreating] = useState(false);
  const [bindingTarget, setBindingTarget] = useState<ClaudeProfile | null>(null);
  const [bindChoice, setBindChoice] = useState<string>(KEY_OPTION_NONE);
  const [bindKeyInput, setBindKeyInput] = useState("");
  const [savingBind, setSavingBind] = useState(false);
  const quarantine = useQuarantineGuard();
  const t = copy.profiles;
  const t_toast = copy.toast;
  const ipKnown = Boolean(currentIp) && currentIp !== "--";

  const refreshRoutes = async (): Promise<RouteView[] | null> => {
    try {
      const snap = await getRoutesSnapshot();
      const next = snap.routes ?? [];
      setRoutes(next);
      setRoutesLoaded(true);
      return next;
    } catch {
      return null;
    }
  };

  const fetchProfiles = async () => {
    setLoading(true);
    try {
      const res = await listClaudeProfiles();
      setProfiles(res.profiles || []);
      setActiveProfileId(res.active_profile_id || "default");
    } catch (err) {
      console.error("Failed to list Claude profiles:", err);
    } finally {
      setLoading(false);
      setLoaded(true);
    }
  };

  useEffect(() => {
    fetchProfiles();
    refreshRoutes();
  }, [refreshTrigger]);

  useEffect(() => {
    if (propRoutesSnapshot?.routes) {
      setRoutes(propRoutesSnapshot.routes);
      setRoutesLoaded(true);
    }
  }, [propRoutesSnapshot]);

  const errText = (err: unknown) => (err instanceof Error ? err.message : String(err));

  const handleSafeLogout = async () => {
    if (safeLogoutBusy) return;
    setSafeLogoutBusy(true);
    try {
      const res = await safeLogoutClaude();
      setSafeLogoutOpen(false);
      await onProfileSwitched("", null);
      onToast(
        t_toast.safeLogoutDone,
        t_toast.safeLogoutDoneText(res.closed_processes, formatCooldownDuration(res.cooldown_secs)),
        "success",
      );
    } catch (err) {
      onToast(t_toast.safeLogoutError, errText(err), "error");
    } finally {
      setSafeLogoutBusy(false);
    }
  };

  const handleSwitch = async (profileId: string) => {
    if (profileId === activeProfileId || switchingId) return;
    quarantine.guardRouteSwitch(async () => {
      setSwitchingId(profileId);
      try {
        const res = await switchClaudeProfile(profileId);
        setActiveProfileId(res.active_profile.id);
        await fetchProfiles();
        await refreshRoutes();
        await onRoutesUpdated?.();
        onToast(t_toast.switched, res.message || t_toast.switchedText(res.active_profile.name), "success");
        await onProfileSwitched(res.active_profile.name, res.pinned_ip_updated);
      } catch (err) {
        onToast(t_toast.switchError, errText(err), "error");
      } finally {
        setSwitchingId(null);
      }
    });
  };

  const handleBindCurrentIp = async (profileId: string) => {
    if (!ipKnown) {
      onToast(t_toast.ipUnknown, t_toast.ipUnknownText, "warning");
      return;
    }
    setBindingId(profileId);
    try {
      const res = await bindIpToClaudeProfile(profileId, currentIp, currentCountry);
      setProfiles(res.profiles || []);
      onToast(t_toast.ipBound, t_toast.ipBoundText(formatIp(currentIp, hideIpMode), currentCountry), "success");
    } catch (err) {
      onToast(t_toast.ipBindError, errText(err), "error");
    } finally {
      setBindingId(null);
    }
  };

  const openBindModal = async (p: ClaudeProfile) => {
    const freshRoutes = (await refreshRoutes()) ?? routes;
    const initial = resolveInitialBindChoice(p, freshRoutes);
    setBindChoice(initial.choice);
    setBindKeyInput(initial.keyInput);
    setBindingTarget(p);
  };

  const handleSaveBindKey = async (e: FormEvent) => {
    e.preventDefault();
    if (!bindingTarget || savingBind) return;
    const targetProfile = bindingTarget;
    quarantine.guardRouteSwitch(async () => {
      setSavingBind(true);
      try {
        let res;
        if (bindChoice === KEY_OPTION_NONE) {
          res = await bindUpstreamToClaudeProfile(targetProfile.id, null);
          setProfiles(res.profiles || []);
          onToast(t_toast.unbound, t_toast.unboundText, "info");
        } else if (bindChoice === KEY_OPTION_NEW) {
          const cleanKey = bindKeyInput.trim();
          if (!cleanKey) return;
          res = await bindUpstreamToClaudeProfile(targetProfile.id, cleanKey);
          setProfiles(res.profiles || []);
          onToast(t_toast.keyBound, t_toast.keyBoundText(targetProfile.name), "success");
        } else {
          res = await bindRouteToClaudeProfile(targetProfile.id, bindChoice);
          setProfiles(res.profiles || []);
          onToast(t_toast.keyBound, t_toast.keyBoundText(targetProfile.name), "success");
        }
        await refreshRoutes();
        await onRoutesUpdated?.();
        setBindingTarget(null);
        setBindKeyInput("");
      } catch (err) {
        onToast(t_toast.keyBindError, errText(err), "error");
      } finally {
        setSavingBind(false);
      }
    });
  };

  const handleUnbindKey = async (profileId: string) => {
    quarantine.guardRouteSwitch(async () => {
      setBindingProxyId(profileId);
      try {
        const res = await bindUpstreamToClaudeProfile(profileId, null);
        setProfiles(res.profiles || []);
        await refreshRoutes();
        await onRoutesUpdated?.();
        onToast(t_toast.unbound, t_toast.unboundText, "info");
      } catch (err) {
        onToast(t_toast.unbindError, errText(err), "error");
      } finally {
        setBindingProxyId(null);
      }
    });
  };

  const handleRemove = async () => {
    if (!removing || removing.id === activeProfileId) {
      setRemoving(null);
      return;
    }
    setRemoveBusy(true);
    try {
      const res = await deleteClaudeProfile(removing.id);
      setProfiles(res.profiles || []);
      setActiveProfileId(res.active_profile_id || "default");
      await refreshRoutes();
      await onRoutesUpdated?.();
      onToast(t_toast.removed, t_toast.removedText(removing.name), "info");
    } catch (err) {
      onToast(t_toast.removeError, errText(err), "error");
    } finally {
      setRemoveBusy(false);
      setRemoving(null);
    }
  };

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    const cleanName = newName.trim();
    if (!cleanName) return;
    setCreating(true);
    try {
      const { ip: ipToBind, country: countryToBind } = resolveCreateProfileIpBinding(
        bindCurrentOnCreate,
        ipKnown,
        currentIp,
        currentCountry,
        createKeyChoice,
      );
      let keyToBind: string | null = null;
      let routeIdToBind: string | null = null;
      if (createKeyChoice === KEY_OPTION_NEW) {
        keyToBind = createKeyInput.trim() || null;
      } else if (createKeyChoice !== KEY_OPTION_NONE) {
        routeIdToBind = createKeyChoice;
      }
      let res = await createClaudeProfile(cleanName, ipToBind, countryToBind, keyToBind);
      if (routeIdToBind) {
        const created = res.profiles[res.profiles.length - 1];
        if (created) {
          res = await bindRouteToClaudeProfile(created.id, routeIdToBind);
        }
      }
      setProfiles(res.profiles || []);
      setNewName("");
      setCreateKeyChoice(KEY_OPTION_NONE);
      setCreateKeyInput("");
      setCreateOpen(false);
      await refreshRoutes();
      await onRoutesUpdated?.();
      onToast(t_toast.created, t_toast.createdText(cleanName), "success");
    } catch (err) {
      onToast(t_toast.createError, errText(err), "error");
    } finally {
      setCreating(false);
    }
  };

  const menuFor = (p: ClaudeProfile, isActive: boolean): MenuEntry[] => {
    const items: MenuEntry[] = [];
    if (!isActive) {
      items.push({
        id: "switch",
        label: switchingId === p.id ? t.switching : t.switchTo,
        disabled: switchingId === p.id,
        onSelect: () => handleSwitch(p.id),
      });
    }
    if (ipKnown && p.bound_ip !== currentIp) {
      items.push({ id: "bind-ip", label: t.bindIp, icon: "lock", disabled: bindingId === p.id, onSelect: () => handleBindCurrentIp(p.id) });
    }
    const hasBoundKey = hasProfileKeyBinding(p);
    items.push({
      id: "bind-key",
      label: hasBoundKey ? t.changeKey : t.bindKey,
      icon: "key",
      disabled: bindingProxyId === p.id,
      onSelect: () => void openBindModal(p),
    });
    if (hasBoundKey) {
      items.push({
        id: "unbind-key",
        label: t.unbindKey,
        icon: "x",
        disabled: bindingProxyId === p.id,
        onSelect: () => handleUnbindKey(p.id),
      });
    }
    if (!isActive && profiles.length > 1) {
      items.push({ id: "sep", type: "separator" });
      items.push({ id: "remove", label: t.remove, icon: "x", tone: "danger", onSelect: () => setRemoving(p) });
    }
    return items;
  };

  return (
    <>
      <Section title={t.section}>
        <Card
          title={t.title}
          aside={
            <Button variant="quiet" size="sm" iconOnly icon="refresh" aria-label={t.refresh} disabled={loading} onClick={fetchProfiles} />
          }
        >
          <p className="zs-t-body zs-backup__text">{t.text}</p>

          {!loaded ? (
            <div role="status" aria-label={t.loading}>
              <Skeleton variant="block" height={56} />
            </div>
          ) : profiles.length === 0 ? (
            <EmptyState
              icon="shield"
              title={t.emptyTitle}
              action={
                <Button icon="lock" onClick={() => setCreateOpen(true)}>
                  {t.create}
                </Button>
              }
            >
              {t.emptyText}
            </EmptyState>
          ) : (
            <>
              <Rows>
                {profiles.map((p) => {
                  const isActive = p.id === activeProfileId;
                  const country = countryName(p.bound_country);
                  const boundBadge = resolveBoundBadge(p, routes, routesLoaded);
                  return (
                    <Row
                      key={p.id}
                      icon="shield"
                      tone={isActive ? "ok" : "neutral"}
                      title={
                        <span className="zs-profile__name">
                          <span className="zs-profile__text">{p.name}</span>
                          {boundBadge && (
                            <Badge tone={boundBadge.tone} icon="key">
                              {boundBadge.text}
                            </Badge>
                          )}
                        </span>
                      }
                      sub={
                        <>
                          <span className="zs-profile__line">
                            {p.bound_ip ? (
                              <>
                                {t.boundIp} <Mono>{formatIp(p.bound_ip, hideIpMode)}</Mono>
                                {country ? ` · ${country}` : ""}
                              </>
                            ) : (
                              t.noIp
                            )}
                          </span>
                          {p.isolated_device_id && (
                            <span className="zs-profile__line">
                              {t.deviceId} <Mono>{p.isolated_device_id.slice(0, 8)}</Mono>
                            </span>
                          )}
                        </>
                      }
                      trail={
                        <>
                          {isActive && (
                            <Badge tone="ok" icon="check">
                              {t.active}
                            </Badge>
                          )}
                          <Menu items={menuFor(p, isActive)} label={t.actionsLabel(p.name)} />
                        </>
                      }
                    />
                  );
                })}
              </Rows>
              <Button block icon="lock" className="zs-backup__block" onClick={() => setCreateOpen(true)}>
                {t.create}
              </Button>
            </>
          )}
          <Button
            block
            variant="secondary"
            icon="shield"
            className="zs-backup__block"
            disabled={safeLogoutBusy}
            onClick={() => setSafeLogoutOpen(true)}
          >
            {safeLogoutBusy ? t.safeLogoutBusy : t.safeLogout}
          </Button>
        </Card>
      </Section>

      <ProfileModals
        routes={routes}
        ipKnown={ipKnown}
        currentIp={currentIp}
        hideIpMode={hideIpMode}
        createOpen={createOpen}
        creating={creating}
        newName={newName}
        bindCurrentOnCreate={bindCurrentOnCreate}
        createKeyChoice={createKeyChoice}
        createKeyInput={createKeyInput}
        onCloseCreate={() => setCreateOpen(false)}
        onNewNameChange={setNewName}
        onBindCurrentOnCreateChange={setBindCurrentOnCreate}
        onCreateKeyChoiceChange={setCreateKeyChoice}
        onCreateKeyInputChange={setCreateKeyInput}
        onCreate={handleCreate}
        bindingTarget={bindingTarget}
        savingBind={savingBind}
        bindChoice={bindChoice}
        bindKeyInput={bindKeyInput}
        onCloseBind={() => setBindingTarget(null)}
        onBindChoiceChange={setBindChoice}
        onBindKeyInputChange={setBindKeyInput}
        onSaveBindKey={handleSaveBindKey}
        removing={removing}
        removeBusy={removeBusy}
        onConfirmRemove={handleRemove}
        onCancelRemove={() => setRemoving(null)}
        safeLogoutOpen={safeLogoutOpen}
        safeLogoutBusy={safeLogoutBusy}
        onConfirmSafeLogout={handleSafeLogout}
        onCancelSafeLogout={() => (safeLogoutBusy ? undefined : setSafeLogoutOpen(false))}
      />
      <QuarantineOverrideModal
        open={quarantine.overrideModalOpen}
        remainingHours={quarantine.quarantineStatus?.remainingHours ?? 72}
        busy={quarantine.overriding}
        onCancel={quarantine.cancelOverride}
        onConfirm={() => void quarantine.confirmOverrideAndRun()}
      />
    </>
  );
}
