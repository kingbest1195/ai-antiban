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
  switchClaudeProfile,
} from "../../utils/api";
import { Badge, Banner, Button, Card, ConfirmModal, EmptyState, Field, Menu, Modal, Mono, Row, Rows, Section, Select, Skeleton, Switch } from "../../ui";
import type { MenuEntry, SelectOption } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { backup as copy, common as commonCopy } from "../../shared/copy/ru";
import { countryName, formatRouteBadgeLabel, formatRouteOptionLabel, hasCountryMention } from "../../shared/lib/country";
import { decodeZastavaKeyPreview } from "../../shared/lib/zastavaKey";

export interface ProfilesSectionProps {
  currentIp: string;
  currentCountry: string;
  activeUpstreamKey?: string | null;
  routesSnapshot?: RoutesSnapshot | null;
  refreshTrigger?: number;
  onRoutesUpdated?: () => Promise<unknown> | void;
  onProfileSwitched: (profileName: string, pinnedIp?: string | null) => Promise<unknown> | void;
  onToast: ShowToast;
}

const CREATE_FORM_ID = "claude-profile-create-form";
const BIND_FORM_ID = "claude-profile-bind-key-form";
export const KEY_OPTION_NONE = "__none__";
export const KEY_OPTION_NEW = "__new__";

export function hasProfileKeyBinding(p: Pick<ClaudeProfile, "bound_upstream_key" | "bound_route_id">): boolean {
  return Boolean(p.bound_upstream_key || p.bound_route_id);
}

export function isProfileRouteMissing(
  p: Pick<ClaudeProfile, "bound_upstream_key" | "bound_route_id">,
  availableRoutes: Pick<RouteView, "id">[],
  routesLoaded: boolean,
): boolean {
  if (!routesLoaded || p.bound_upstream_key || !p.bound_route_id) return false;
  return !availableRoutes.some((r) => r.id === p.bound_route_id);
}

export function resolveCreateProfileIpBinding(
  bindCurrentOnCreate: boolean,
  ipKnown: boolean,
  currentIp: string,
  currentCountry: string,
  createKeyChoice: string,
): { ip: string | null; country: string | null } {
  if (createKeyChoice !== KEY_OPTION_NONE) {
    return { ip: null, country: null };
  }
  return {
    ip: bindCurrentOnCreate && ipKnown ? currentIp : null,
    country: bindCurrentOnCreate && ipKnown && currentCountry !== "--" ? currentCountry : null,
  };
}

export function resolveInitialBindChoice(
  p: Pick<ClaudeProfile, "bound_upstream_key" | "bound_route_id">,
  availableRoutes: Pick<RouteView, "id">[],
): { choice: string; keyInput: string } {
  if (p.bound_route_id && availableRoutes.some((r) => r.id === p.bound_route_id)) {
    return { choice: p.bound_route_id, keyInput: "" };
  }
  if (p.bound_upstream_key) {
    return { choice: KEY_OPTION_NEW, keyInput: p.bound_upstream_key };
  }
  return { choice: KEY_OPTION_NONE, keyInput: "" };
}

/** Профили Claude: строка на профиль, переключение, привязка IP и ключа, удаление с подтверждением, создание. */
export function ProfilesSection({
  currentIp,
  currentCountry,
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

  const handleSwitch = async (profileId: string) => {
    if (profileId === activeProfileId || switchingId) return;
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
      onToast(t_toast.ipBound, t_toast.ipBoundText(currentIp, currentCountry), "success");
    } catch (err) {
      onToast(t_toast.ipBindError, errText(err), "error");
    } finally {
      setBindingId(null);
    }
  };

  const resolveBoundBadge = (p: ClaudeProfile): { text: string; tone: "info" | "danger" } | null => {
    if (!p.bound_upstream_key && !p.bound_route_id) return null;
    if (isProfileRouteMissing(p, routes, routesLoaded)) {
      return { text: "Маршрут удалён", tone: "danger" };
    }
    if (p.bound_route_id) {
      const match = routes.find((r) => r.id === p.bound_route_id);
      if (match) {
        return { text: t.keyBoundLabel(formatRouteBadgeLabel(match.label, match.country)), tone: "info" };
      }
    }
    if (p.bound_upstream_key) {
      const preview = decodeZastavaKeyPreview(p.bound_upstream_key);
      if (preview?.label) {
        return { text: t.keyBoundLabel(formatRouteBadgeLabel(preview.label, preview.country)), tone: "info" };
      }
      if (preview?.entrySummary) {
        return { text: t.keyBoundLabel(preview.entrySummary), tone: "info" };
      }
    }
    return { text: t.keyBound, tone: "info" };
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
    setSavingBind(true);
    try {
      let res;
      if (bindChoice === KEY_OPTION_NONE) {
        res = await bindUpstreamToClaudeProfile(bindingTarget.id, null);
        setProfiles(res.profiles || []);
        onToast(t_toast.unbound, t_toast.unboundText, "info");
      } else if (bindChoice === KEY_OPTION_NEW) {
        const cleanKey = bindKeyInput.trim();
        if (!cleanKey) return;
        res = await bindUpstreamToClaudeProfile(bindingTarget.id, cleanKey);
        setProfiles(res.profiles || []);
        onToast(t_toast.keyBound, t_toast.keyBoundText(bindingTarget.name), "success");
      } else {
        res = await bindRouteToClaudeProfile(bindingTarget.id, bindChoice);
        setProfiles(res.profiles || []);
        onToast(t_toast.keyBound, t_toast.keyBoundText(bindingTarget.name), "success");
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
  };

  const handleUnbindKey = async (profileId: string) => {
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
      onSelect: () => {
        void openBindModal(p);
      },
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
                  const boundBadge = resolveBoundBadge(p);
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
                                {t.boundIp} <Mono>{p.bound_ip}</Mono>
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
        </Card>
      </Section>

      <Modal
        open={createOpen}
        onClose={() => (creating ? undefined : setCreateOpen(false))}
        title={copy.create.title}
        footer={
          <>
            <Button onClick={() => setCreateOpen(false)} disabled={creating}>
              {commonCopy.cancel}
            </Button>
            <Button
              variant="primary"
              type="submit"
              form={CREATE_FORM_ID}
              disabled={
                creating ||
                !newName.trim() ||
                (createKeyChoice === KEY_OPTION_NEW && !createKeyInput.trim())
              }
            >
              {creating ? copy.create.submitting : copy.create.submit}
            </Button>
          </>
        }
      >
        <form id={CREATE_FORM_ID} className="zs-backup__create" onSubmit={handleCreate}>
          <Field
            label={copy.create.nameLabel}
            placeholder={copy.create.namePlaceholder}
            help={copy.create.nameHelp}
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            autoComplete="off"
            required
          />
          <Rows>
            <Row
              icon="lock"
              title={copy.create.bindIp}
              sub={
                createKeyChoice !== KEY_OPTION_NONE
                  ? "Отключено: профиль работает через выделенный ключ Заставы"
                  : ipKnown
                    ? copy.create.bindIpOn(currentIp)
                    : copy.create.bindIpNone
              }
              trail={
                <Switch
                  checked={createKeyChoice === KEY_OPTION_NONE && bindCurrentOnCreate && ipKnown}
                  disabled={!ipKnown || createKeyChoice !== KEY_OPTION_NONE}
                  onChange={setBindCurrentOnCreate}
                  aria-label={copy.create.bindIp}
                />
              }
            />
            <Row
              icon="key"
              title={copy.create.keyTitle}
              sub={copy.create.keySub}
            />
          </Rows>
          <Select
            label={copy.create.keyTitle}
            value={createKeyChoice}
            onChange={(e) => setCreateKeyChoice(e.target.value)}
            options={
              [
                { value: KEY_OPTION_NONE, label: copy.create.keyNone },
                ...routes.map((r) => ({
                  value: r.id,
                  label: formatRouteBadgeLabel(r.label, r.country),
                })),
                { value: KEY_OPTION_NEW, label: copy.create.keyNewOption },
              ] satisfies SelectOption[]
            }
          />
          {createKeyChoice === KEY_OPTION_NEW && (
            <Field
              label={copy.create.keyPasteLabel}
              placeholder={copy.create.keyPastePlaceholder}
              value={createKeyInput}
              onChange={(e) => setCreateKeyInput(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          )}
        </form>
      </Modal>

      <Modal
        open={bindingTarget !== null}
        onClose={() => (savingBind ? undefined : setBindingTarget(null))}
        title={copy.bindKeyModal.title(bindingTarget?.name ?? "")}
        footer={
          <>
            <Button onClick={() => setBindingTarget(null)} disabled={savingBind}>
              {commonCopy.cancel}
            </Button>
            <Button
              variant="primary"
              type="submit"
              form={BIND_FORM_ID}
              disabled={savingBind || (bindChoice === KEY_OPTION_NEW && !bindKeyInput.trim())}
            >
              {savingBind ? copy.bindKeyModal.saving : copy.bindKeyModal.save}
            </Button>
          </>
        }
      >
        <form id={BIND_FORM_ID} className="zs-backup__create" onSubmit={handleSaveBindKey}>
          <p className="zs-t-body">{copy.bindKeyModal.lead}</p>
          <Select
            label={copy.bindKeyModal.sourceLabel}
            value={bindChoice}
            onChange={(e) => setBindChoice(e.target.value)}
            options={
              [
                { value: KEY_OPTION_NONE, label: copy.bindKeyModal.noneOption },
                ...routes.map((r) => ({
                  value: r.id,
                  label: formatRouteOptionLabel({
                    label: r.label,
                    country: r.country,
                    ipOrHost: r.exit_ip,
                  }),
                })),
                { value: KEY_OPTION_NEW, label: copy.bindKeyModal.newOption },
              ] satisfies SelectOption[]
            }
          />
          {bindChoice === KEY_OPTION_NEW && (
            <>
              <Field
                label={copy.bindKeyModal.inputLabel}
                placeholder={copy.bindKeyModal.inputPlaceholder}
                value={bindKeyInput}
                onChange={(e) => setBindKeyInput(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              {(() => {
                const preview = decodeZastavaKeyPreview(bindKeyInput);
                if (!preview) return null;
                const countryPart =
                  preview.country && !hasCountryMention(preview.label, preview.country) ? preview.country : null;
                const parts = [preview.label, countryPart, preview.exit_ip, preview.entrySummary].filter(Boolean);
                return parts.length > 0 ? (
                  <Banner tone="info" title={copy.bindKeyModal.previewLabel}>
                    {parts.join(" · ")}
                  </Banner>
                ) : null;
              })()}
            </>
          )}
        </form>
      </Modal>

      <ConfirmModal
        open={removing !== null}
        title={t.confirmTitle(removing?.name ?? "")}
        confirmLabel={t.confirmAction}
        busy={removeBusy}
        onConfirm={handleRemove}
        onCancel={() => setRemoving(null)}
      >
        {t.confirmText}
      </ConfirmModal>
    </>
  );
}
