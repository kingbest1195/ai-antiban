import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import type { ClaudeProfile } from "../../types";
import {
  bindIpToClaudeProfile,
  bindUpstreamToClaudeProfile,
  createClaudeProfile,
  deleteClaudeProfile,
  listClaudeProfiles,
  switchClaudeProfile,
} from "../../utils/api";
import { Badge, Button, Card, ConfirmModal, EmptyState, Field, Menu, Modal, Mono, Row, Rows, Section, Skeleton, Switch } from "../../ui";
import type { MenuEntry } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { status as words } from "../../shared/copy/ru";
import { backup as copy, common as commonCopy } from "../../shared/copy/ru";
import { countryName } from "../../shared/lib/country";

export interface ProfilesSectionProps {
  currentIp: string;
  currentCountry: string;
  activeUpstreamKey?: string | null;
  onProfileSwitched: (profileName: string, pinnedIp?: string | null) => void;
  onToast: ShowToast;
}

const CREATE_FORM_ID = "claude-profile-create-form";

/** Профили Claude: строка на профиль, переключение, привязка IP и ключа, удаление с подтверждением, создание. */
export function ProfilesSection({ currentIp, currentCountry, onProfileSwitched, onToast }: ProfilesSectionProps) {
  const [profiles, setProfiles] = useState<ClaudeProfile[]>([]);
  const [activeProfileId, setActiveProfileId] = useState<string>("default");
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
  const [creating, setCreating] = useState(false);
  const t = copy.profiles;
  const t_toast = copy.toast;
  const ipKnown = Boolean(currentIp) && currentIp !== "--";

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
  }, []);

  const errText = (err: unknown) => (err instanceof Error ? err.message : String(err));

  const handleSwitch = async (profileId: string) => {
    if (profileId === activeProfileId || switchingId) return;
    setSwitchingId(profileId);
    try {
      const res = await switchClaudeProfile(profileId);
      setActiveProfileId(res.active_profile.id);
      await fetchProfiles();
      onToast(t_toast.switched, res.message || t_toast.switchedText(res.active_profile.name), "success");
      onProfileSwitched(res.active_profile.name, res.pinned_ip_updated);
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

  const handleBindKey = () => {
    onToast(copy.soon.title, copy.soon.text, "warning");
  };

  const handleUnbindKey = async (profileId: string) => {
    setBindingProxyId(profileId);
    try {
      const res = await bindUpstreamToClaudeProfile(profileId, null);
      setProfiles(res.profiles || []);
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
      const ipToBind = bindCurrentOnCreate && ipKnown ? currentIp : null;
      const countryToBind = bindCurrentOnCreate && currentCountry !== "--" ? currentCountry : null;
      const res = await createClaudeProfile(cleanName, ipToBind, countryToBind, null);
      setProfiles(res.profiles || []);
      setNewName("");
      setCreateOpen(false);
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
    items.push(
      p.bound_upstream_key
        ? { id: "unbind-key", label: t.unbindKey, icon: "x", disabled: bindingProxyId === p.id, onSelect: () => handleUnbindKey(p.id) }
        : { id: "bind-key", label: t.bindKey, icon: "key", onSelect: handleBindKey },
    );
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
                  return (
                    <Row
                      key={p.id}
                      icon="shield"
                      tone={isActive ? "ok" : "neutral"}
                      title={
                        <span className="zs-profile__name">
                          <span className="zs-profile__text">{p.name}</span>
                          {p.bound_upstream_key && (
                            <Badge tone="info" icon="key">
                              {t.keyBound}
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
            <Button variant="primary" type="submit" form={CREATE_FORM_ID} disabled={creating || !newName.trim()}>
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
              sub={ipKnown ? copy.create.bindIpOn(currentIp) : copy.create.bindIpNone}
              trail={
                <Switch
                  checked={bindCurrentOnCreate && ipKnown}
                  disabled={!ipKnown}
                  onChange={setBindCurrentOnCreate}
                  aria-label={copy.create.bindIp}
                />
              }
            />
            <Row
              icon="key"
              title={copy.create.keyTitle}
              sub={copy.create.keySub}
              trail={<Badge tone="info">{words.soon}</Badge>}
            />
          </Rows>
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
