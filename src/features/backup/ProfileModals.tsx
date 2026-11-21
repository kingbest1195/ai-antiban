import type { FormEvent } from "react";
import type { ClaudeProfile, RouteView } from "../../types";
import { Banner, Button, ConfirmModal, Field, Modal, Row, Rows, Select, Switch } from "../../ui";
import type { SelectOption } from "../../ui";
import { backup as copy, common as commonCopy } from "../../shared/copy/ru";
import { formatRouteBadgeLabel, formatRouteOptionLabel, hasCountryMention } from "../../shared/lib/country";
import { formatIp, maskIpsInText } from "../../shared/lib/format";
import { decodeZastavaKeyPreview } from "../../shared/lib/zastavaKey";
import { KEY_OPTION_NEW, KEY_OPTION_NONE } from "./profileModel";

const CREATE_FORM_ID = "claude-profile-create-form";
const BIND_FORM_ID = "claude-profile-bind-key-form";

interface ProfileModalsProps {
  routes: RouteView[];
  ipKnown: boolean;
  currentIp: string;
  hideIpMode?: boolean;
  createOpen: boolean;
  creating: boolean;
  newName: string;
  bindCurrentOnCreate: boolean;
  createKeyChoice: string;
  createKeyInput: string;
  onCloseCreate: () => void;
  onNewNameChange: (val: string) => void;
  onBindCurrentOnCreateChange: (val: boolean) => void;
  onCreateKeyChoiceChange: (val: string) => void;
  onCreateKeyInputChange: (val: string) => void;
  onCreate: (e: FormEvent) => void;
  bindingTarget: ClaudeProfile | null;
  savingBind: boolean;
  bindChoice: string;
  bindKeyInput: string;
  onCloseBind: () => void;
  onBindChoiceChange: (val: string) => void;
  onBindKeyInputChange: (val: string) => void;
  onSaveBindKey: (e: FormEvent) => void;
  removing: ClaudeProfile | null;
  removeBusy: boolean;
  onConfirmRemove: () => void;
  onCancelRemove: () => void;
  safeLogoutOpen: boolean;
  safeLogoutBusy: boolean;
  onConfirmSafeLogout: () => void;
  onCancelSafeLogout: () => void;
}

export function ProfileModals({
  routes,
  ipKnown,
  currentIp,
  hideIpMode = false,
  createOpen,
  creating,
  newName,
  bindCurrentOnCreate,
  createKeyChoice,
  createKeyInput,
  onCloseCreate,
  onNewNameChange,
  onBindCurrentOnCreateChange,
  onCreateKeyChoiceChange,
  onCreateKeyInputChange,
  onCreate,
  bindingTarget,
  savingBind,
  bindChoice,
  bindKeyInput,
  onCloseBind,
  onBindChoiceChange,
  onBindKeyInputChange,
  onSaveBindKey,
  removing,
  removeBusy,
  onConfirmRemove,
  onCancelRemove,
  safeLogoutOpen,
  safeLogoutBusy,
  onConfirmSafeLogout,
  onCancelSafeLogout,
}: ProfileModalsProps) {
  const t = copy.profiles;

  return (
    <>
      <Modal
        open={createOpen}
        onClose={() => (creating ? undefined : onCloseCreate())}
        title={copy.create.title}
        footer={
          <>
            <Button onClick={onCloseCreate} disabled={creating}>
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
        <form id={CREATE_FORM_ID} className="zs-backup__create" onSubmit={onCreate}>
          <Field
            label={copy.create.nameLabel}
            placeholder={copy.create.namePlaceholder}
            help={copy.create.nameHelp}
            value={newName}
            onChange={(e) => onNewNameChange(e.target.value)}
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
                    ? copy.create.bindIpOn(formatIp(currentIp, hideIpMode))
                    : copy.create.bindIpNone
              }
              trail={
                <Switch
                  checked={createKeyChoice === KEY_OPTION_NONE && bindCurrentOnCreate && ipKnown}
                  disabled={!ipKnown || createKeyChoice !== KEY_OPTION_NONE}
                  onChange={onBindCurrentOnCreateChange}
                  aria-label={copy.create.bindIp}
                />
              }
            />
            <Row icon="key" title={copy.create.keyTitle} sub={copy.create.keySub} />
          </Rows>
          <Select
            label={copy.create.keyTitle}
            value={createKeyChoice}
            onChange={(e) => onCreateKeyChoiceChange(e.target.value)}
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
              onChange={(e) => onCreateKeyInputChange(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          )}
        </form>
      </Modal>

      <Modal
        open={bindingTarget !== null}
        onClose={() => (savingBind ? undefined : onCloseBind())}
        title={copy.bindKeyModal.title(bindingTarget?.name ?? "")}
        footer={
          <>
            <Button onClick={onCloseBind} disabled={savingBind}>
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
        <form id={BIND_FORM_ID} className="zs-backup__create" onSubmit={onSaveBindKey}>
          <p className="zs-t-body">{copy.bindKeyModal.lead}</p>
          <Select
            label={copy.bindKeyModal.sourceLabel}
            value={bindChoice}
            onChange={(e) => onBindChoiceChange(e.target.value)}
            options={
              [
                { value: KEY_OPTION_NONE, label: copy.bindKeyModal.noneOption },
                ...routes.map((r) => ({
                  value: r.id,
                  label: formatRouteOptionLabel({
                    label: r.label,
                    country: r.country,
                    ipOrHost: r.exit_ip ? formatIp(r.exit_ip, hideIpMode) : null,
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
                onChange={(e) => onBindKeyInputChange(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              {(() => {
                const preview = decodeZastavaKeyPreview(bindKeyInput);
                if (!preview) return null;
                const countryPart =
                  preview.country && !hasCountryMention(preview.label, preview.country) ? preview.country : null;
                const maskedExitIp = preview.exit_ip ? formatIp(preview.exit_ip, hideIpMode) : null;
                const maskedEntry = preview.entrySummary ? maskIpsInText(preview.entrySummary, hideIpMode) : null;
                const parts = [preview.label, countryPart, maskedExitIp, maskedEntry].filter(Boolean);
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
        onConfirm={onConfirmRemove}
        onCancel={onCancelRemove}
      >
        {t.confirmText}
      </ConfirmModal>

      <ConfirmModal
        open={safeLogoutOpen}
        title={t.safeLogoutModalTitle}
        confirmLabel={safeLogoutBusy ? t.safeLogoutBusy : t.safeLogoutModalConfirm}
        busy={safeLogoutBusy}
        onConfirm={onConfirmSafeLogout}
        onCancel={onCancelSafeLogout}
      >
        {t.safeLogoutModalText}
      </ConfirmModal>
    </>
  );
}
