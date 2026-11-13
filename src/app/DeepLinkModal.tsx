import { useEffect, useMemo, useState } from "react";
import type { ClaudeProfile } from "../types";
import { listClaudeProfiles } from "../utils/api";
import { decodeZastavaKeyPreview, formatRemainingTimeRu } from "../shared/lib/zastavaKey";
import { Badge, Button, Card, Field, Modal, Mono, Segmented, Select } from "../ui";
import type { SegmentedOption, SelectOption } from "../ui";

export type DeepLinkScope = "all" | "profile" | "save_only";

export interface DeepLinkConfirmOptions {
  scope: DeepLinkScope;
  profileId?: string;
}

export interface DeepLinkModalProps {
  deepLinkKey: string | null;
  onClose: () => void;
  onConfirm: (options: DeepLinkConfirmOptions) => void;
  submitting?: boolean;
}

const SCOPE_OPTIONS: SegmentedOption<DeepLinkScope>[] = [
  { value: "all", label: "Ко всем профилям" },
  { value: "profile", label: "К профилю Claude" },
  { value: "save_only", label: "Только добавить" },
];

/** Модальное окно подтверждения подключения ключа из ссылки zastava://... */
export function DeepLinkModal({
  deepLinkKey,
  onClose,
  onConfirm,
  submitting = false,
}: DeepLinkModalProps) {
  const [scope, setScope] = useState<DeepLinkScope>("all");
  const [profiles, setProfiles] = useState<ClaudeProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string>("default");

  useEffect(() => {
    if (!deepLinkKey) return;
    setScope("all");
    listClaudeProfiles()
      .then((res) => {
        setProfiles(res.profiles || []);
        setSelectedProfileId(res.active_profile_id || res.profiles?.[0]?.id || "default");
      })
      .catch(() => {});
  }, [deepLinkKey]);

  const preview = useMemo(
    () => (deepLinkKey ? decodeZastavaKeyPreview(deepLinkKey) : null),
    [deepLinkKey],
  );

  if (!deepLinkKey) return null;

  const maskedKey =
    deepLinkKey.length > 22
      ? `${deepLinkKey.slice(0, 22)}…`
      : deepLinkKey;

  const profileOptions: SelectOption[] = profiles.map((p) => ({
    value: p.id,
    label: p.is_active ? `${p.name} (активен)` : p.name,
  }));

  const expiryText = preview?.expires_at
    ? `${new Date(preview.expires_at * 1000).toLocaleDateString()} (${formatRemainingTimeRu(preview.expires_at)})`
    : null;

  const scopeHelp =
    scope === "all"
      ? "Маршрут станет основным для всех ИИ-сервисов без отдельной привязки."
      : scope === "profile"
      ? "Ключ привяжется только к Claude выбранного профиля и не затронет OpenAI или Gemini."
      : "Ключ сохранится в списке маршрутов, но не изменит текущее подключение.";

  return (
    <Modal
      open={Boolean(deepLinkKey)}
      onClose={onClose}
      title="Подключить ключ Заставы?"
      footer={
        <>
          <Button variant="quiet" onClick={onClose} disabled={submitting}>
            Отмена
          </Button>
          <Button
            variant="primary"
            onClick={() =>
              onConfirm({
                scope,
                profileId: scope === "profile" ? selectedProfileId : undefined,
              })
            }
            disabled={submitting}
          >
            {submitting ? "Подключение…" : "Подключить ключ"}
          </Button>
        </>
      }
    >
      <div className="zs-stack">
        <p className="zs-modal-text">
          Обнаружена ссылка для быстрого подключения ключа. Проверьте параметры и выберите область действия.
        </p>

        <Card>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "var(--space-2)",
              flexWrap: "wrap",
              marginBottom: "var(--space-2)",
            }}
          >
            <span className="zs-t-caption" style={{ color: "var(--ink-2)" }}>
              {preview?.label || "Ссылка быстрого подключения"}
            </span>
            <div style={{ display: "flex", gap: "var(--space-1)", flexWrap: "wrap" }}>
              {preview?.country && <Badge tone="info">{preview.country}</Badge>}
              <Badge tone="ok" icon="key">
                zastava://
              </Badge>
            </div>
          </div>

          {(preview?.exit_ip || preview?.entrySummary || expiryText) && (
            <div className="zs-stack" style={{ gap: "var(--space-1)", marginBottom: "var(--space-2)" }}>
              {preview?.exit_ip && (
                <div className="zs-t-caption">
                  Выходной IP: <Mono>{preview.exit_ip}</Mono>
                </div>
              )}
              {preview?.entrySummary && (
                <div className="zs-t-caption">
                  Узел входа: <Mono>{preview.entrySummary}</Mono>
                </div>
              )}
              {expiryText && (
                <div className="zs-t-caption">
                  Действует до: {expiryText}
                </div>
              )}
            </div>
          )}

          <Field
            label="Предпросмотр ключа"
            readOnly
            value={maskedKey}
            help={scopeHelp}
          />
        </Card>

        <div className="zs-stack" style={{ gap: "var(--space-2)" }}>
          <span className="zs-t-label">Куда применить ключ</span>
          <Segmented
            aria-label="Куда применить ключ"
            options={SCOPE_OPTIONS}
            value={scope}
            onChange={setScope}
          />
          {scope === "profile" && profileOptions.length > 0 && (
            <Select
              label="Профиль Claude"
              options={profileOptions}
              value={selectedProfileId}
              onChange={(e) => setSelectedProfileId(e.target.value)}
            />
          )}
        </div>
      </div>
    </Modal>
  );
}
