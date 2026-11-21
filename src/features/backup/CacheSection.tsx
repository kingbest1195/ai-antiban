import { useState } from "react";
import type { ProviderId } from "../../types";
import { Button, Card, ConfirmModal, Row, Rows, Section } from "../../ui";
import type { ClaudeBackup } from "../../shared/hooks";
import { backup as copy } from "../../shared/copy/ru";

const CLIENTS: { provider: ProviderId; name: string; icon: "term" | "globe" }[] = [
  { provider: "anthropic", name: copy.cache.claude, icon: "term" },
  { provider: "openai", name: copy.cache.chatgpt, icon: "globe" },
];

/** Очистка хвостов и меток устройства клиентов ИИ: тихая danger-кнопка и подтверждение. */
export function CacheSection({ backup }: { backup: ClaudeBackup }) {
  const [pending, setPending] = useState<ProviderId | null>(null);
  const t = copy.cache;
  const busyOf = (p: ProviderId) => (p === "anthropic" ? backup.cleaningClaude : backup.cleaningGpt);
  const target = CLIENTS.find((c) => c.provider === pending);

  const confirm = async () => {
    if (!pending) return;
    await backup.handleCleanSpecificClientCache(pending);
    setPending(null);
  };

  return (
    <>
      <Section title={t.section}>
        <Card title={t.title}>
          <p className="zs-t-body zs-backup__text">{t.text}</p>
          <Rows>
            {CLIENTS.map((c) => (
              <Row
                key={c.provider}
                icon={c.icon}
                title={c.name}
                trail={
                  <Button variant="danger" size="sm" disabled={busyOf(c.provider)} onClick={() => setPending(c.provider)}>
                    {busyOf(c.provider) ? t.cleaning : t.clean}
                  </Button>
                }
              />
            ))}
          </Rows>
        </Card>
      </Section>
      <ConfirmModal
        open={pending !== null}
        title={t.confirmTitle(target?.name ?? "")}
        confirmLabel={t.confirmAction}
        busy={pending !== null && busyOf(pending)}
        busyLabel={t.cleaning}
        onConfirm={confirm}
        onCancel={() => setPending(null)}
      >
        {t.confirmText}
      </ConfirmModal>
    </>
  );
}
