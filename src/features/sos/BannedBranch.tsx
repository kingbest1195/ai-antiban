import { useState } from "react";
import { Banner, Button, Card, Select } from "../../ui";
import { bunkerCopy } from "../../shared/copy/ru/bunker";
import { sosCopy as copy } from "../../shared/copy/ru/sos";
import type { ShowToast } from "../../shared/hooks";
import { writeClipboard } from "../../shared/lib/clipboard";
import type { TeleportTarget } from "../../types";
import { runContextTeleport } from "../../utils/api/bunker";
import {
  listCleanProfiles,
  markCleanProfileTainted,
  markIpTainted,
} from "../../utils/api/cleanRoom";
import "./sos.css";

export interface BannedBranchProps {
  ctaVariant?: "primary" | "secondary";
  onToast?: ShowToast;
  onNavigateToCleanRoom?: (step?: number) => void;
}

/**
 * Помечает текущий IP как скомпрометированный, а также активный профиль песочницы (если есть),
 * после чего переводит пользователя на Шаг 1 «Чистой комнаты».
 */
export async function executeBannedCleanRoomJump(
  onNavigateToCleanRoom?: (step?: number) => void,
  onToast?: ShowToast,
): Promise<void> {
  await markIpTainted();
  try {
    const cleanState = await listCleanProfiles();
    if (cleanState.active_profile_id) {
      await markCleanProfileTainted(cleanState.active_profile_id, "sos_banned_branch");
    }
  } catch {
    // Не блокируем переход, если профили песочницы ещё не созданы.
  }
  onToast?.(copy.banned.taintedToastTitle, copy.banned.taintedToastText, "info");
  onNavigateToCleanRoom?.(1);
}

/** Ветка 4 SOS: Account disabled / Organization suspended — разбор причин и 1-click переход в Чистую комнату. */
export function BannedBranch({
  ctaVariant = "primary",
  onToast,
  onNavigateToCleanRoom,
}: BannedBranchProps) {
  const t = copy.banned;
  const [jumping, setJumping] = useState(false);
  const [teleportTarget, setTeleportTarget] = useState<TeleportTarget>("universal");
  const [teleporting, setTeleporting] = useState(false);
  const [teleported, setTeleported] = useState(false);

  const handleJump = async () => {
    if (jumping) return;
    setJumping(true);
    try {
      await executeBannedCleanRoomJump(onNavigateToCleanRoom, onToast);
    } finally {
      setJumping(false);
    }
  };

  const handleTeleport = async () => {
    if (teleporting) return;
    setTeleporting(true);
    try {
      const res = await runContextTeleport(teleportTarget);
      await writeClipboard(res.primaryPasteText);
      setTeleported(true);
      onToast?.(
        bunkerCopy.actions.teleport.toastTitle,
        bunkerCopy.actions.teleport.toastText(res.filesWritten.length, res.secretsRedactedCount),
        "success",
      );
    } catch (err) {
      onToast?.(
        bunkerCopy.actions.teleport.errTitle,
        err instanceof Error ? err.message : String(err),
        "error",
      );
    } finally {
      setTeleporting(false);
    }
  };

  return (
    <Card title={t.title}>
      <p className="zs-t-heading">{t.causesTitle}</p>
      <ul className="zs-t-body zs-sos__list">
        {t.causes.map((cause) => (
          <li key={cause}>{cause}</li>
        ))}
      </ul>

      <Banner tone="danger" icon="alert" title={t.cleanRoomWarning} className="zs-sos__block" />
      <div className="zs-sos__step">
        <p className="zs-t-heading zs-sos__step-title">{t.teleportTitle}</p>
        <p className="zs-t-body zs-sos__step-desc">{t.teleportSub}</p>
        <Select
          label={bunkerCopy.actions.teleport.formatLabel}
          value={teleportTarget}
          options={[...bunkerCopy.actions.teleport.options]}
          onChange={(e) => {
            setTeleportTarget(e.target.value as TeleportTarget);
            setTeleported(false);
          }}
        />
        <div className="zs-sos__block">
          <Button
            variant="secondary"
            size="sm"
            icon={teleported ? "check" : "copy"}
            disabled={teleporting}
            onClick={() => void handleTeleport()}
          >
            {teleporting
              ? bunkerCopy.actions.teleport.exportingBtn
              : teleported
                ? bunkerCopy.actions.teleport.doneBtn
                : bunkerCopy.actions.teleport.exportBtn}
          </Button>
        </div>
      </div>
      <div className="zs-sos__block">
        <Button
          variant={ctaVariant}
          block
          icon="arrow"
          disabled={jumping}
          onClick={() => void handleJump()}
        >
          {jumping ? t.jumpingBtn : t.jumpCleanRoomBtn}
        </Button>
      </div>
    </Card>
  );
}
