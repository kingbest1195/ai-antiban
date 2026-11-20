import { useState } from "react";
import { Banner, Button, Card } from "../../ui";
import { sosCopy as copy } from "../../shared/copy/ru/sos";
import type { ShowToast } from "../../shared/hooks";
import {
  listCleanProfiles,
  markCleanProfileTainted,
  markIpTainted,
} from "../../utils/api/cleanRoom";
import "./sos.css";

export interface BannedBranchProps {
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
export function BannedBranch({ onToast, onNavigateToCleanRoom }: BannedBranchProps) {
  const t = copy.banned;
  const [jumping, setJumping] = useState(false);

  const handleJump = async () => {
    if (jumping) return;
    setJumping(true);
    try {
      await executeBannedCleanRoomJump(onNavigateToCleanRoom, onToast);
    } finally {
      setJumping(false);
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

      <Banner tone="danger" icon="alert" title={t.cleanRoomWarning} className="zs-sos__block">
        <Button
          variant="primary"
          block
          icon="arrow"
          disabled={jumping}
          onClick={() => void handleJump()}
        >
          {jumping ? t.jumpingBtn : t.jumpCleanRoomBtn}
        </Button>
      </Banner>
    </Card>
  );
}
