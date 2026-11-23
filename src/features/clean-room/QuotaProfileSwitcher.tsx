import type { CleanRoomProfile } from "../../types";
import { Badge, Button } from "../../ui";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";

export interface QuotaProfileSwitcherProps {
  profiles: readonly CleanRoomProfile[];
  activeProfileId: string | null;
  onSelectProfile: (profileId: string) => void;
  onQuickAddGemini: () => void;
}

/** Быстрое переключение 2–3 изолированных профилей для смены квот без смешивания cookies. */
export function QuotaProfileSwitcher({
  profiles,
  activeProfileId,
  onSelectProfile,
  onQuickAddGemini,
}: QuotaProfileSwitcherProps) {
  const geminiCount = profiles.filter((p) => p.provider === "gemini").length;
  if (profiles.length < 2 && geminiCount === 0) {
    return null;
  }

  return (
    <div className="cr-quota-switcher">
      <div className="cr-row-between">
        <p className="cr-form__title">{copy.sandbox.quotaSwitcher.title}</p>
        {geminiCount > 0 && geminiCount < 3 && (
          <Button size="sm" variant="quiet" onClick={onQuickAddGemini}>
            {copy.sandbox.quotaSwitcher.addReserveBtn}
          </Button>
        )}
      </div>
      <p className="zs-t-caption cr-step-head__text">{copy.sandbox.quotaSwitcher.hint}</p>
      <div className="cr-quota-pills" role="group" aria-label={copy.sandbox.quotaSwitcher.title}>
        {profiles.slice(0, 4).map((p) => {
          const isActive = p.id === activeProfileId;
          return (
            <Button
              key={p.id}
              size="sm"
              variant="secondary"
              aria-pressed={isActive}
              onClick={() => onSelectProfile(p.id)}
            >
              <span>{p.label}</span>
              {isActive && <Badge tone="info">{copy.sandbox.quotaSwitcher.activeTag}</Badge>}
            </Button>
          );
        })}
      </div>
    </div>
  );
}
