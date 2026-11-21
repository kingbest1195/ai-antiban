import type { AppStateData } from "../../types";
import { Button, Modal } from "../../ui";

/** Показывать ли upgrade-гайд «Что нового в v3.0»: только мигрантам v2→v3, ещё не видевшим sheet. */
export function shouldShowWhatsNew(state: AppStateData | null | undefined): boolean {
  if (!state) return false;
  return !state.whats_new_v3_seen && Boolean(state.onboarding_v3_done);
}

const CARDS = [
  {
    title: "1. Главный экран без прокрутки и 5 разделов",
    text: "Главный экран теперь умещается целиком: статус, главный выключатель защиты и 5 понятных разделов с возвратом по кнопке «Назад».",
  },
  {
    title: "2. «Чистая комната» для новых аккаунтов",
    text: "Проверка следов и среды, изолированное окно браузера, проверка карты и 96-часовой прогрев.",
  },
  {
    title: "3. «Аккаунты, Бункер и SOS»",
    text: "Бесплатный локальный автобэкап проектов и чатов, а также пошаговый план спасения при запросе проверки личности.",
  },
] as const;

export interface WhatsNewSheetProps {
  open: boolean;
  busy?: boolean;
  onAcknowledge: () => void;
  onRestartOnboarding: () => void;
}

/** Однократный компактный sheet для пользователей, обновившихся с v2.x на v3.0.0. */
export function WhatsNewSheet({ open, busy = false, onAcknowledge, onRestartOnboarding }: WhatsNewSheetProps) {
  return (
    <Modal
      open={open}
      onClose={onAcknowledge}
      title="Что нового в Заставе v3.0"
      footer={
        <div className="zs-v3-whatsnew__actions">
          <Button variant="primary" block disabled={busy} onClick={onAcknowledge}>
            Понятно
          </Button>
          <Button variant="secondary" block disabled={busy} onClick={onRestartOnboarding}>
            Пройти знакомство заново
          </Button>
        </div>
      }
    >
      <div className="zs-v3-whatsnew">
        {CARDS.map((card) => (
          <div key={card.title} className="zs-v3-whatsnew__card">
            <h3 className="zs-v3-whatsnew__title">{card.title}</h3>
            <p className="zs-v3-whatsnew__text">{card.text}</p>
          </div>
        ))}
      </div>
    </Modal>
  );
}
