import type { ReactNode } from "react";
import { Button, Icon, Menu, Spinner, Tip } from "../../ui";
import type { MenuEntry } from "../../ui";
import type { ShellV3HeaderProps } from "./types";

const EXCLUDED_MENU_IDS = new Set(["subscription", "rescan", "syncTimezone", "timezone"]);

/** Убирает из меню «Ещё» пункты, вынесенные на Home Hub и в разделы v3, а также лишние разделители. */
export function menuWithout(items: MenuEntry[], ids: readonly string[] = []): MenuEntry[] {
  const drop = new Set([...EXCLUDED_MENU_IDS, ...ids]);
  const out = items.filter((e) => !drop.has(e.id));
  return out.filter((e, i, arr) => {
    if (e.type !== "separator") return true;
    if (i === 0 || i === arr.length - 1) return false;
    return arr[i - 1]?.type !== "separator";
  });
}

/** Кликабельный индикатор времени последней проверки сети в шапке. */
export function PingBadge({ ms, refreshing, onRescan }: { ms: number | null; refreshing: boolean; onRescan: () => void }) {
  if (ms == null && !refreshing) return null;
  return (
    <Tip
      title="Время проверки сети"
      text={
        <>
          {ms != null ? `Последняя полная проверка сети заняла ${ms} мс. ` : ""}
          Это время аудита IP и рисков, а не скорость интернета. Нажмите, чтобы проверить заново.
        </>
      }
    >
      <button
        type="button"
        className="zs-v3-ping"
        onClick={onRescan}
        disabled={refreshing}
        aria-label="Проверить сеть заново"
      >
        {refreshing ? <Spinner size={12} /> : <Icon name="pulse" size={12} />}
        {ms != null ? `${ms} мс` : "…"}
      </button>
    </Tip>
  );
}

/** Шапка Shell v3: щит Заставы, жёлтая пилюля «Обновить», PingBadge, скрытие IP и кнопка меню «more». */
export function HeaderBar({
  pingMs,
  refreshing,
  onRescan,
  hideIpMode,
  onToggleHideIp,
  updateInfo,
  onOpenUpdate,
  menuItems,
  children,
}: ShellV3HeaderProps & { children?: ReactNode }) {
  const update = updateInfo?.update_available ? updateInfo.latest_version : null;
  const filteredMenu = menuWithout(menuItems);

  return (
    <header className="zs-app__bar zs-v3-bar">
      <span className="zs-app__logo">
        <Icon name="shield" />
      </span>
      <span className="zs-app__name">Застава</span>
      {children}
      <span className="zs-app__spacer" />
      {update && (
        <Tip title={`Вышла версия ${update}`} text="Нажмите, чтобы посмотреть изменения и установить обновление.">
          <button type="button" className="zs-v3-update" onClick={onOpenUpdate}>
            <Icon name="download" size={13} />
            Обновить
          </button>
        </Tip>
      )}
      <PingBadge ms={pingMs} refreshing={refreshing} onRescan={onRescan} />
      <Tip
        text={hideIpMode ? "IP-адреса скрыты. Нажмите, чтобы показать." : "Скрыть IP-адреса для безопасного скриншота."}
      >
        <Button
          variant={hideIpMode ? "secondary" : "quiet"}
          iconOnly
          icon={hideIpMode ? "eyeOff" : "eye"}
          aria-label={hideIpMode ? "Показать IP-адреса" : "Скрыть IP-адреса"}
          aria-pressed={hideIpMode}
          onClick={onToggleHideIp}
        />
      </Tip>
      <Menu
        items={filteredMenu}
        label="Меню и настройки"
        triggerIcon="more"
        triggerDot={Boolean(update)}
      />
    </header>
  );
}

/** Заголовок подстраницы с кнопкой «Назад» по navStack и опциональной кнопкой «На главную». */
export function PageHead({
  title,
  onBack,
  onHome,
  showHome = false,
}: {
  title: string;
  onBack: () => void;
  onHome?: () => void;
  showHome?: boolean;
}) {
  return (
    <div className="zs-v3-page-head">
      <button type="button" className="zs-v3-back" onClick={onBack}>
        <Icon name="back" size={18} />
        Назад
      </button>
      <h2 className="zs-v3-page-head__title">{title}</h2>
      {showHome && onHome && (
        <Button variant="quiet" size="sm" className="zs-v3-home-btn" onClick={onHome}>
          На главную
        </Button>
      )}
    </div>
  );
}
