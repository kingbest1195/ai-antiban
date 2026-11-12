import type { CSSProperties } from "react";
import {
  Activity,
  ArrowRight,
  Check,
  ChevronRight,
  CircleHelp,
  Copy,
  Ellipsis,
  Folder,
  Globe,
  Info,
  Key,
  Lock,
  Power,
  RefreshCw,
  Shield,
  Terminal,
  TriangleAlert,
  X,
  Zap,
} from "lucide-react";
import { cx } from "./cx";

/** 19 иконок ДС (design/zastava-ds/icons) → имена lucide-react. */
export const ICONS = {
  alert: TriangleAlert,
  arrow: ArrowRight,
  check: Check,
  chev: ChevronRight,
  copy: Copy,
  folder: Folder,
  globe: Globe,
  help: CircleHelp,
  info: Info,
  key: Key,
  lock: Lock,
  more: Ellipsis,
  power: Power,
  pulse: Activity,
  refresh: RefreshCw,
  shield: Shield,
  term: Terminal,
  x: X,
  zap: Zap,
} as const;

export type IconName = keyof typeof ICONS;
export const ICON_NAMES = Object.keys(ICONS) as IconName[];

export interface IconProps {
  name: IconName;
  /** Размер в px. По умолчанию 16 (размер задаёт класс zs-ic). */
  size?: number;
  /** Подпись для скринридера. Без неё иконка декоративная (aria-hidden). */
  label?: string;
  className?: string;
}

/** Линейная иконка ДС: сетка 24, толщина 1,75, цвет наследуется от текста. */
export function Icon({ name, size, label, className }: IconProps) {
  const Glyph = ICONS[name];
  const style: CSSProperties | undefined = size ? { width: size, height: size } : undefined;
  return (
    <Glyph
      className={cx("zs-ic", className)}
      style={style}
      strokeWidth={1.75}
      aria-hidden={label ? undefined : true}
      aria-label={label}
      role={label ? "img" : undefined}
      focusable="false"
    />
  );
}
