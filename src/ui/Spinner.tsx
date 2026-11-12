import { cx } from "./cx";

export interface SpinnerProps {
  /** Размер в px; по умолчанию 14 (в строку с текстом). */
  size?: number;
  className?: string;
}

/** Индикатор ожидания: вращающееся кольцо без текста. Подпись «Проверяем…» всегда рядом, сам индикатор скрыт от скринридера. */
export function Spinner({ size = 14, className }: SpinnerProps) {
  return <span aria-hidden="true" className={cx("zs-spinner", className)} style={{ width: size, height: size }} />;
}
