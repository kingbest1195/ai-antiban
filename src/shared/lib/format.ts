/** Число с пробелами между разрядами: «5 262». */
export function formatNumber(value: number): string {
  try {
    return value.toLocaleString("ru-RU");
  } catch {
    return String(value);
  }
}

/** «из 13 проверок», «из 1 проверки»: форма слова после «из» (родительный падеж). */
export function checksWord(total: number): string {
  const mod10 = total % 10;
  const mod100 = total % 100;
  if (mod10 === 1 && mod100 !== 11) return "проверки";
  return "проверок";
}

/** Время события шлюза «14:03:27». Метка может быть в секундах или в миллисекундах. */
export function formatClock(timestamp: number): string {
  const ms = timestamp > 1e11 ? timestamp : timestamp * 1000;
  try {
    return new Date(ms).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return "";
  }
}
