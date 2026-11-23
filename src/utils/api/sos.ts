import type { CleanResult, PersonaRiskReport, PersonaSelfCheckPatch } from "../../types";
import { isTauri, tauriInvoke } from "./client";
import {
  mockCleanAntigravityAuthCache,
  mockGetPersonaRiskReport,
  mockUpdatePersonaSelfCheck,
} from "./mocks/sos";

/** Получить расчёт проактивного «Индекса риска Persona» (технические сигналы + self-check). */
export async function getPersonaRiskReport(): Promise<PersonaRiskReport> {
  if (isTauri()) {
    return await tauriInvoke<PersonaRiskReport>("get_persona_risk_report");
  }
  return mockGetPersonaRiskReport();
}

/** Обновить чекбоксы поведенческой самооценки Persona и пересчитать индекс риска. */
export async function updatePersonaSelfCheck(
  patch: PersonaSelfCheckPatch,
): Promise<PersonaRiskReport> {
  if (isTauri()) {
    return await tauriInvoke<PersonaRiskReport>("update_persona_self_check", { patch });
  }
  return mockUpdatePersonaSelfCheck(patch);
}

/** Безопасно очистить только кеш входа в ~/.gemini и ~/.antigravity, сохраняя правила и проекты. */
export async function cleanAntigravityAuthCache(): Promise<CleanResult> {
  if (isTauri()) {
    return await tauriInvoke<CleanResult>("clean_antigravity_auth_cache");
  }
  return mockCleanAntigravityAuthCache();
}
