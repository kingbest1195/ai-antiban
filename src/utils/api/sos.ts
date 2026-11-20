import type { PersonaRiskReport, PersonaSelfCheckPatch } from "../../types";
import { isTauri, tauriInvoke } from "./client";
import { mockGetPersonaRiskReport, mockUpdatePersonaSelfCheck } from "./mocks/sos";

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
