import type { PersonaSelfCheck } from "./state";

export type { PersonaSelfCheck };

export type PersonaRiskLevel = "low" | "medium" | "high";

export type PersonaRiskFactorSource = "technical" | "self_check";

export type PersonaRiskFixTarget =
  | "pin_ip"
  | "sync_os_tz"
  | "open_clean_room"
  | "clean_cache"
  | "open_bunker"
  | "switch_route"
  | (string & {});

export interface PersonaRiskFactor {
  id: string;
  source: PersonaRiskFactorSource;
  label: string;
  detail: string;
  weight: number;
  active: boolean;
  fix_target: PersonaRiskFixTarget | null;
}

export interface PersonaRiskReport {
  score: number;
  level: PersonaRiskLevel;
  factors: PersonaRiskFactor[];
  self_check: PersonaSelfCheck;
  recommended_actions: string[];
  evaluated_at: number;
}

export type PersonaSelfCheckPatch = Partial<PersonaSelfCheck>;
