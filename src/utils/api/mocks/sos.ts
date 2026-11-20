import type {
  PersonaRiskFactor,
  PersonaRiskLevel,
  PersonaRiskReport,
  PersonaSelfCheck,
  PersonaSelfCheckPatch,
} from "../../../types";
import { currentMockExitInfo } from "./cleanRoom";
import { mockFlags, mockState } from "./state";

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function ensureSelfCheck(): PersonaSelfCheck {
  if (!mockState.persona_self_check) {
    mockState.persona_self_check = {
      bought_or_grey_account: false,
      virtual_sms_used: false,
      reseller_payment_used: false,
      multi_account_same_browser: false,
    };
  }
  return mockState.persona_self_check;
}

export function levelForScore(score: number): PersonaRiskLevel {
  if (score >= 55) return "high";
  if (score >= 25) return "medium";
  return "low";
}

export function mockGetPersonaRiskReport(): PersonaRiskReport {
  const selfCheck = { ...ensureSelfCheck() };
  const exit = currentMockExitInfo();
  const tainted = Boolean(mockState.clean_room?.tainted_ips?.[exit.ip]);
  const now = nowSec();
  const cooldownActive =
    typeof mockState.ip_change_cooldown_until === "number" &&
    mockState.ip_change_cooldown_until > now;
  const ruOsTz =
    mockFlags.osTzCurrent === "Europe/Moscow" || mockFlags.osTzCurrent === "Europe/Minsk";

  const factors: PersonaRiskFactor[] = [
    {
      id: "tech_ip_or_cooldown",
      source: "technical",
      label: "Смена ASN/IP < 4ч или скомпрометированный IP",
      detail: tainted
        ? `IP ${exit.ip} помечен как скомпрометированный.`
        : cooldownActive
          ? "Действует 4-часовой таймер после смены аккаунта."
          : mockFlags.scenario === "ru"
            ? "Выходной IP относится к РФ."
            : "Стабильный выходной адрес без резких прыжков.",
      weight: 40,
      active: tainted || cooldownActive || mockFlags.scenario === "ru",
      fix_target: "switch_route",
    },
    {
      id: "tech_no_pin",
      source: "technical",
      label: "Не закреплён постоянный IP",
      detail: mockState.pinned_ip
        ? `Закреплён IP ${mockState.pinned_ip}.`
        : "Без закрепления IP возможны тихие смены выходного узла.",
      weight: 15,
      active: !mockState.pinned_ip,
      fix_target: "pin_ip",
    },
    {
      id: "tech_os_tz_ru",
      source: "technical",
      label: "Часовой пояс ОС РФ/РБ без изоляции",
      detail: ruOsTz
        ? `Часовой пояс ОС: ${mockFlags.osTzCurrent}.`
        : `Часовой пояс ОС согласован (${mockFlags.osTzCurrent}).`,
      weight: 20,
      active: ruOsTz && !mockFlags.syncAiTz,
      fix_target: "sync_os_tz",
    },
    {
      id: "tech_unprotected_browser",
      source: "technical",
      label: "Защита браузера выключена",
      detail: mockFlags.sysproxyActive
        ? "Системная защита браузеров активна."
        : "Защита выключена — трафик браузера идёт напрямую.",
      weight: 15,
      active: !mockFlags.sysproxyActive,
      fix_target: "open_clean_room",
    },
    {
      id: "self_bought_or_grey_account",
      source: "self_check",
      label: "Аккаунт куплен с рук / на бирже",
      detail: "Чужие или массово зарегистрированные аккаунты чаще попадают под Persona KYC.",
      weight: 45,
      active: selfCheck.bought_or_grey_account,
      fix_target: "open_clean_room",
    },
    {
      id: "self_virtual_sms_used",
      source: "self_check",
      label: "Использован одноразовый виртуальный SMS-номер",
      detail: "Дешёвые VoIP/SMS-активаторы массово помечены антифродом.",
      weight: 30,
      active: selfCheck.virtual_sms_used,
      fix_target: "open_bunker",
    },
    {
      id: "self_reseller_payment_used",
      source: "self_check",
      label: "Оплата через перекупа (Playerok / FunPay / чужой Apple Pay)",
      detail: "Серый биллинг — один из главных триггеров перманентного бана.",
      weight: 45,
      active: selfCheck.reseller_payment_used,
      fix_target: "open_bunker",
    },
    {
      id: "self_multi_account_same_browser",
      source: "self_check",
      label: "Вход в несколько аккаунтов из одного обычного браузера",
      detail: "Используйте изолированное окно «Чистой комнаты» для каждого нового аккаунта.",
      weight: 35,
      active: selfCheck.multi_account_same_browser,
      fix_target: "open_clean_room",
    },
  ];

  const rawScore = factors.reduce((sum, f) => sum + (f.active ? f.weight : 0), 0);
  const score = Math.min(100, Math.max(0, rawScore));
  const level = levelForScore(score);

  const recommended_actions: string[] = [];
  if (level === "high") {
    recommended_actions.push("Сделайте немедленный локальный бэкап в «Бункере данных».");
    recommended_actions.push("Переходите на новый аккаунт только через «Чистую комнату».");
  } else if (level === "medium") {
    recommended_actions.push("Устраните активные факторы риска до следующей оплаты или сессии.");
  }

  return {
    score,
    level,
    factors,
    self_check: selfCheck,
    recommended_actions,
    evaluated_at: now,
  };
}

export function mockUpdatePersonaSelfCheck(patch: PersonaSelfCheckPatch): PersonaRiskReport {
  const current = ensureSelfCheck();
  if (patch.bought_or_grey_account !== undefined) {
    current.bought_or_grey_account = patch.bought_or_grey_account;
  }
  if (patch.virtual_sms_used !== undefined) {
    current.virtual_sms_used = patch.virtual_sms_used;
  }
  if (patch.reseller_payment_used !== undefined) {
    current.reseller_payment_used = patch.reseller_payment_used;
  }
  if (patch.multi_account_same_browser !== undefined) {
    current.multi_account_same_browser = patch.multi_account_same_browser;
  }
  return mockGetPersonaRiskReport();
}
