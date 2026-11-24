import type {
  GuardPauseStatus,
  InterceptionAction,
  InterceptionBehavior,
  PopupPosition,
  ProviderId,
  RiskInterceptPayload,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";
import {
  clearMockPendingAlert,
  getMockPendingAlert,
  type MockAlertScenario,
  runMockAlert,
} from "./mocks/alert";
import { mockFlags, mockState } from "./mocks/state";

export async function resolveInterception(
  id: string,
  action: InterceptionAction,
  provider: ProviderId,
  scope?: string,
  persistException = false,
): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("resolve_interception", {
      id,
      action,
      provider,
      scope,
      persistException,
    });
  }
  clearMockPendingAlert(id);
  return true;
}

export async function pauseUntilNetworkChange(
  reason?: string | null,
): Promise<GuardPauseStatus> {
  if (isTauri()) {
    return await tauriInvoke<GuardPauseStatus>("pause_until_network_change_cmd", {
      reason: reason ?? null,
    });
  }
  mockFlags.killswitchStatus = true;
  return {
    paused: true,
    mode: "until_network_change",
    gate: null,
    gate_reason: reason ?? "Пауза до следующей смены сети",
    manual_killswitch: false,
  };
}

/** Текущий активный алерт (для окна, открытого после события). В браузере-моке — последний смоделированный. */
export async function takePendingAlert(): Promise<RiskInterceptPayload | null> {
  if (isTauri()) {
    return await tauriInvoke<RiskInterceptPayload | null>("take_pending_alert");
  }
  return getMockPendingAlert();
}

export async function simulateInterception(
  provider: ProviderId = "anthropic",
  scenario?: MockAlertScenario,
): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("simulate_interception", { provider });
  }
  const fromUrl = new URLSearchParams(window.location.search).get("mockAlert");
  runMockAlert(provider, scenario ?? (fromUrl === "slow-enrich" ? "slow-enrich" : "default"));
}

export async function setInterceptionBehavior(
  behavior: InterceptionBehavior,
): Promise<InterceptionBehavior> {
  if (isTauri()) {
    await tauriInvoke("set_interception_behavior_cmd", { behavior });
    return behavior;
  }
  mockState.interception_behavior = behavior;
  return behavior;
}

export async function getInterceptionBehavior(): Promise<InterceptionBehavior> {
  if (isTauri()) {
    return await tauriInvoke<InterceptionBehavior>("get_interception_behavior_cmd");
  }
  return mockState.interception_behavior || "ask_popup";
}

export async function setPopupPosition(position: PopupPosition): Promise<PopupPosition> {
  if (isTauri()) {
    await tauriInvoke("set_popup_position_cmd", { position });
    return position;
  }
  mockState.popup_position = position;
  return position;
}

export async function getPopupPosition(): Promise<PopupPosition> {
  if (isTauri()) {
    return await tauriInvoke<PopupPosition>("get_popup_position_cmd");
  }
  return mockState.popup_position || "top_right";
}

export async function getCustomAiDomains(): Promise<string[]> {
  if (isTauri()) {
    return await tauriInvoke<string[]>("get_custom_ai_domains_cmd");
  }
  return [...(mockState.custom_ai_domains || [])];
}

export async function addCustomAiDomain(domain: string): Promise<string[]> {
  if (isTauri()) {
    return await tauriInvoke<string[]>("add_custom_ai_domain_cmd", { domain });
  }
  const clean = domain.trim().toLowerCase();
  const current = mockState.custom_ai_domains || [];
  if (clean && !current.includes(clean)) {
    mockState.custom_ai_domains = [...current, clean];
  }
  return [...(mockState.custom_ai_domains || [])];
}

export async function removeCustomAiDomain(domain: string): Promise<string[]> {
  if (isTauri()) {
    return await tauriInvoke<string[]>("remove_custom_ai_domain_cmd", { domain });
  }
  const clean = domain.trim().toLowerCase();
  mockState.custom_ai_domains = (mockState.custom_ai_domains || []).filter(
    (d) => d.toLowerCase() !== clean,
  );
  return [...(mockState.custom_ai_domains || [])];
}

export async function toggleNetworkKillswitch(freeze?: boolean): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("toggle_network_killswitch_cmd", {
      freeze: freeze !== undefined ? freeze : null,
    });
  }
  mockFlags.killswitchStatus =
    freeze !== undefined ? freeze : !mockFlags.killswitchStatus;
  return mockFlags.killswitchStatus;
}

export async function getNetworkKillswitchStatus(): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("get_network_killswitch_status_cmd");
  }
  return mockFlags.killswitchStatus;
}

export async function getGuardPauseStatus(): Promise<GuardPauseStatus> {
  if (isTauri()) {
    return await tauriInvoke<GuardPauseStatus>("get_guard_pause_status_cmd");
  }
  return {
    paused: false,
    mode: "none",
    gate: "open",
    gate_reason: null,
    manual_killswitch: mockFlags.killswitchStatus,
    pending_providers: [],
    blocked_providers: [],
  };
}
