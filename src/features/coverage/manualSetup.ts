import type { AppCoverageItem, CoverageSnapshot, ManualStepKey } from "../../types";
import { coverage as copy } from "../../shared/copy/ru";

/** Шаг инструкции: заголовок-действие и одно-два предложения. */
export interface SetupStep {
  title: string;
  text: string;
}

/** Адрес или команда, которые копируются ровно так, как показаны. */
export interface SetupBlock {
  id: string;
  label: string;
  lines: string[];
  /** address — кнопка «Копировать адрес»; command — «Скопировать» для команды терминала. */
  kind: "address" | "command";
}

export interface ManualSetup {
  /** Не больше пяти: требование Steps из дизайн-системы. */
  steps: SetupStep[];
  blocks: SetupBlock[];
  /** Предупреждение над шагами (JetBrains, «запросы идут мимо» у Antigravity). */
  warning: { title: string; text: string } | null;
  hints: string[];
  /** Какой переключатель защиты включает кнопка «Включить защиту»; null — кнопка не нужна. */
  protection: "sysproxy" | "cli" | null;
  /** Шагам нужен адрес, а шлюз ещё не привязан к порту. */
  addressPending: boolean;
}

export const MAX_STEPS = 5;

/** Программы, которые в режиме «Только ИИ-клиенты и IDE» идут напрямую. */
const DIRECT_IN_AI_ONLY = ["node-cli", "python-cli", "curl"];

export const isJetBrains = (app: Pick<AppCoverageItem, "id">) => app.id === "jetbrains";
export const isAntigravity = (app: Pick<AppCoverageItem, "id">) => app.id === "antigravity";

/** Локальные адреса не должны идти через прокси: иначе интерфейс не достучится до локального агента приложения. */
export const LOCAL_NO_PROXY = "localhost,127.0.0.1,::1";

/** Запуск Antigravity 2.x с прокси в окружении (агент игнорирует системный PAC). Адрес — из снимка шлюза. */
export function antigravityLaunch(addr: string): { address: string; mac: string[]; powershell: string[] } {
  const url = `http://${addr}`;
  return {
    address: url,
    mac: [`open -a Antigravity --env HTTPS_PROXY=${url} --env HTTP_PROXY=${url} --env NO_PROXY=${LOCAL_NO_PROXY}`],
    powershell: [`$env:HTTPS_PROXY="${url}"; $env:HTTP_PROXY=$env:HTTPS_PROXY; $env:NO_PROXY="${LOCAL_NO_PROXY}"`],
  };
}

/** Команды для нового терминала с реальным адресом шлюза. Без `setx`: подпись Заставы совпадёт с её же миграцией. */
export function envCommands(addr: string): { unix: string[]; powershell: string[] } {
  return {
    unix: [`export HTTPS_PROXY=http://${addr} HTTP_PROXY=http://${addr}`],
    powershell: [`$env:HTTPS_PROXY="http://${addr}"; $env:HTTP_PROXY=$env:HTTPS_PROXY`],
  };
}

/** Строит инструкцию «Как настроить» по ключам manual_steps, приложению и режиму CLI. Адрес берётся из снимка шлюза, а не из константы. */
export function buildManualSetup(
  app: AppCoverageItem,
  snapshot: Pick<CoverageSnapshot, "gateway_addr" | "pac_url" | "cli_mode"> & Partial<Pick<CoverageSnapshot, "sysproxy_enabled" | "cli_protection_enabled">>,
): ManualSetup {
  const addr = snapshot.gateway_addr;
  const pacUrl = snapshot.pac_url ?? (addr ? `http://${addr}/proxy.pac` : null);
  const keys = app.manual_steps as ManualStepKey[];
  const has = (k: ManualStepKey) => keys.includes(k);
  const aiOnly = snapshot.cli_mode === "ai_only";
  const steps: SetupStep[] = [];
  const blocks: SetupBlock[] = [];
  const hints: string[] = [];
  let protection: ManualSetup["protection"] = null;
  let needsAddress = false;

  const pacBlock = () => {
    needsAddress = true;
    if (pacUrl) blocks.push({ id: "pac", label: copy.steps.pac.blockLabel, lines: [pacUrl], kind: "address" });
  };
  const addrBlock = (label: string, lines: string[] | null) => {
    needsAddress = true;
    if (lines) blocks.push({ id: "addr", label, lines, kind: "address" });
  };

  if (has("enable_protection")) {
    // Защита уже включена: шаг «включите» бессмыслен, остаётся состояние в карточке и остальные шаги.
    if (app.category === "browser" || app.category === "desktop") {
      protection = "sysproxy";
      if (!snapshot.sysproxy_enabled) steps.push(copy.steps.enable.sysproxy);
    } else {
      protection = "cli";
      if (!snapshot.cli_protection_enabled) steps.push(app.category === "cli" && aiOnly ? copy.steps.cli.aiOnlyEnable : copy.steps.enable.cli);
    }
  }

  if (isAntigravity(app) && (has("launch_with_env") || has("enable_system_proxy"))) {
    // Автоматической записи для этого приложения нет: кнопки «Включить защиту» тут не будет.
    if (has("enable_system_proxy")) steps.push(copy.steps.antigravity.systemProxy);
    if (has("launch_with_env")) {
      steps.push(copy.steps.antigravity.launch);
      needsAddress = true;
      if (addr) {
        const launch = antigravityLaunch(addr);
        blocks.push({ id: "launch-mac", label: copy.steps.antigravity.launch.macLabel, lines: launch.mac, kind: "command" });
        blocks.push({ id: "launch-ps", label: copy.steps.antigravity.launch.powershellLabel, lines: launch.powershell, kind: "command" });
        blocks.push({ id: "addr", label: copy.steps.antigravity.launch.addressLabel, lines: [launch.address], kind: "address" });
      }
    }
    hints.push(copy.hints.antigravityAgent);
  } else if (isJetBrains(app)) {
    if (has("jetbrains_proxy_settings")) steps.push(copy.steps.jetbrains.open);
    if (has("set_pac_url")) {
      steps.push(copy.steps.jetbrains.auto);
      pacBlock();
    }
    if (has("set_http_proxy")) {
      steps.push(copy.steps.jetbrains.manual);
      addrBlock(copy.steps.httpProxy.blockLabel, addr ? [addr] : null);
    }
    if (steps.length > 0) steps.push(copy.steps.jetbrains.confirm);
  } else {
    if (has("set_pac_url")) {
      steps.push(copy.steps.pac);
      pacBlock();
    }
    if (has("set_http_proxy")) {
      steps.push(copy.steps.vscode);
      addrBlock(copy.steps.httpProxy.blockLabel, addr ? [`http://${addr}`] : null);
    }
    if (app.category === "browser" && steps.length > 0) steps.push(copy.steps.firefox);
    if (has("set_env_proxy")) {
      if (aiOnly && DIRECT_IN_AI_ONLY.includes(app.id)) steps.push(copy.steps.cli.aiOnlyDirect);
      steps.push(copy.steps.cli.env);
      needsAddress = true;
      if (addr) {
        const cmd = envCommands(addr);
        blocks.push({ id: "env-unix", label: copy.steps.cli.env.unixLabel, lines: cmd.unix, kind: "command" });
        blocks.push({ id: "env-ps", label: copy.steps.cli.env.powershellLabel, lines: cmd.powershell, kind: "command" });
      }
    }
    if (has("reopen_terminal")) steps.push(copy.steps.cli.reopen);
    if (has("restart_app")) steps.push(copy.steps.restart);
  }

  // Ключ, который эта версия не знает, не должен давать пустую инструкцию.
  const known: ManualStepKey[] = [
    "enable_protection",
    "set_pac_url",
    "set_http_proxy",
    "set_env_proxy",
    "restart_app",
    "reopen_terminal",
    "jetbrains_proxy_settings",
    "launch_with_env",
    "enable_system_proxy",
  ];
  if (steps.length === 0 && keys.some((k) => !known.includes(k))) steps.push(copy.steps.generic);

  if (steps.length > 0) {
    hints.unshift(copy.hints.effect);
    if (app.category === "cli") {
      hints.push(copy.mode[snapshot.cli_mode]);
      if (!has("reopen_terminal")) hints.push(copy.hints.reopenTerminal);
    }
  }

  return {
    steps: steps.slice(0, MAX_STEPS),
    blocks,
    warning: setupWarning(app, steps.length > 0),
    hints,
    protection,
    addressPending: needsAddress && !addr,
  };
}

function setupWarning(app: AppCoverageItem, hasSteps: boolean): ManualSetup["warning"] {
  if (!hasSteps) return null;
  if (isJetBrains(app)) return copy.steps.jetbrains.warning;
  if (isAntigravity(app) && app.bypass_suspected) return copy.antigravity.bypass;
  return null;
}
