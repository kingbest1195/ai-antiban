# Спецификация Zastava v3.0.0 (`spec-v3.0.0.md`)

> **Статус:** Архитектурная спецификация (Implementation-Ready Blueprint) поверх релиза `v2.3.0`.
> **Стек:** Rust (`edition = "2024"`) + Tauri v2 (`460×660` main, `440×470` `alert-popup`) + React 19 / TypeScript / Vite 8 / Tailwind CSS 4.
> **Архитектурные ограничения:** 4-слойная Clean Hexagonal + Vertical Domain Slices ([`CONSTITUTION.md`](CONSTITUTION.md), [`scripts/check-architecture.mjs`](scripts/check-architecture.mjs)): **≤ 350** строк soft / **≤ 500** строк hard на prod-файл, **≤ 700** строк на test-файл, пустой `LEGACY_ALLOWLIST`, `0` сырых hex/rgb в компонентах (`pnpm lint:hex`).
> **Git-инвариант:** Шаблон `spec-*.md` игнорируется через `.gitignore:19` — спецификация хранится локально в корне репозитория и не коммитится, если не принято иное решение владельца.

---

## Содержание

0. [Архитектурный фундамент и Zero-Regression Baseline (`v2.3.0 → v3.0.0`)](#0-архитектурный-фундамент-и-zero-regression-baseline-v230--v300)
1. [Executive Summary и конкурентное позиционирование (`v3.0.0`)](#1-executive-summary-и-конкурентное-позиционирование-v300)
2. [Pillar 1 — «Чистая комната»: Pre-Flight аудит хвостов, изолированная браузерная песочница и 4-шаговый Launchpad](#2-pillar-1--чистая-комната-pre-flight-аудит-хвостов-изолированная-браузерная-песочница-и-4-шаговый-launchpad)
3. [Pillar 2 — «SOS-Верификация + Бесплатный Бункер данных + Индекс риска Persona»](#3-pillar-2--sos-верификация--бесплатный-бункер-данных--индекс-риска-persona)
4. [Pillar 3 — «Одушевлённый» UI/UX-редизайн: маскот Заставы, навигация «Разделы», онбординг, анимации, иконки и трей](#4-pillar-3--одушевлённый-uiux-редизайн-маскот-заставы-навигация-разделы-онбординг-анимации-иконки-и-трей)
5. [Pillar 4 — Все 9 подтверждённых баг-фиксов `v2.3.0` (Root Cause, File:Line, Fix & Tests)](#5-pillar-4--все-9-подтверждённых-баг-фиксов-v230-root-cause-fileline-fix--tests)
6. [Pillar 5 — Миграция `AppState`, поэтапный план внедрения, E2E-матрица верификации и DoD](#6-pillar-5--миграция-appstate-поэтапный-план-внедрения-e2e-матрица-верификации-и-dod)

---

## 0. Архитектурный фундамент и Zero-Regression Baseline (`v2.3.0 → v3.0.0`)

### 0.1. Распределение новых модулей по 4 слоям (`src-tauri/src/` и `src/`)

Все новые возможности `v3.0.0` строго подчиняются 4-слойной иерархии из [`spec-v2.3.0.md`](spec-v2.3.0.md) и `scripts/check-architecture.mjs`:

```text
Layer 3: Delivery / Shell
  src-tauri/src/app/{mod.rs, watchers.rs}        — глобальный listener cowork_guard (вкл. Service Running без Claude) + hooks
  src-tauri/src/commands/{clean_room.rs, bunker.rs, sos.rs, routes.rs, claude.rs, sysproxy/*}
  src-tauri/src/tray/{mod.rs, events.rs}          — 4-й цвет TrayColor::Gray + единый toggle_sysproxy с CLI/os_tz/actual emit
    │
    ▼
Layer 2: Domain Services & Platform Adapters (без импортов commands::*, app::*, tray::*)
  src-tauri/src/clean_room/{mod.rs, detector.rs, browser_sandbox.rs, browser_discovery.rs, tz_guard.rs}
  src-tauri/src/bunker/{mod.rs, scheduler.rs, cursor_export.rs, web_helper.rs, retention.rs}
  src-tauri/src/proxy/server/{mod.rs, connect.rs, http_handler.rs, tunnel.rs} — alias-изоляция без transit_tunnel fallback
  src-tauri/src/auditor/{cache_cleaner.rs, leaks.rs, persona_risk.rs, profile_switcher/device_registry.rs, claude_exporter/*, probes/whoami/verdict.rs, probes/stun.rs}
  src-tauri/src/sysproxy/macos/apply.rs           — дедупликация диагностики
    │
    ▼
Layer 1: State & Routing Contracts
  src-tauri/src/state/{schema.rs, migration.rs, persistence.rs, routes.rs} — v3 schema, state.v2.bak.json
  src-tauri/src/routing/net/{mod.rs, dns.rs}      — public hickory + DoH A/AAAA fallback, is_gateway_loop для alias
    │
    ▼
Layer 0: Core Primitives (0 зависимостей на Tauri и доменные сервисы)
  src-tauri/src/core/net_safety.rs                — IPv6 Fake-IP fc00::/18 + alias-порты в validate_tunnel_target
```

На фронтенде (`src/`) сохраняется строгая изоляция `invoke()` / `listen()` внутри `src/utils/api/`:
* Новые API-модули: `src/utils/api/cleanRoom.ts`, `src/utils/api/bunker.ts`, `src/utils/api/sos.ts` (+ реэкспорты в `src/utils/api.ts`).
* Новые/перенесённые фичи: `src/features/shell-v3/` (портированный и доработанный каркас «Разделы» с реальным `navStack`), `src/features/mascot/`, `src/features/clean-room/`, `src/features/sos/`, `src/features/bunker/`, обновлённый `src/features/onboarding/` (5 шагов) и `WhatsNewSheet` / `HintCard`.

### 0.2. Зафиксированный Zero-Regression Baseline из `v2.3.0`

При интеграции интерфейсных решений из прототипа `/Users/putiniye/Downloads/Telegram Desktop/Вариант C 2/` **запрещены регрессии** следующих механизмов `v2.3.0`:

| Механизм `v2.3.0` | Где реализован сейчас | Инвариант для `v3.0.0` |
|---|---|---|
| `CooldownBanner` (4h таймер после `safe_logout_claude`) | `src/features/overview/CooldownBanner.tsx`, `state/schema.rs:274` (`ip_change_cooldown_until`) | Обязательно рендерится в приоритетном `AlertStrip` на Home Hub (с push в `navStack` по клику) и в `CleanRoom` / `Аккаунты, Бункер и SOS`. |
| Модульный `ConnectScreen` (`ProviderRoutesSection` + `RouteListSection` + `handleResetActiveProfileRoute`) | `src/features/connect/{ConnectScreen.tsx, ProviderRoutesSection.tsx, RouteListSection.tsx}` | Прототип `Вариант C 2/.../ConnectScreen.tsx` был монолитным (`711` строк, не проходит `PROD_HARD_LIMIT=500`!). В `v3.0.0` `layout="sales"` строится поверх модульного `v2.3.0` `ConnectScreen` с сохранением `ProviderRoutesSection` и учётом `profile_route_id` в `getAffectedProvidersForRoute` + отдельным подтверждением `handleResetActiveProfileRoute`. |
| `executeAllowSequence` + `verify_and_unblock_provider` | `src/features/overview/OverviewScreen.tsx:101-111,158-165` | Сохраняется строгое последовательное снятие блока `unblock` → `allow` без гонок. |
| `CopyErrorLogButton` на опасных баннерах и тостах | `src/shared/components/CopyErrorLogButton.tsx`, `src/app/AppShell.tsx:185,329` | Сохраняется в `NotificationStack` (`t.tone === "danger"`) и в `routeUnavailableBanner`. |
| Постоянные исключения `trusted_exceptions` и тосты | `src/shared/copy/ru/toasts.ts:15-17,43-44`, `state/schema.rs:212` | Прототип `Вариант C 2/.../toasts.ts` содержал устаревший текст «до конца сессии». В `v3.0.0` сохраняются формулировки `v2.3.0` про `trusted_exceptions` («Постоянное исключение можно удалить в Настройках»). |
| Fail-closed маршрутизация & `TRAVEL_ASN_JUMP_SAME_COUNTRY` | `proxy/server/connect.rs:58-95`, `proxy/guard/policy.rs:230-280`, `state/routes.rs:205-219` | Отключение/удаление маршрута никогда не сбрасывает трафик в `Direct` автоматически без подтверждения пользователя. |
| `resolve_interception` с `AllowErrorCode` | `src/features/alert/alertState.ts:86-129`, `commands/interception/helpers.rs` | Неделегируемая классификация ошибок `Allow` только по `AllowErrorCode`. |

---

## 1. Executive Summary и конкурентное позиционирование (`v3.0.0`)

### 1.1. Стратегическая цель

Релиз **Zastava v3.0.0** решает две задачи:
1. **Продуктовое доминирование на рынке RU AI-antiban:** закрыть весь жизненный цикл безопасного пользования зарубежными AI (Claude, ChatGPT, Gemini, Cursor) — от *«чистого запуска нового аккаунта без следов старого бана»* («Чистая комната») до *«выживания без потери кода/контекста и денег при запросе Persona KYC»* («Аккаунты, Бункер и SOS»).
2. **Рост органического охвата (`300 → 1,000+` пользователей, фокус на Threads и Telegram):** переход от сухого «инженерного прокси-тумблера» к понятному «одушевлённому» продукту со сторожевым псом-маскотом, визуальным прогрессом и **нулевой ценой (`0 ₽`, MIT Open Source)** при полном паритете **Windows (`68%` установок)** и **macOS**.

### 1.2. Конкурентная матрица (`v3.0.0` vs рынок)

| Возможность | **Zastava v3.0.0** | **Kordon / Kordon Plus** | **ExitPin** | **Dolphin Anty** |
|---|---|---|---|---|
| Цена | **0 ₽ (MIT Open Source)** | `149–990 ₽/мес` (закрытый код) | `299 ₽/мес` | `$30–$89/мес` |
| Платформы | **Windows (68%) + macOS** | Ограничено / проприетарно | **Только macOS** | Win / macOS |
| Сетевой Kill-Switch + Anti-Fraud аудит | 14 проверок + PAC/HTTP CONNECT + 4h ASN-jump guard | Базовый прокси/роутинг | Базовая проверка | Нет защиты Desktop/IDE/CLI |
| Защита CLI и IDE (Cursor, Claude Code, Antigravity) | `AiOnly` + `GlobalTerminal` + TZ/Locale spoofing | Нет / частично | Нет | Нет |
| «Чистая комната» + изолированное окно браузера | **Встроено (MSIX-aware + Chromium sandbox)** | Нет | Нет | Отдельный тяжёлый антидетект |
| Локальный «Бункер данных» (автобэкап + `restore_prompt.md`) | **Бесплатно, 100% локально** (Claude + Cursor + web helper) | **Платно (`299 ₽/мес` Plus)** в облаке/подписке | Нет | Нет |
| «SOS-Верификация» + Plan B (BYOK / OpenRouter за 2 мин) | **Интерактивное дерево + 1-click экспорт** | Нет | Нет | Нет |

### 1.3. Строгий устав безопасности и легальности (Safety & Legal Charter)

Zastava v3.0.0 **категорически НЕ реализует** и **запрещает** следующие практики:
* **Zero Document Forgery / Zero KYC Bypass:** никаких генераторов документов, дипфейков, подмены камеры/Liveness или советов по обходу Persona чужими/поддельными паспортами. При запросе Persona с только РФ-доками система даёт честный красный `STOP` и переводит пользователя на **Plan B (официальный API / OpenRouter BYOK)**.
* **Zero Credential / Keychain Scraping:** «Детектор хвостов» работает строго **read-only по метаданным и существованию файлов** (`fs::metadata` / `exists()` / `tasklist`/`pgrep`). Приложение **никогда** не читает Windows Credential Manager, DPAPI-ключи, `Cookies` SQLite-строки, macOS Keychain или содержимое чужих сессионных токенов, чтобы не вызывать срабатываний Windows Defender / SmartScreen / macOS TCC.
* **100% Local-First Privacy:** «Бункер данных» хранит снапшоты исключительно на локальном диске пользователя с `0o600` правами на Unix и санитизацией при экспорте.

---

## 2. Pillar 1 — «Чистая комната»: Pre-Flight аудит хвостов, изолированная браузерная песочница и 4-шаговый Launchpad

### 2.1. Read-only «Детектор хвостов» (`src-tauri/src/clean_room/detector.rs`)

Перед регистрацией нового аккаунта или входом после бана пользователь запускает аудит **«Чистой комнаты»** (доступен на Windows и macOS).

#### 2.1.1. Источники сканирования (строго `metadata` / `exists` / `is_running`, без чтения секретов)

| Категория | Windows (`68%` установок) | macOS | Критичность |
|---|---|---|---|
| **Браузерные профили** (следы прошлых банов) | `%LOCALAPPDATA%\Google\Chrome\User Data`, `Microsoft\Edge\User Data`, `BraveSoftware\Brave-Browser\User Data`, `Yandex\YandexBrowser\User Data` | `~/Library/Application Support/{Google/Chrome,Microsoft Edge,BraveSoftware/Brave-Browser,Yandex/YandexBrowser}` | Инфо / Warn (для личного браузера — рекомендуется изолированное окно Заставы) |
| **Claude Desktop (Classic + MSIX)** | `%APPDATA%\Claude` **И** `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude` | `~/Library/Application Support/Claude` | **Critical**, если есть `Cookies`, `Network/Cookies`, `Local Storage`, `ant-device-registry.json`, `ccd-ids.json` или `dispatch-footprint-census.json` |
| **ChatGPT Desktop (Classic + MSIX)** | `%APPDATA%\ChatGPT` **И** `%LOCALAPPDATA%\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT` | `~/Library/Application Support/ChatGPT` | **Critical**, если целевой провайдер `openai` и есть `Cookies` / `Local Storage` |
| **Cursor IDE** | `%APPDATA%\Cursor` (наличие auth/storage DB без чтения токенов) | `~/Library/Application Support/Cursor` | **Warning** (рекомендация закрыть/перепривязать перед сменой аккаунта) |
| **Запущенные процессы** | `chrome.exe`, `msedge.exe`, `brave.exe`, `claude.exe`, `ChatGPT.exe`, `Cursor.exe` | `Claude`, `ChatGPT`, `Cursor` | **Critical** для целевого desktop-клиента (файл-локи на Windows) |
| **Коллизия IP / истории** | Сравнение текущего выходного IP + ASN из `NetworkTelemetry` с `AppStateData.ip_history` (`state/schema.rs:205`) и **новым списком `tainted_ips`** + `profiles.json` (`profiles_store.rs`) | Идентично | **Critical**, если текущий exit IP помечен как `tainted` (бывший бан) или использовался другим профилем за последние 30 дней без сброса |
| **Сетевая и ОС-гигиена** | Текущий `RiskReport` (`geo_matrix`, `ipv6`, `dns`, `udp_stun`, `timezone`, `locale_hygiene`) + `os_tz` статус на Windows | Идентично (`timezone` в браузере может передаваться через `TZ=<iana>`, но ОС-локали и утечки IPv6/DNS/STUN обязательны) | **Critical**, если `geo` в санкционном списке, утечка IPv6/DNS/STUN, `dnsbl` red, или на Windows OS TZ = РФ/РБ (`is_russian_or_belarusian_timezone`) |

#### 2.1.2. Rust-контракты (`src-tauri/src/clean_room/mod.rs`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceSeverity {
    Ok,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanRoomFixAction {
    CleanAppCache { provider: String },        // вызывает MSIX-aware clean_ai_app_cache (Bug #1)
    SyncOsTimezone { target_iana: String },    // os_tz::sync_os_timezone (особенно критично на Windows)
    SwitchRouteOrVpn,                          // навигация в «VPN и ключи» (при tainted / RU IP)
    CloseRunningApp { process_name: String },  // мягкое закрытие перед чисткой
    AcknowledgeSandboxIsolation,               // выбор изолированного браузера вместо личного
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanRoomFinding {
    pub id: String,
    pub category: String,          // "desktop_traces" | "ip_collision" | "network_leak" | "os_tz_locale" | "browser"
    pub title: String,
    pub detail: String,
    pub severity: TraceSeverity,
    pub path_hint: Option<String>, // маскированный/относительный путь без секретов
    pub fix_action: Option<CleanRoomFixAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanRoomAuditReport {
    pub checked_at: u64,
    pub exit_ip: Option<String>,
    pub exit_country: Option<String>,
    pub exit_timezone: Option<String>,
    pub ip_is_tainted: bool,
    pub os_tz_matches_exit: bool,
    pub findings: Vec<CleanRoomFinding>,
    pub critical_count: usize,
    pub warning_count: usize,
    /// Hard Readiness Gate: true ТОЛЬКО когда critical_count == 0
    pub ready_to_launch: bool,
}
```

#### 2.1.3. Hard Readiness Gate (жёсткая блокировка запуска)

* Кнопка **«Открыть чистое окно»** (`launch_clean_browser`) физически заблокирована (`disabled` + `aria-disabled="true"`) на UI **и** повторно валидируется в Tauri-команде `launch_clean_browser` на бэкенде, пока `ready_to_launch == false` (`critical_count > 0`) **или** активен `manual_killswitch == true` (в состоянии ручной блокировки запуск окна песочницы запрещён).
* Внутри каждого красного `CleanRoomFinding` отображается **1-click fix кнопка**:
  * MSIX-совместимая очистка следов (`clean_ai_app_cache`, строго сохраняющая `claude_desktop_config.json` и `.claude/settings.json`).
  * На Windows при `TIMEZONE_LEAK_RU` / `TIMEZONE_MISMATCH`: 1-click кнопка `sync_os_timezone` (через существующий `os_tz/sync.rs:50`) с авто-восстановлением при выходе.
  * При `ip_is_tainted == true` или санкционном IP: кнопка перехода к смене ключа/сервера.

---

### 2.2. One-Click изолированная браузерная песочница (`browser_discovery.rs`, `browser_sandbox.rs`)

Позволяет открыть **чистое изолированное окно Chromium** поверх работающей системы, не закрывая личный браузер пользователя (Сбербанк, Ozon, личная почта и старые куки остаются нетронутыми и не зависают).

#### 2.2.1. Обнаружение браузера (`browser_discovery.rs`)

Поддерживаемые движки (в порядке приоритета): `chrome`, `edge`, `brave` (опционально пользователь может выбрать из найденных; при `0` найденных браузеров отображается человечный `EmptyState` со ссылкой на официальное скачивание Chrome / Edge):
* **Windows (`68%`):**
  1. Чтение `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{chrome.exe,msedge.exe,brave.exe}` и `HKCU\...` (через `win_reg`).
  2. Fallback-пути: `%ProgramFiles%\Google\Chrome\Application\chrome.exe`, `%ProgramFiles(x86)%`, `%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe`, `%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe`, `%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe`.
* **macOS:**
  1. `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`
  2. `/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge`
  3. `/Applications/Brave Browser.app/Contents/MacOS/Brave Browser`
  4. `~/Applications/...` fallback.

#### 2.2.2. Изолированный запуск, hardened-флаги Chromium и полная изоляция алиаса

Каждый профиль «Чистой комнаты» имеет собственный каталог `<app_data_dir>/clean-profiles/<profile_id>/` (создаётся с правами `0o700` на Unix).

**Обязательные hardened-аргументы запуска процесса** (через `Command::new(binary)` с отключённой консолью на Windows):
```text
--user-data-dir=<app_data_dir>/clean-profiles/<profile_id>
--proxy-server=http://127.0.0.1:<bound_alias_port>
--proxy-bypass-list="127.0.0.1;[::1]"
--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
--disable-quic
--disable-features=DnsOverHttps
--disable-background-networking
--no-pings
--force-webrtc-ip-handling-policy=disable_non_proxied_udp
--lang=en-US
--no-first-run
--no-default-browser-check
--disable-sync
```
*(Критично: контрпродуктивный флаг `--disable-features=WebRtcHideLocalIpsWithMdns` **УДАЛЁН** и запрещён, чтобы не отключать скрытие локальных LAN IP через mDNS; `--host-resolver-rules` и `--disable-quic`/`--disable-features=DnsOverHttps` гарантируют, что DNS, HTTP/3 и DoH не утекут через ISP РФ в обход `--proxy-server`, даже если системный `sysproxy` выключен или OS-политики не применились.)*

**Fail-Closed предзапись Preferences и lifecycle окна:**
1. Перед запуском процесса `browser_sandbox.rs` атомарно записывает/обновляет `<profile>/Default/Preferences`, прописывая:
   * `"proxy": {"mode": "fixed_servers", "server": "http://127.0.0.1:<bound_alias_port>"}`
   * `"dns_over_https": {"mode": "off"}`
   Это гарантирует, что даже случайный ручной перезапуск профиля вне Zastava (или при закрытом приложении) останется fail-closed без утечки в `DIRECT`.
2. Если `manual_killswitch == true`, `launch_clean_browser` отклоняет запуск с явной ошибкой блокировки.
3. Если окно данного `profile_id` уже запущено на устаревшем/другом `bound_alias_port`, `launch_clean_browser` корректно закрывает старый процесс профиля и перезапускает его на актуальном порту.

> **Полная изоляция трафика per-profile loopback alias (`ProxyManager` + `connect.rs` + `http_handler.rs` + `tunnel.rs`):**
> * Изолированное окно **напрямую** привязано к выделенному per-profile loopback listener alias (`127.0.0.1:<ephemeral_port>` внутри `ProxyManager`), жёстко связанному с `clean_profile.bound_route_id`. Это обеспечивает физическую изоляцию нескольких параллельных окон (окно A на US-ключе и окно B на NL-ключе работают одновременно без конфликтов).
> * **Инвариант P0 (Zero Non-AI Split-IP Leak):** Per-profile listener alias **ОБЯЗАН** направлять **ВЕСЬ** трафик окна — **как AI, так и non-AI `CONNECT`** (Stripe, `withpersona.com`, Cloudflare Turnstile, Apple/Auth0 OAuth, `ipinfo.io`), а также **`plain HTTP`** (`http_handler.rs`) — строго через `bound_route_id` (или через `FollowGate` для явного `Direct`). **Любой fallback в `transit_tunnel` / `RouteSelection::Direct` на алиасе строго запрещён**; при выключенном или недоступном маршруте алиас возвращает fail-closed `403`/`502`.
> * **Anti-SSRF регистрация alias-портов:** Все активные ephemeral-порты per-profile алиасов динамически регистрируются в `validate_tunnel_target` (`core/net_safety.rs:133-136`) и `is_gateway_loop` (`routing/net/mod.rs:70-74`) наравне с `bound_proxy_port`, `8899`, `8900`.

#### 2.2.3. Кроссплатформенная обработка Timezone (Win vs Mac)

* **macOS:** `Command::env("TZ", &target_iana)` передаётся дочернему процессу Chromium (`Google Chrome` / `Edge` / `Brave`) — `Intl.DateTimeFormat().resolvedOptions().timeZone` и `Date.getTimezoneOffset()` внутри песочницы **автоматически** соответствуют `target_iana` без изменения часового пояса всей macOS. (При этом для чистого запуска без запуска системного Chrome достаточно `--user-data-dir`, так как новый `user-data-dir` стартует отдельный процесс Chromium с новым `TZ` env!).
* **Windows (`68%`):** Chromium на Windows игнорирует переменную окружения `TZ` и читает часовой пояс напрямую из реестра/Win32 API (`GetDynamicTimeZoneInformation`). Поэтому на Windows:
  1. `CleanRoomAuditReport.os_tz_matches_exit` проверяет соответствие OS TZ и exit IP TZ.
  2. Если они не совпадают (или OS TZ в РФ/РБ), **Hard Readiness Gate** блокирует запуск до 1-click вызова `sync_os_timezone` (`os_tz/sync.rs:50`), который атомарно сохраняет `os_tz_baseline.json` и безопасно восстанавливает исходный часовой пояс при закрытии песочницы или выключении защиты (`restore_if_synced_on_disable`).

#### 2.2.4. Управление жизненным циклом профилей песочницы

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CleanProfileStatus {
    Active,
    WarmingUp,
    Ready,
    Tainted, // забанен — IP/подсеть попадают в tainted_ips
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanRoomProfile {
    pub id: String,
    pub label: String,
    pub provider: String,             // "anthropic" | "openai" | "gemini"
    pub browser_engine: String,       // "chrome" | "edge" | "brave"
    pub bound_route_id: Option<String>,
    pub last_exit_ip: Option<String>,
    pub last_exit_country: Option<String>,
    pub status: CleanProfileStatus,
    pub created_at: u64,
    pub last_opened_at: Option<u64>,
    pub warmup_started_at: Option<u64>,
    pub launchpad_step: u8,           // 1..=4
    pub completed_checklist: Vec<String>,
}
```
* Операции: `list_clean_profiles`, `create_clean_profile`, `launch_clean_browser(profile_id)`, `mark_clean_profile_tainted(profile_id, reason)`, `delete_clean_profile(profile_id)` (удаляет каталог `clean-profiles/<id>` с проверкой path-traversal и записью `last_exit_ip` в `tainted_ips` при бане).

---

### 2.3. Stateful 4-Step New-Account Launchpad (вывод скрытого `SubscriptionScreen` на первый план)

В `v2.3.0` модуль `src/features/subscription/` (`SubscriptionScreen.tsx`, `CardCheck.tsx`, `AddressCard.tsx`, `Warmup.tsx`) был спрятан в бургер-меню «Ещё» (`useAppShellController.ts:304`, рендер в `src/app/AppShell.tsx:87-103`). В `v3.0.0` он становится видимым без блуждания:
* Внутри **«Чистой комнаты»** доступны две понятные подвкладки/ярлыка: **«Новый аккаунт (4 шага)»** и прямой быстрый вход **«Оплата и прогрев»** (чтобы пользователь с уже готовым аккаунтом мог сразу открыть **«Проверка карты (BIN) и адрес США 0%»** без прохождения Шагов 1–2).
* Дополнительно быстрая кнопка открытия **«Проверка карты (BIN) и адрес США 0%»** размещается прямо в `Проверки и гайды → Гайд по оплате` (с обязательным исправлением устаревшей строки `src/shared/copy/ru/guides.ts:172`, упоминающей *«во вкладке „Биллинг“»*).
* Состояние Launchpad сохраняется в `AppStateData.clean_room` (с обратной совместимостью по `AppStateData.warmup_started_at` в `state/schema.rs:219`):

1. **Шаг 1: Чистая комната (`step: 1`)**
   * Проход «Детектора хвостов» → зелёный Hard Readiness Gate → создание/выбор чистого профиля (**«Браузерная песочница (для веба)»** — в UI явно отделяется от *«Профилей Claude Desktop»* в разделе «Аккаунты, Бункер и SOS») и привязка выделенного маршрута (ключа Заставы или личного VPS).
2. **Шаг 2: Регистрация в песочнице (`step: 2`)**
   * Кнопка **«Открыть чистое окно»** запускает изолированный браузер на целевом URL (`claude.ai` / `chatgpt.com` / `aistudio.google.com`).
   * Встроенная памятка гигиены регистрации (интерактивный чек-лист, прогресс сохраняется):
     * Почта: только зарубежные провайдеры (`gmail.com`, `proton.me`, `icloud.com`, корпоративный домен) — **запрет на `.ru` / `.by` домены** (`mail.ru`, `yandex.ru`, `rambler.ru`).
     * Телефон для SMS: физическая SIM/eSIM или доверенный реальный номер страны выхода — **жёсткое предупреждение против дешёвых одноразовых VoIP/SMS-активаторов** (высокий процент мгновенного флага Persona).
3. **Шаг 3: Автопилот прогрева 96ч (`step: 3`)**
   * Интеграция `Warmup.tsx` (`WARMUP_TARGET_HOURS = 96`) + привязка к `CleanRoomProfile.warmup_started_at` (и `state.warmup_started_at` для legacy-совместимости).
   * Сохраняемый чек-лист естественной активности (первые бесплатные диалоги, отсутствие массовой генерации/автоматизации сразу после регистрации, единый IP).
   * **Честный дисклеймер прямо в карточке:** 96 часов — это дисциплинарный буфер, а не «волшебная защита». Реальные триггеры бана — **грязный общий IP (смена ASN/страны)** и **плохой биллинг/карта/реселлер**.
4. **Шаг 4: Шлюз оплаты (`step: 4`)**
   * Интеграция `CardCheck.tsx` (локальный + `bin_checker/mod.rs` BIN-аудит с проверкой совпадения страны карты и страны выходного IP: `IP country ≈ Card country`) и `AddressCard.tsx` (5 безналоговых штатов США: `DE`, `OR`, `NH`, `MT`, `AK` для Stripe AVS). Кнопка перехода к гайду по оплате (`onNavigateToPaymentGuide`) пушит маршрут в `navStack`, чтобы `← Назад` возвращал ровно на Шаг 4 «Чистой комнаты».
   * **Красный блок-предупреждение:** категорический отказ от серых перекупщиков на `Playerok`, `FunPay`, Telegram-ботах «подписок за полцены» и чужих Apple Pay / Google Pay аккаунтов — именно они вызывают волну банов и запросы Persona без возврата средств.

---

## 3. Pillar 2 — «SOS-Верификация + Бесплатный Бункер данных + Индекс риска Persona»

### 3.1. Глобальное интерактивное дерево решений `🚨 SOS / Верификация` (`src/features/sos/`)

Доступно в 1 клик с Home Hub (раздел **«Аккаунты, Бункер и SOS»**) и через экстренный триггер при обнаружении ошибки/блокировки. Содержит **4 ветки** без воды — только точные действия:

#### Ветка 1: `Persona (паспорт + селфи)`
* **Вопрос 1:** «Какие документы есть на руках?»
  * **Подветка 1A — «У меня только РФ документы (внутренний паспорт / загранпаспорт РФ / права РФ)»:**
    * **Красный экран `STOP`:** жёсткое предупреждение: *«НЕ загружайте ни внутренний, ни заграничный паспорт РФ в Persona — это приводит к перманентному бану аккаунта примерно за ~60 секунд без возврата средств»*.
    * **Протокол выживания из 3 шагов (Zero-Downtime Survival Protocol):**
      1. **Шаг 1 — Немедленный экстренный бэкап в Бункер (1 клик):** пока открыт интерфейс/локальный клиент — мгновенный запуск `run_bunker_backup_now` (сохраняет `~/.claude`, проекты, планы, `CLAUDE.md`, конфиги Cursor и веб-экспорт).
      2. **Шаг 2 — Остановка списаний и чек-лист возврата средств:**
         * Пошаговая отмена подписки (`reportaproblem.apple.com` для App Store, Google Play Subscriptions, Stripe Billing Portal / письмо в support при прямой оплате картой — с шаблоном тикета, без ложных обещаний гарантированного рефанда).
      3. **Шаг 3 — Plan B (2 минуты до продолжения работы без Persona):**
         * Переключение в **BYOK / API Survival Mode** (API-ключ не проходит consumer-антифрод Persona и не требует телефона/селфи на уровне потребительской подписки):
           * **OpenRouter (`openrouter.ai`)** или прямой **Anthropic Console / OpenAI API** (оплата виртуальной зарубежной картой или крипто-шлюзами для OpenRouter) — единый ключ для **Claude Code** (`ANTHROPIC_BASE_URL` / API key), **Cursor** (`Override OpenAI Base URL` / Anthropic API Key), **Antigravity / Cline** и **Open WebUI** (локальный чат в браузере как замена Claude.ai / ChatGPT).
           * Кнопка **1-click «Скопировать `restore_prompt.md`»** — копирует контекст последнего проекта в буфер через `writeClipboard` (`src/shared/lib/clipboard.ts`), чтобы продолжить работу с того же места за 2 минуты.
  * **Подветка 1B — «Есть легальный ВНЖ / иностранный паспорт / заграничная компания»:**
    * **Pre-Flight чек-лист прохождения Persona без ложного отклонения** (никаких подделок — только согласование реальных легальных данных):
      1. Страна выходного IP Заставы **строго совпадает** со страной выдачи документа/ВНЖ.
      2. Часовой пояс ОС (`os_tz`) и браузера совпадает со страной документа.
      3. Имя в биллинге карты / Stripe совпадает с именем в документе.
      4. Камера/освещение: ровный свет без бликов, отключённые виртуальные камеры (OBS Virtual Camera часто вызывает автоматический отказ Liveness), прохождение в обычном чистом браузере с включённой защитой Заставы.

#### Ветка 2: `SMS на номер`
* Диагностика причины (VoIP/виртуальный пул vs таймаут доставки vs повторное использование номера).
* Чёткое правило: виртуальные одноразовые номера с SMS-агрегаторов массово заблокированы/помечены у Anthropic и OpenAI — для повторного запроса использовать физическую SIM/eSIM той же страны, что и IP/оплата.

#### Ветка 3: `Ошибка оплаты / 3DS / Your card was declined`
* Встроенная проверка: страна BIN карты (`CardCheck`) vs страна текущего выходного IP.
* Диагностика типичных отказов Stripe: (а) prepaid/virtual BIN с низким трастом, (б) несовпадение IP и страны выпуска карты, (в) неверный AVS ZIP (быстрый переход к `AddressCard` с 5 безналоговыми штатами `DE/OR/NH/MT/AK`), (г) блокировка 3DS из-за активного стороннего VPN поверх Заставы.

#### Ветка 4: `Account disabled / Organization suspended`
* Разбор: почему произошёл бан (сопоставление с последними событиями из `ip_history` / `TRAVEL_ASN_JUMP_SAME_COUNTRY` / реселлерским биллингом).
* **Кнопка 1-click перехода в «Чистую комнату»**, которая **автоматически**:
  1. Помечает текущий exit IP как `tainted` (`mark_ip_tainted`), чтобы пользователь случайно не зарегистрировал на нём следующий аккаунт.
  2. Снимает/помечает текущий профиль как скомпрометированный.
  3. Пушит **«Чистую комнату»** в `navStack` сразу на Шаге 1 (Детектор хвостов + запуск экстренного бэкапа из Бункера), сохраняя предсказуемый `← Назад` в SOS и кнопку «На главный экран».

---

### 3.2. «Бункер данных» — бесплатный локальный автобэкап (`src-tauri/src/bunker/`)

В отличие от **Kordon Plus (`299 ₽/мес`)**, Zastava v3.0.0 предоставляет **полный локальный бэкап бесплатно и навсегда**, расширяя существующий `src-tauri/src/auditor/claude_exporter/` (`mod.rs`, `scan.rs`, `export.rs`).

#### 3.2.1. Что входит в снапшот Бункера

1. **Claude Code (`~/.claude` + `~/.claude.json`):**
   * `projects/` (истории `.jsonl` и долговременная память `memory/MEMORY.md`), `plans/`, `CLAUDE.md`, `history.jsonl`, `settings.json`, **без** утечки OAuth-секретов из `.credentials.json` (секретные ключи/токены не дублируются в читаемый индекс и санитизируются!).
2. **Claude Desktop (Classic + Windows MSIX):**
   * Обновление `get_claude_desktop_config_path` (`claude_exporter/mod.rs:86`) через общий резолвер с поддержкой `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\claude_desktop_config.json` — сохраняются MCP-серверы и настройки без `Cookies`/`ant-device-registry.json`.
3. **Cursor IDE (`src-tauri/src/bunker/cursor_export.rs`):**
   * Пользовательские настройки `%APPDATA%\Cursor\User\settings.json` / `~/Library/Application Support/Cursor/User/settings.json`, `keybindings.json`, `snippets/`, глобальный `~/.cursor/mcp.json` и список `.cursorrules` из известных проектов `~/.claude/projects` (строго без `state.vscdb` auth-токенов!).
4. **Помощник для не-кодеров (Web Claude / ChatGPT Export Helper):**
   * Вкладка/карточка внутри Бункера для тех, кто работает только в браузере (нет `~/.claude` и Cursor): вместо пустой заглушки `ArchiveSection.tsx:35` (*«Claude не найден»*) отображается дружелюбный **`EmptyState`** с прямым открытием Web Export Helper:
     * Пошаговая кнопка открытия официального экспорта (`claude.ai/settings/data-privacy` → *Export Data*, `chatgpt.com/#settings/DataControls` → *Export data*).
     * Локальный **парсер-конвертер `conversations.json` / `export.zip`**: пользователь перетаскивает/выбирает скачанный официальный JSON/ZIP, а Бункер **полностью локально** извлекает последние диалоги/инструкции проектов в читаемый Markdown + генерирует `RESTORE_PROMPT.md` для переноса в новый аккаунт или Plan B (Open WebUI / OpenRouter).
5. **1-Click «Восстановить контекст» (`RESTORE_PROMPT.md`):**
   * Обновление `generate_restore_prompt_md` (`claude_exporter/export.rs:142`) — добавляет секцию конфигурации Cursor + MCP-серверов + последний контекст сессии, готовый к вставке в новый аккаунт Claude, Cursor, Antigravity или Plan B (BYOK).

#### 3.2.2. Планировщик, хранение и ротация (`scheduler.rs`, `retention.rs`)

* **Расположение:** `<app_data_dir>/bunker/snapshots/<YYYY-MM-DD_HHMMSS>/` (а также ручной экспорт на Рабочий стол через существующую кнопку).
* **Расписание (`AppStateData.bunker`):**
  * `auto_backup_enabled: bool` (по умолчанию `true` при наличии данных Claude/Cursor),
  * `interval_hours: u32` (по умолчанию `24`, тихий фоновый прогон через `tokio::task::spawn_blocking` раз в сутки при простое — не чаще раза в 24ч),
  * `retention_count: usize` (по умолчанию **`7`** последних снапшотов — старые автоматически удаляются по FIFO, чтобы не забивать диск),
  * `last_backup_at: Option<u64>`, `last_backup_size_bytes: u64`.

---

### 3.3. Проактивный «Индекс риска Persona» (`src-tauri/src/auditor/persona_risk.rs`)

Синтетический проактивный скор (**`Низкий` / `Средний` / `Высокий`**), предупреждающий о риске триггера Persona/бана **ДО** блокировки аккаунта. Сочетает автоматические технические сигналы и добровольные поведенческие тумблеры пользователя.

#### 3.3.1. Технические сигналы (автоматические, из `RiskReport` + `AppStateData`)

| Фактор | Источник в коде | Вес риска |
|---|---|---|
| Выход через Datacenter / VPS ASN без стабильного пина или массовый VPN/Tor | `auditor/ip_type.rs` (`IpType::Hosting`, `Vpn`, `Tor`) | `+15` (Datacenter без пина) / `+35` (Mass VPN) / `+60` (Tor) |
| Прыжок ASN/ДЦ `< 4h` или смена страны | `auditor/history.rs` (`TRAVEL_ASN_JUMP_SAME_COUNTRY`, `IMPOSSIBLE_TRAVEL_*`), `ip_change_cooldown_until` | `+40` |
| Утечка IPv6, DNS или WebRTC/STUN | `auditor/leaks.rs`, `probes/stun.rs` | `+25` |
| Часовой пояс ОС РФ/РБ или локаль РФ/РБ без изоляции | `auditor/os_env.rs` (`TIMEZONE_LEAK_RU`, `LOCALE_ENV_SANCTIONED_MARKER`) | `+20` |
| Использование незащищённого/личного браузера с прошлыми следами | `clean_room/detector.rs` + `proxy/coverage` | `+15` |

#### 3.3.2. Поведенческие тумблеры самооценки (сохраняются в `AppStateData.persona_self_check`)

Пользователь может отметить чекбоксы в карточке «Индекс риска Persona» (4 честных фактора):
1. `bought_or_grey_account: bool` — «Аккаунт куплен с рук / на бирже (не регистрировался лично)» (`+45`).
2. `virtual_sms_used: bool` — «Регистрация на одноразовый виртуальный номер (SMS-активатор)» (`+30`).
3. `reseller_payment_used: bool` — «Оплата через перекупа (Playerok / FunPay / чужой Apple Pay)» (`+45`).
4. `multi_account_same_browser: bool` — «Вход в несколько аккаунтов из одного обычного браузера» (`+35`).

#### 3.3.3. Итоговый уровень и 1-click действия

* `0..=24` → **`Низкий`** (emerald `--brand-text`).
* `25..=54` → **`Средний`** (amber `--warn-text`) + список конкретных триггеров с 1-click fix кнопками (Закрепить IP / Включить синхронизацию TZ / Открыть Чистую комнату / Сбросить кэш).
* `55..=100` → **`Высокий`** (rose `--danger-text`) + предупреждение: *«Высокая вероятность запроса Persona или бана при следующей оплате/сессии»* + кнопка немедленного бэкапа в **Бункер** и перехода в **Чистую комнату**.

---

## 4. Pillar 3 — «Одушевлённый» UI/UX-редизайн: маскот Заставы, навигация «Разделы», онбординг, анимации, иконки и трей

### 4.1. Навигация, стек возврата (`navStack`) и жёсткий бюджет высоты (`460×660` zero-scroll)

За основу берётся проверенный каркас **Вариант C «Разделы»** из `/Users/putiniye/Downloads/Telegram Desktop/Вариант C 2/src/features/redesign/` (`VariantC.tsx`, `base.tsx`, `blocks.tsx`, `redesign.css`), но **портированный строго поверх `v2.3.0`** с устранением всех найденных недочётов прототипа:

1. **Отказ от 5 верхних вкладок (`Tabs`) и реальный стек навигации (`navStack: Route[]`):**
   * Главный экран — **Home Hub**; все подробные экраны открываются через drill-down с единым `PageHead` (`← Назад`, `base.tsx:272-281`).
   * **Фикс тупиков возврата (`VariantC.tsx:50-53` + `useNavigation.ts:53-65`):** наивный `goHome()` в прототипе заменяется на реальный стек **`navStack: Route[]`** с операциями `push(route)` / `pop()` и сохранением параметров маршрута (в частности `checksProvider`, который `useNavigation.ts:55` сбрасывал при уходе!):
     * `Проверки → Что исправить (guide_ref) → Гайды → ← Назад` возвращает в `Проверки` с сохранённым `checksProvider`.
     * `Чистая комната (Шаг 4 CardCheck) → Гайд по оплате → ← Назад` возвращает на Шаг 4 «Чистой комнаты».
     * `Аккаунты, Бункер и SOS (Ветка 4 Account disabled) → Чистая комната (Шаг 1) → ← Назад` возвращает в `SOS` (плюс явная кнопка «На главный экран»).
     * Deep-link клики из баннеров (`CooldownBanner`, `CoworkGuardBanner`, `ExpiringKeyBanner`) пушат маршрут в `navStack`; переход на Home Hub очищает стек.
   * **Правило ≤ 2 кликов:** все ключевые действия доступны за **≤ 2 клика** от Home (`Home → Раздел → Действие`).
   * Все страницы остаются смонтированными (`hidden={page !== ...}`), чтобы не терять состояние форм и инпутов при переходах.
2. **Шапка (`HeaderBar`, `base.tsx:133-167`):**
   * Иконка-щит (или мини-эмблема сторожевого пса) + название `Застава`
   * Жёлтая пилюля `Обновить` (`zs-rd-update`) при наличии обновления
   * Кликабельный `PingBadge` (время последнего аудита в `мс` + кликабельный `Tip` с объяснением, что это время проверки сети, а не пинг интернета + re-scan по клику)
   * Кнопка скрытия IP для скриншотов (`eye` / `eyeOff`, `hideIpMode`)
   * Кнопка меню **`menu` / `more`** (вместо неоднозначной голой шестерёнки `triggerIcon="settings"` при 10 пунктах меню, либо с явным первым пунктом `Все настройки`) + жёлтая точка `triggerDot` при наличии обновления.
   * **Точный список `menuWithout` для `v3.0.0`:** из бургер-меню «Ещё» исключаются пункты, вынесенные на Home Hub и в разделы: `subscription` (переехал в «Чистую комнату» и гайд оплаты), `rescan` (выполняется кликом по `PingBadge` в шапке и кнопкой «Перепроверить» в «Проверках и гайдах»), `syncTimezone` (доступен 1-click в «Чистой комнате», «Проверках» и `SettingsModal`). В меню остаются: `Все настройки`, `События и диагностика`, `О программе`, `Поддержка`, `Пройти знакомство заново` и др. сервисные пункты.
3. **Home Hub (`460×660`, строгий бюджет высоты `~610–635px` — ZERO скролл в штатном состоянии):**
   * *Почему нельзя переносить вертикальный Hero из прототипа:* вертикальный стек (`300px` Hero + `296px` 5 разделов + баннеры = `776–1050px`) превращает окно `460×660` в длинный скролл и выдавливает нижние разделы и `StopNetwork` за экран. Поэтому в `v3.0.0` вводятся 4 обязательных уплотнения:
   * **Блок 1 — Компактный горизонтальный Hero (`~135–145px` вместо `300px`, экономия `~75–90px`):**
     * Слева: **`WatchdogMascot` (`64×64`)** в текущем состоянии.
     * Справа: **Вердикт** (`Вы защищены` / `Требуется внимание` / `Нейросети без защиты` / `Сеть остановлена`) + IP & страна + **`Доверие к адресу` (`N из 100`)** + **пилюля `Индекс риска Persona` (`Низкий` / `Средний` / `Высокий`)**.
     * **1-строчная компактная полоса статистики (`18px`, `12px` шрифт)** внутри Hero-карточки (`Защищено: N · Отражено сбоев: N · Напрямую: N`, кликабельна для деталей).
     * **Кнопка-выключатель `PowerPill`** («Защита включена / Нажмите, чтобы выключить», `base.tsx:252-269`) с **жёсткой синхронизацией и блокировкой гонок:**
       * `PowerPill` **блокируется (`disabled`)** во время `startupPending || togglingSysproxy` (убирается оптимистичная гонка `sysproxyActive = true` при инициализации в `useGatewayState.ts:79`).
       * `src-tauri/src/tray/events.rs:158-171` (`toggle_sysproxy_tray`) **унифицируется** с `commands/sysproxy`: при включении из трея также вызывает `enable_cli_and_ide_protection_with`, при выключении — `os_tz::restore_if_synced_on_disable`, и эмитит **фактический** статус после команды (никогда не эмитит оптимистичный `!active` при ошибке `ADMIN_AUTH_REQUIRED`!).
       * После каждого `toggle_sysproxy`, события `tray://sysproxy-toggled` или ошибки (`PARTIAL_RESTORE_TEXT` в `useProtectionToggles.ts:110-134`) фронт **всегда** принудительно пересинхронизирует `getSysproxyStatus()` + `checkCliProtectionStatus()`.
   * **Приоритетный `AlertStrip` (вместо длинной стопки `OverviewBanners`):**
     * Показывает **1** баннер наивысшего приоритета (`ProblemBanner` / `CoworkGuardBanner` / `CooldownBanner` / `ExpiringKeyBanner`) + компактную пилюлю **`ещё N`** для раскрытия остальных — баннеры никогда не выталкивают `PowerPill`, разделы и `StopNetwork` за пределы `660px`.
   * **Блок 2 — 5 семантических разделов (`Card.zs-rd-sections`, `.zs-row { padding: 9px 0 }`, высота `~220px` вместо `296px`, экономия `~75px`):**
     1. **`Нейросети и защита`** (объединяет «Нейросети» и «Что защищено»; итог справа: `Все доступны` / `Без терминала` / `Заблокированы: ...`).
        * Внутри: `ServicesList` (с `executeAllowSequence`), `ProtectedRows` (Браузеры + Десктопные приложения как единый статус `sysproxyActive`, и отдельный тумблер `Редакторы кода и терминал`), а также `CoverageSection` с **упрощённой 4-состоячной легендой** (`Подключено`, `Настроено — ждёт запрос`, `Не подключено`, `Напрямую (норма)`).
        * **Фикс десинхронизации CLI-тумблера:** убираем view-layer опрос `checkCliProtectionStatus()` из `blocks.tsx:28-42` — синхронизация `cliProtected` выполняется централизованно в `useProtectionToggles.ts` (включая `disableSysproxy`, `enableSysproxy`, `toggleSysproxy`, реальные события `tray://sysproxy-toggled`, `tray://cli-toggled`, `tray://state-changed` из `src-tauri/src/tray/events.rs` и `startup://phase` из `src-tauri/src/startup.rs:19` / `src/utils/api/events.ts:45`).
        * **Платформенная чистота:** на macOS скрываем Windows-специфичную проверку `wifi_geo` (`OS_LOCATION_NOT_APPLICABLE`, `os_env.rs:316`) из списка обязательных/внимания проверок.
     2. **`Чистая комната`** (итог справа: `Готова` / `Есть хвосты (N)` / `Прогрев: Xч из 96ч`).
        * Внутри: две понятные подвкладки/ярлыка — **«Новый аккаунт (4 шага)»** (Pre-Flight «Детектор хвостов» + Hard Readiness Gate + **«Браузерная песочница (для веба)»** + 4-шаговый Launchpad) и прямой быстрый вход **«Оплата и прогрев»** (BIN-проверка карты `CardCheck` + адрес США 0% `AddressCard` + `Warmup` 96ч без прохождения Шагов 1–2).
     3. **`Аккаунты, Бункер и SOS`** (переименовано из «SOS и Бункер», чтобы ежедневное переключение профилей и безопасный выход были логичны; итог справа: `Риск: Низкий` / `Бэкап: сегодня` / `SOS` при высоком риске).
        * Внутри: кнопка запуска дерева **`🚨 SOS / Верификация`**, карточка **«Бункер данных»** (автобэкап Claude + Cursor + Web Helper + `restore_prompt.md`), **Индекс риска Persona** и чётко подписанная секция **`Профили Claude Desktop и безопасный выход`** (`BackupScreen` / `ProfilesSection` + `CacheSection`, явно отличаемая от веб-песочницы «Чистой комнаты»).
     4. **`VPN и ключи`** (итог справа: `Ключ Заставы` / `Через ваш VPN` / `Ключ истекает`).
        * Внутри: `ConnectScreen` с `layout="sales"` **поверх модульной архитектуры `v2.3.0`** (`ProviderRoutesSection.tsx` + `RouteListSection.tsx` + `handleResetActiveProfileRoute` + привязки профилей + `EmptyState` при `0` маршрутов):
          * Карточка **«ВПН Заставы»** идёт **первой** с изумрудной рамкой (`.zs-sale--key`), списком преимуществ, CTA «Получить ВПН» и полем ввода ключа **сразу под кнопкой** (без прокрутки вниз).
          * Карточка **«Свой сервер»** идёт второй; **убираем вводящий в заблуждение бейдж `Бесплатно`** (`src/shared/copy/ru/connect.ts:5`), т.к. аренда VPS платная.
          * **Управляемые копирайт-константы:** все конкретные цифры цены/срока выдачи ключа Заставы выносятся в единый блок конфигурируемых констант `PROMO_COPY` в `src/shared/copy/ru/connect.ts` с пометкой `[CONFIRM_BEFORE_RELEASE]`.
     5. **`Проверки и гайды`** (итог справа: `13 из 13` или число замечаний).
        * Внутри: две компактные подвкладки **`Проверки сети`** (`ChecksScreen` с `showCoverage={false}` + кнопка **`Тест обрыва VPN (Краш-тест)`** (`CrashTestModal` `compact`), вынесенная **в самый верх экрана** рядом с «Перепроверить», а не в низ списка) и **`Гайды`** (`GuidesScreen`: Свой VPS, Оплата — с прямой кнопкой открытия «Проверка карты (BIN) и адрес США 0%» без ссылки на несуществующую вкладку «Биллинг» — и Защита ОС).
   * **Аварийная кнопка `StopNetwork`** («Остановить сеть для ИИ» / «Возобновить») остаётся внизу Home Hub (суммарная высота Home Hub `~610–635px`, полностью помещается в `460×660` без скролла!).

4. **Уведомления и `alert-popup`:**
   * **`NotificationStack`** (`base.tsx:175-247`): стопка тостов внизу экрана со счётчиком `ещё N`, сохраняющая `CopyErrorLogButton` для `t.tone === "danger"`. **Улучшение относительно прототипа:** убираем тяжёлый полноэкранный `backdrop-filter: blur(6px)` у `.zs-rd-notes-backdrop` (`redesign.css:80`) ради `0` лагов на бюджетных Windows-ноутбуках, заменяя на лёгкое затемнение `background: color-mix(in srgb, var(--bg-0) 72%, transparent)`.
   * **`alert.css`**: портируется компактная вёрстка `Вариант C 2/src/features/alert/alert.css` (`440×470` без прокрутки), плюс сохраняется `overflow-wrap: anywhere` для длинных причин `TRAVEL_ASN_JUMP_SAME_COUNTRY` из `v2.3.0`.

5. **Цветовая система (Color System):**
   * Строгая 4-цветная семантика статусов поверх `src/styles/tokens.css`:
     * **Серый (`--ink-2`, `--bg-2`/`--bg-3`)** — нейтральная информация и фоны.
     * **Изумрудный (`--brand: #10b981`, `--brand-text: #34d399`, `--brand-soft: #0f2f25`, `--on-brand: #04140e`)** — защита активна, проверки пройдены, **главные CTA-кнопки (`.zs-btn--primary`)**. *(Отклоняем монохромное переопределение `.zs-redesign .zs-btn--primary{background:var(--ink)}` из `Вариант C 2/redesign.css:10`!)*
     * **Янтарный (`--warn`, `--warn-text`, `--warn-soft`)** — требуется внимание.
     * **Розовый/красный (`--danger`, `--danger-text`, `--danger-soft`)** — утечка, опасность, остановка сети.
   * **Доступность и `pnpm lint:hex`:** сохраняем контрастное кольцо фокуса `--focus: #7dd3fc` из `tokens.css:26` и запрещаем любые raw hex/rgb в компонентах.

---

### 4.2. Маскот «Сторожевой пёс Заставы» (Flat Vector SVG) и 5 функциональных анимаций

#### 4.2.1. Персонаж и 5-состоячный конечный автомат (`src/features/mascot/WatchdogMascot.tsx`)

Персонаж: стилизованный плоский векторный корги/лайка в изумрудном плаще-щите (геометричный, строгий, без «детской мультяшности», с цветами исключительно через CSS-переменные `var(--brand)`, `var(--warn)`, `var(--danger)`, `var(--ink)`, `var(--bg-2)`):

| Состояние (`MascotState`) | Триггер UI/ядра | Визуал и анимация (CSS `@keyframes` only `transform`/`opacity`) |
|---|---|---|
| `protected` (Спокойная охрана) | `sysproxyActive && overall_status === "green"` | Пёс сидит ровно на фоне щита с лёгким изумрудным ореолом; мягкое «дыхание» грудной клетки (`scaleY(1 → 1.02)`, `4s ease-in-out infinite`) + редкое моргание (`opacity`/`scaleY` раз в `5s`). |
| `scanning` (Чистая комната / Поиск) | `refreshing || startupPending || cleanRoomScanning` | Пёс в профиль с лёгким наклоном головы; плавное движение сканер-луча (`translateX`, `1.8s ease-in-out infinite`). |
| `alert` (Перехват / Опасность) | `killswitchFrozen || overall_status === "red" || pendingAlert` | Уши встают торчком, поза настороженная, щит спереди подсвечен `--danger`; одноразовый чёткий snap-импульс при входе в состояние (без раздражающего бесконечного мигания). |
| `sleep` (Защита выключена) | `!sysproxyActive && !startupPending` | Пёс свернулся калачиком с закрытыми глазами в серой палитре (`--ink-3`), минимальная статичная поза. |
| `warmup` (Прогрев / Бункер) | Экран прогрева `96ч` или активное сохранение Бункера | Пёс рядом с мягким изумрудным индикатором-щитком / таймером (спокойный прогресс). |

#### 4.2.2. Жёсткий бюджет производительности (~0% idle CPU/GPU)

* **Только Inline SVG + CSS `@keyframes`** с анимацией исключительно композитных свойств `transform` и `opacity` (никакого `lottie-web`, никаких `requestAnimationFrame` циклов, никаких фильтров `blur`/`drop-shadow` внутри анимации).
* **Visibility & Window Pause:** класс `.zs-mascot--paused` вешается автоматически, когда:
  1. `document.visibilityState === "hidden"` (`visibilitychange`),
  2. окно Tauri свёрнуто в трей или потеряло фокус/скрыто (`tauri://blur` / `window` hide),
  3. включён `@media (prefers-reduced-motion: reduce)` (анимации полностью отключаются).
  Это гарантирует **~0% нагрузки на CPU/GPU в фоне и в трее**.

#### 4.2.3. 5 функциональных обучающих анимаций

1. **Живая схема Split-Routing** (в Шаге 2 онбординга и в разделе «VPN и ключи» / «Нейросети и защита»): два потока наглядно расходятся — `Сбербанк / Ozon` идёт по прямой зелёной/серой стрелке напрямую, а `Claude / ChatGPT / Gemini` проходит через щит маскота на выделенный узел (`transform: translateX` точек потока).
2. **Мгновенный перехват «0.04 мс»** (в `AlertWindow`, Шаге 4 онбординга и `CrashTestModal` `compact`): анимация захлопывания щита при срабатывании `Kill-Switch`.
3. **Пошаговый радар «Чистой комнаты»**: поочерёдное подсвечивание 4 проверенных слоёв (Браузеры → Desktop/MSIX → IP/DNS → TZ/Locale) во время префлайт-аудита.
4. **2-кадровый визуальный гайд SmartScreen / Gatekeeper** (в сворачиваемом блоке Шага 2 онбординга и в `About`/помощи по установке): наглядная 2-шаговая схема «Подробнее → Выполнить в любом случае» (Windows SmartScreen) и «Открыть» (macOS Gatekeeper), снижающая отвал новых пользователей на Windows.
5. **Плавный переход пробуждения/сна `PowerPill`**: синхронная CSS-транзиция кнопки `PowerPill` и маскота между состояниями `sleep` ↔ `protected`.

---

### 4.3. Обновление иконок приложения и системного трея (`src-tauri/icons/`, `tray/mod.rs`)

1. **Иконка приложения (`icon.png`, `icon.icns`, `icon.ico`, Windows Tile PNGs):**
   * Новый знак **«Сторожевой пёс внутри щита»** с **контрастной светло-изумрудной внешней обводкой** (`--brand` / светлый кант), что полностью решает **Bug #8** (невидимость тёмной иконки на тёмной панели задач Windows 10/11).
2. **Иконки системного трея (`16×16` и `@2x` `32×32`) + 4-е состояние в `src-tauri/src/tray/mod.rs`:**
   * Текущие 3 иконки (`tray/mod.rs:43-45`): `tray-green.png`, `tray-yellow.png`, `tray-red.png`.
   * **Добавляется 4-я иконка `tray-gray.png`** (`TRAY_ICON_GRAY`) и вариант `TrayColor::Gray` в `enum TrayColor` (`tray/mod.rs:58-81`):
     * `TrayColor::Gray` используется, когда защита выключена пользователем (`!sysproxyActive` / выключенный режим — см. `update_tray_status(..., "gray", Some("Защита выключена"))`), чтобы в трее сразу визуально отличать **«выключена пользователем» (серый)** от **«ошибка/нет данных» (жёлтый)** и **«утечка/СТОП СЕТИ» (красный)**.
   * Обновление `scripts/check-tray-main-thread.mjs` и unit-тестов в `tray/mod.rs` для `TrayColor::Gray`.

---

### 4.4. Онбординг первого запуска, Upgrade-гайд «Что нового в v3.0» и контекстные подсказки

#### 4.4.1. 5-шаговый First-Run Onboarding (`onboarding_v3_done`)

Заменяет устаревший 4-шаговый онбординг (`ONBOARDING_DONE_KEY = "zastava_onboarding_v2_2_done"`, `ONBOARDING_STEPS = 4` в `src/features/onboarding/useOnboarding.ts:6-8`) на **5-шаговый онбординг `v3.0.0`**, привязанный к `AppStateData.onboarding_v3_done`:

1. **Шаг 1 (`StepWelcome` — Маскот + `PowerPill` + 1-click Quick-Pick Goal):**
   * Знакомство с псом-сторожем и главной кнопкой `PowerPill`.
   * Выбор цели в 1 клик (адаптирует финальный маршрут после завершения):
     * **«Защитить текущий аккаунт»** → Home Hub;
     * **«Создать новый аккаунт без следов старого бана»** → **«Чистая комната»**;
     * **«Уже вылезла Persona / бан»** → **«Аккаунты, Бункер и SOS»**.
2. **Шаг 2 (`StepNetwork` — Split-Routing + Сеть/VPN + SmartScreen/Gatekeeper):**
   * Встроенная живая анимация Split-Routing (*«Сбербанк / Ozon напрямую vs Claude / ChatGPT через щит»*) — снимает главный страх новичков перед «сломанным интернетом».
   * Живая проверка сети + выбор **«Ключ Заставы» / «Свой VPN»**.
   * Сворачиваемый мини-блок **2-кадрового гайда SmartScreen (Win `68%`) / Gatekeeper (Mac)**.
3. **Шаг 3 (`StepProtect` — Слои защиты и локальный Бункер):**
   * Подключение браузеров/десктоп-приложений и редакторов кода/терминала + 1 понятная строка про автоматический локальный **Бункер** (бэкап без облака).
4. **Шаг 4 (`StepAlert` — Пробная тревога / Краш-тест):**
   * Демо-тревога / краш-тест с человеческой формулировкой **«Точная причина остановки»** вместо технического жаргона `gate_reason`.
5. **Шаг 5 (`StepDone` — 4 цвета трея и автоматический старт):**
   * Наглядное объяснение 4 цветов иконки трея (включая **серый «Защита выключена»**) + автоматический переход к цели, выбранной пользователем на Шаге 1.

**Обязательная переработка текстов (`src/shared/copy/ru/onboarding.ts`):** переписать все устаревшие строки `v2.2` (`onboarding.ts:17,52,55,93,107-111,130,155,176` с упоминаниями *«В версии 2.2»*, *«во вкладке „Проверки“»*, *«Во вкладке „Подключение“»*, *«на „Обзоре“ есть кнопка „Тест обрыва VPN“»*, *«В меню „Ещё“»*) и убрать технический жаргон (`PAC-политики`, `QUIC/DoH`, `TUN VPN вроде V2Box Pro`, `ai_only`, `gate_reason`).

#### 4.4.2. Upgrade-гайд «Что нового в v3.0» (`whats_new_v3_seen`)

Чтобы ~300 текущих пользователей при миграции `v2 → v3` не потеряли привычные верхние вкладки без объяснения:
* В `AppStateData` добавляется флаг `whats_new_v3_seen: bool` (`false` при миграции `v2 → v3`, `true` для новых пользователей, прошедших 5-шаговый онбординг `v3.0`).
* При `whats_new_v3_seen == false` показывается компактный 3-карточный sheet **`WhatsNewSheet` («Что нового в v3.0»)**:
  1. **Вкладки переехали в 5 разделов + маскот и `PowerPill`**.
  2. **«Чистая комната»** (изолированное окно браузера + проверка BIN карты и прогрев 96ч).
  3. **«Аккаунты, Бункер и SOS»** (автобэкап на диск + Plan B при запросе Persona).
* Внизу sheet'а — кнопка **«Понятно»** (ставит `whats_new_v3_seen = true`) и вторичная CTA **«Пройти знакомство заново»**.

#### 4.4.3. Контекстные подсказки (`HintCard`, click+hover `InfoTip`, `EmptyState`)

1. **`HintCard` (`dismissed_hints: Vec<String>` в `AppStateData`):**
   * При первом визите в любой из **5 разделов** Home Hub, а также в **«Чистую комнату»** и **«SOS»**, сверху показывается компактный закрываемый 1-предложенческий баннер «что здесь находится и что нажать первым».
   * В `SettingsModal` добавляется кнопка **«Сбросить подсказки и обучение»** (очищает `dismissed_hints` и позволяет заново открыть онбординг).
2. **`InfoTip` с поддержкой клика (`src/ui/Tooltip.tsx:102-106,140`):**
   * `Tip` дорабатывается для открытия как по **hover/focus**, так и по **клику/тапу** (важно для тачпадов и пользователей, нажимающих на иконку `!`/`?`).
   * `InfoTip` становится обязательным на всех ключевых терминах интерфейса: `ASN`, `WebRTC / STUN`, `DoH / QUIC`, `BIN`, `Stripe AVS / 0% US Tax`, `deviceId` vs `Org ID`, `4ч таймер безопасного выхода`, `Индекс риска Persona (0–24 / 25–54 / 55–100)`, `Direct (Свой VPN)` vs `Ключ Заставы`.
3. **Человечные `EmptyState` (`src/ui/EmptyState.tsx`) для всех пустых состояний:**
   * `0` чистых профилей в «Чистой комнате» → CTA *«Создать чистый профиль и проверить хвосты»*.
   * `0` снапшотов Бункера (особенно для веб-пользователей без `~/.claude` и Cursor) → вместо тупиковой заглушки `ArchiveSection.tsx:35` (*«Claude не найден»*) открывается карточка **Web Export Helper** с пошаговым экспортом `claude.ai` / `chatgpt.com`.
   * `0` маршрутов в `ConnectScreen` → понятный `EmptyState` с выбором «Ключ Заставы» / «Добавить свой сервер».
   * `0` обнаруженных браузеров в «Чистой комнате» → `EmptyState` со ссылками на скачивание Chrome / Edge.

---

## 5. Pillar 4 — Все 9 подтверждённых баг-фиксов `v2.3.0` (Root Cause, File:Line, Fix & Tests)

### Bug #1 [P0]: Windows MSIX Store Cache Cleaner не чистит Microsoft Store версии Claude / ChatGPT и врёт при `0` файлов

* **Root Cause (`File:Line`):**
  * `src-tauri/src/auditor/cache_cleaner.rs:15-44` (`get_ai_app_data_dir`) на Windows проверяет только `%APPDATA%\Claude` и `%APPDATA%\ChatGPT`, игнорируя MSIX-контейнеры Microsoft Store (`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude` и `%LOCALAPPDATA%\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT`). При этом в соседнем `src-tauri/src/auditor/profile_switcher/device_registry.rs:156-214` (`resolve_claude_desktop_dir_for_platform`) логика MSIX для Claude уже существует, но не переиспользована в `cache_cleaner.rs` и `claude_exporter/mod.rs:86-118`.
  * `clean_ai_app_cache_in_dir` (`cache_cleaner.rs:84-192`) не закрывает запущенные процессы `claude.exe` / `ChatGPT.exe` перед удалением, поэтому Windows удерживает file lock на `Cookies` и `Local Storage`, и ошибки `remove_file` / `remove_dir_all` молча проглатываются (`let _ = ...`).
  * `src/shared/hooks/useClaudeBackup.ts:80-84` всегда показывает зелёный тост `t.backup.cacheCleaned(...)` (`"success"`), даже если `files_removed === 0` или каталог клиента не найден / заблокирован.
  * Текст UI недостаточно ясно разделяет локальный **Session / Cookies**, **`deviceId` (`ant-device-registry.json`)** и серверный **`Org ID`**.
* **Fix:**
  1. Вынести единый платформенный резолвер `resolve_ai_app_data_dirs(provider: ProviderId)` в `device_registry.rs` (возвращает **все** найденные директории — и classic `%APPDATA%\...`, и Windows MSIX `%LOCALAPPDATA%\Packages\{Claude_*,OpenAI.ChatGPT-Desktop_*}\LocalCache\Roaming\{Claude,ChatGPT}`), переиспользовать в `cache_cleaner.rs` и `claude_exporter/mod.rs`.
  2. Перед удалением в `clean_ai_app_cache` вызывать мягкое закрытие процесса, строго уважая `os_effects_enabled()`:
     * Для **Claude Desktop на Windows**: закрывать процесс фильтрацией по пути исполняемого файла (`WindowsApps\Claude_*` / `AnthropicClaude` или PID без CLI) — **КАТЕГОРИЧЕСКИ ЗАПРЕЩЕНО** использовать глобальный `taskkill /IM claude.exe /T` (как в `safe_logout.rs:194`), который убивает запущенный нативный **Claude Code CLI (`claude.exe`)** в терминале!
     * Для **ChatGPT**: закрывать `ChatGPT.exe` (мягкое закрытие до `/F`, затем дерево при необходимости).
  3. Исправить `remove_dir_contents` (`cache_cleaner.rs:212-213`): **не инкрементировать `count += 1` при ошибке удаления** залоченного файла (`let _ = remove_file`); возвращать `locked_targets: Vec<String>` и `found_dir: bool` в `CleanResult` (`cache_cleaner.rs:6-13`), не скрывая ошибки блокировки.
  4. В `useClaudeBackup.ts:80-84`: если `!res.found_dir` или `files_removed === 0 && locked_targets.is_empty()` — показывать спокойный `info`-тост («Следы не найдены — кэш уже чист»); если `locked_targets.length > 0` — `warning` с указанием закрыть приложение.
  5. Обновить подписи в `src/shared/copy/ru/backup.ts`: явно пояснять разницу между **локальными cookies/сессией**, **`deviceId` устройства** и **серверным `Org ID`** (который нельзя сбросить с локального диска).
* **Tests:** Unit-тест в `cache_cleaner.rs` с mock MSIX-директорией `Packages/Claude_test123/LocalCache/Roaming/Claude` и `Packages/OpenAI.ChatGPT-Desktop_test/LocalCache/Roaming/ChatGPT`, проверка сохранения `claude_desktop_config.json`, проверка что `remove_dir_contents` не считает залоченный файл в `files_removed` и добавляет его в `locked_targets`, тест фильтрации процесса (Claude Desktop vs Claude Code CLI), плюс Vitest для `useClaudeBackup.ts` (`files_removed === 0` → `"info"`, `locked_targets` → `"warning"`).

---

### Bug #2 [P0]: «Что исправить» для DNS / STUN / IPv6 открывает вкладку «Часовой пояс» (замкнутый цикл)

* **Root Cause (`File:Line`):**
  * Все сетевые/DNS/IPv6/STUN-проверки в `src-tauri/src/auditor/leaks.rs:191,227,359,409,467,480`, `src-tauri/src/auditor/probes/whoami/verdict.rs:110` и `src-tauri/src/auditor/probes/stun.rs:293` передают `guide_ref: Some(GUIDE_OS_PRIVACY.to_string())`, где `GUIDE_OS_PRIVACY = "03-os-privacy-setup"` (`geo_matrix/mod.rs:12`).
  * На фронтенде `src/features/guides/routing.ts:32-34` жёстко маршрутизирует `case "03-os-privacy-setup": return { section: "os", part: "tz" };`! В результате клик на «Что исправить» у **DNS**, **IPv6** или **UDP STUN** перекидывает пользователя на вкладку **«Часовой пояс»** вместо **«Сеть, DNS и IPv6» (`part: "geo"`)**.
* **Fix:**
  1. Добавить специализированную константу `pub const GUIDE_OS_NETWORK: &str = "03-os-privacy-setup#geo";` (или `"03-os-network-dns"`) в `src-tauri/src/auditor/geo_matrix/mod.rs:12` и перевести на неё все DNS/IPv6/STUN/PTR `guide_ref` в `leaks.rs`, `verdict.rs`, `stun.rs` и `network/mod.rs:190` (оставив `GUIDE_OS_PRIVACY` для `timezone` и `locale_hygiene` в `os_env.rs`).
  2. В `src/features/guides/routing.ts:27-45` добавить обработку:
     ```ts
     case "03-os-privacy-setup#geo":
     case "03-os-network-dns":
     case "os-geo":
       return { section: "os", part: "geo" };
     ```
  3. Дополнить `GeoCards` в `src/features/guides/OsGuide.tsx:99` явной карточкой-инструкцией по DNS (`1.1.1.1 / 8.8.8.8` и DoH) и кнопкой «Открыть настройки сети ОС» (`openOsNetworkSettings`).
* **Tests:** Unit-тест (новый файл `src/features/guides/routing.test.ts`: проверка `resolveGuide("03-os-privacy-setup#geo")` → `{ section: "os", part: "geo" }`) + Rust-тест в `leaks_tests.rs` / `stun_tests.rs`, проверяющий корректный `guide_ref` у `DNS_DOMESTIC_WARNING`, `IPV6_LEAK_MISMATCH`, `UDP_STUN_MISMATCH`.

---

### Bug #3 [P0]: С активным «ВПН Заставы» (`via_zastava_key`) оценка DNS застревает на `65 / 100`

* **Root Cause (`File:Line`):**
  * При работе через «ВПН Заставы» (`via_zastava_key == true` в `evaluate.rs:55`) пользователь часто сидит на домашнем интернете без системного VPN, где в ОС прописан DNS провайдера РФ (`scutil --dns` / `ipconfig /all`) и публичный `whoami` видит резолвер провайдера РФ (`country == "RU"`).
  * При этом AI-запросы уходят через `TCP CONNECT` / `SOCKS5H` на узел Заставы (имя хоста AI резолвится **удалённо** на узле Заставы!). Однако `src-tauri/src/auditor/leaks.rs:352` проверяет `if country == "RU" && exit.as_deref() != Some("RU")` **без** учёта `via_zastava_key`, а строки `leaks.rs:366-372` и `388-395` возвращают `config` (`Warning`, `-15` баллов в `scoring.rs:78-81`), если `check_dns_leak_with` нашёл провайдера РФ/Яндекс в настройках ОС!
  * В паре с `dns_country` (`verdict.rs:94-114`, где для `RU` `is_sanctioned_or_blocked_country("RU") == true`, даёт ещё `-15` за `DNS_COUNTRY_SPLIT`) или `TIMEZONE_LEAK_RU` (`-15`) и `UNKNOWN` (`-5`) суммарный `trust_score` падает до **`65 / 100`** и жёлтого вердикта, пугая пользователя с платным ключом Заставы!
* **Fix:**
  1. В `leaks.rs::resolve_dns_verdict` (`leaks.rs:301-433`) и `verdict.rs::evaluate_dns_country_for_route` (`verdict.rs:40-123`): при `via_zastava_key == true` разрешать спокойный `CheckResult::ok("DNS_KEY_REMOTE_RESOLVE", ...)` **ТОЛЬКО при одновременном выполнении ВСЕХ 3 предусловий**:
     * (1) привязанный маршрут Заставы исправен и проходит `r.check_usable(...)`;
     * (2) `sysproxy::is_sysproxy_active()` (либо активна браузерная песочница / CLI-защита) **И** `!os_pac_deferred`;
     * (3) текст проверки явно поясняет пользователю, что **non-AI сайты в обычном браузере по-прежнему резолвятся через DNS ОС**.
     Если хотя бы одно из предусловий нарушено (например, `sysproxy` выключен или `os_pac_deferred == true`), **сохраняется `DNS_DOMESTIC_WARNING` (`Warning`, `-15`)**, чтобы никогда не маскировать реальную утечку DNS оценкой `100 / 100`.
  2. **Строгий инвариант безопасности:** когда `via_zastava_key == false` (режим `Direct` / личный системный VPN), вся строгость `DNS_DOMESTIC_WARNING` / `DNS_YANDEX_LEAK` / `DNS_COUNTRY_SPLIT` (`Warning` и `-15` баллов) **полностью сохраняется**!
  3. Проверить поведение при утечке DoH/DNS мимо PAC в браузере: в `ChecksScreen` оставить справочную подсказку про DoH без занижения `trust_score` до `65`.
* **Tests:** Новые тесты в `leaks_tests.rs`, `whoami_tests.rs` и `scoring_tests.rs`: `via_zastava_key = true` + `usable = true` + `sysproxy_active = true` + `os_pac_deferred = false` + `country = "RU"` → `CheckStatus::Ok("DNS_KEY_REMOTE_RESOLVE")` и `trust_score >= 95`; при `sysproxy_active = false` ИЛИ `os_pac_deferred = true` ИЛИ `via_zastava_key = false` + `country = "RU"` → `CheckStatus::Warning("DNS_DOMESTIC_WARNING")` и штраф `-15` сохраняется.

---

### Bug #4 [P1]: Сбой Entry DNS при активном TUN Fake-IPv6 (`fc00::/18`) и неинформативный лог `check_entry_ip`

* **Root Cause (`File:Line`):**
  * `src-tauri/src/core/net_safety.rs:48-58` (`is_tun_fake_ip`) распознаёт только IPv4 `198.18.0.0/15` и IPv4-mapped `::ffff:198.18.0.0/15`. Популярные TUN-клиенты (sing-box, Clash Meta, Nekoray, Hiddify) в режиме FakeIPv6 выдают адреса из пула **`fc00::/18`** (ULA), который полностью блокируется в `is_forbidden_ip` (`net_safety.rs:93`: `(seg0 & 0xfe00) == 0xfc00`).
  * В `src-tauri/src/routing/net/mod.rs:306`:
    ```rust
    Ok(addrs) if !addrs.is_empty() => {
        validate_entry_addrs(&addrs, true, allow_local, gateway_port)?;
        cache.insert(key, addrs.clone());
        return Ok(addrs);
    }
    ```
    Оператор `?` немедленно прерывает функцию ошибкой `PermissionDenied`, **минуя** `backend.fallback_lookup` (`hickory-resolver` + DoH, строка `322`)! С другой стороны, простое принятие `fc00::/18` в `system_lookup` и `proxy/transit.rs:283-297` до вызова публичного DoH-резолва создаёт риск SSRF на `fc00::/18` (а `hickory_resolve_addrs(..., use_system_conf=true)` в `routing/net/dns.rs:200` может вновь вернуть TUN Fake-IP).
  * Кроме того, `check_entry_ip` (`routing/net/mod.rs:79-99`) возвращает статическую строку без указания самого отклонённого IP, из-за чего диагностика `[proxy:route]` (`routing/net/mod.rs:379-382`) не показывает проблемный адрес.
* **Fix:**
  1. В `core/net_safety.rs::is_tun_fake_ip`: добавить проверку IPv6 Fake-IP **`fc00::/18`** (`(s[0] == 0xfc00) && (s[1] & 0xc000) == 0` — маска `ffff:c000::`), сохраняя запрет на все остальные ULA `fc00::/7` при `via_hostname == false` и в `validate_tunnel_target` (SSRF-защита для прямых IP-литералов не ослабляется!).
  2. **Anti-SSRF инвариант в `resolve_entry_checked_with` (`routing/net/mod.rs:305-319` и `proxy/transit.rs:283-297`):**
     * Если `system_lookup` вернул **ЛЮБОЙ** Fake-IP (`198.18.0.0/15` или `fc00::/18`) **ИЛИ** `is_forbidden_ip`, функция **ОБЯЗАНА сначала принудительно** вызвать публичный `hickory` (`1.1.1.1` / `8.8.8.8`, без `use_system_conf=true`) + `doh_resolve_addrs` (с поддержкой **`A` и `AAAA`** в `routing/net/dns.rs:132`) для получения реального публичного entry IP узла!
     * Принимать Fake-IP (`198.18.0.0/15` или `fc00::/18`) разрешается **ТОЛЬКО как last-resort fallback**, когда публичный `hickory`/DoH полностью отказал при активном TUN (и никогда для локального LAN без TUN).
     * Убрать ранний `?` на `validate_entry_addrs` для `system_lookup` (`routing/net/mod.rs:306`) и логировать каждый отклонённый IP в `diagnostics::record("routing:dns", ...)`.
  3. Расширить сообщение об ошибке в `validate_entry_addrs` / диагностику `[proxy:route]`, указав точный отклонённый IP и источник (`system` vs `fallback`).
* **Tests:** Unit-тесты в `core/net_safety.rs` (`fc00::1` → `is_tun_fake_ip == true`, `fd12:3456::1` → `false`) и в `routing/net/tests.rs`: (a) `system_lookup` возвращает `127.0.0.1` или `fd00::1` → `resolve_entry_checked_with` НЕ падает, а переходит на public `hickory`/DoH и возвращает валидный публичный IP + пишет в `routing:dns`; (b) `system_lookup` возвращает `fc00::1` / `198.18.0.1` → сначала запрашивается public `hickory`/DoH и используется реальный публичный IP; Fake-IP принимается только при полном отказе public DNS/DoH под активным TUN.

---

### Bug #5 [P1]: Спам в логах `[sysproxy:macos]` каждые 5 секунд при активном внешнем VPN

* **Root Cause (`File:Line`):**
  * `src-tauri/src/sysproxy/macos/apply.rs:145-158` на каждом 5-секундном тике self-heal/watcher, когда внешний VPN проксирует трафик и `skipped_vpn` не пуст, безусловно вызывает `crate::diagnostics::record("sysproxy:macos", ...)` при отличии `effective_proxy()`, засоряя кольцевой буфер диагностики одинаковыми строками.
* **Fix:**
  1. Ввести в `sysproxy/macos/apply.rs` дедупликацию по ключу состояния (например, `static LAST_MACOS_DIAG_STATE: Mutex<Option<String>>` + rate-limit минимум `300` секунд для повторяющегося неизменного состояния).
  2. Записывать событие в `diagnostics::record("sysproxy:macos", ...)` только при **переходе** состояния (появление/исчезновение/изменение параметров) или изменении ошибки `AdminAuthRequired`.
* **Tests:** Unit-тест в `sysproxy/macos/` (повторный вызов `apply_pac` с неизменным `skipped_vpn` состоянием записывает в диагностику `1` раз вместо `N` раз; при смене состояния — записывает снова).

---

### Bug #6 [P1]: Недружественное поведение при выключении маршрута (Route Toggle OFF)

* **Root Cause (`File:Line`):**
  * При выключении тумблера активного привязанного маршрута в `ConnectScreen.tsx:159-175` (`setRouteEnabled(routeId, false)`), `proxy/server/connect.rs:88-93` fail-closed отклоняет запросы (`RouteDownReason::Disabled`), выбрасывая красный баннер `route-unavailable`, хотя пользователь часто хочет временно перейти на свой системный VPN (`Direct`).
  * **Ловушка приоритета `profile_route_id`:** в `routing/select.rs:17-20` `profile_route_id` имеет **наивысший приоритет** для `anthropic`, однако `getAffectedProvidersForRoute` (`ConnectScreen.tsx:42-52`) его не проверяет — из-за чего переключение в `Direct` без обработки `profile_route_id` оставляет `anthropic` в `RouteDownReason::Disabled` (или при молчаливом сбросе ломает мультиаккаунт-изоляцию).
* **Fix:**
  1. **Сохранить fail-closed инвариант в ядре (`state/routes.rs`, `proxy/server/connect.rs`):** простое выключение маршрута по-прежнему не допускает тихой утечки в `Direct`.
  2. На фронтенде (`ConnectScreen.tsx` / `RouteListSection.tsx`), `getAffectedProvidersForRoute(routeId, snapshot)` и диалог Route-OFF **обязаны также проверять `profile_route_id`**:
     * Если маршрут задействован в `default_route_id` / `provider_routes`, показывать диалог с **двумя понятными действиями**:
       * **«Отключить и перейти на свой VPN (Direct)»** — явно переключает затронутые привязки (`setDefaultRoute(null)` / `bindProviderRoute(p, DIRECT_ROUTE_ID)`) после подтверждения и выключает маршрут;
       * **«Просто остановить маршрут (блокировать ИИ)»** — выключает маршрут в строгом fail-closed режиме.
     * Если маршрут привязан к **`profile_route_id`**, требовать **отдельного явного подтверждения** (`handleResetActiveProfileRoute()`) с предупреждением о мультиаккаунт-изоляции перед его сбросом.
  3. В `routeUnavailableBanner` (`AppShell.tsx:169-198`) добавить прямую 1-click кнопку **«Переключиться на свой VPN (Direct)»** (с подтверждением и проверкой `profile_route_id`), если причина отказа — `Disabled`.
* **Tests:** Vitest-тесты на сценарий Route Toggle OFF → выбор Direct vs fail-closed и отдельное подтверждение `profile_route_id`; Rust-тест в `routing_fail_closed.rs`, подтверждающий, что без явного выбора Direct маршрут остаётся fail-closed.

---

### Bug #7 [P1]: Деградация Windows `CoworkVMService` не уведомляет пользователя, если окно Настроек закрыто

* **Root Cause (`File:Line`):**
  * Бэкенд `src-tauri/src/app/watchers.rs:262-289` каждые 60 секунд проверяет статус `CoworkVMService` и исправно шлёт событие `handle.emit("cowork-guard://status", &status)`. Однако `watchers.rs:270` авто-триггерит guard-задачу только при `task_installed && start_type == Some(2)` (если Store-обновление запустило службу при `Start = 3` без запущенного `claude.exe`, авто-остановка не срабатывает), а сам воркер при старте спит `5` секунд до первого `emit`.
  * На фронтенде на `onCoworkGuardStatus` подписан **только** `src/features/settings/useSettingsController.ts:153-165`, который монтируется исключительно при `open === true` (открытое модальное окно Настроек!). Пользователь на Windows никогда не узнает о сбросе `Start = 2` после обновления Microsoft Store Claude Desktop.
* **Fix:**
  1. В `src-tauri/src/app/watchers.rs:270`: также авто-триггерить guard-задачу, когда `task_installed && service_running && !is_claude_process_running()`.
  2. Вынести глобальную подписку `onCoworkGuardStatus` на уровень оболочки (`useAppShellController.ts` / новый `useCoworkGuardWatcher.ts`), причём **вызывать `getCoworkGuardStatus()` сразу на mount** (не ждать 5 секунд первого `emit`).
  3. При `status.supported && status.needs_repair` сразу показывать спокойный **не-аварийный баннер внимания** (`tone="warn"`, визуально чётко отделённый от красных kill-switch алертов обрыва VPN!) с кнопкой **«Починить в 1 клик»** (`installOrRepairCoworkGuard`), который пропадает сразу после успешного восстановления `needs_repair == false`.
* **Tests:** Rust-тест в `watchers.rs` на триггер при `task_installed && service_running && !is_claude_process_running()`; Vitest-тест глобального `useCoworkGuardWatcher`: начальный fetch `getCoworkGuardStatus()` на mount + listener `cowork-guard://status` сразу показывают баннер при закрытом `SettingsModal` (`needs_repair === true`) и скрывают его после «Починить».

---

### Bug #8 [P2]: Нечитаемая иконка приложения на тёмной панели задач Windows

* **Root Cause (`File:Line`):**
  * Текущие иконки `src-tauri/icons/{icon.png,icon.ico,icon.icns,32x32.png,128x128.png,...}` не имеют светлого/контрастного внешнего контура и сливаются с тёмной темой панели задач Windows 10/11.
* **Fix:**
  * Решено комплексно в рамках **Раздела 4.3**: новый дизайн иконки «Сторожевой пёс в щите» со светло-изумрудной контрастной рамкой, перегенерированный во все форматы `src-tauri/icons/*` (включая `icon.ico` с размерами 16/24/32/48/64/256px и `Square*Logo.png`).
* **Tests:** Визуальная проверка на светлой и тёмной панели задач Windows + `tauri.conf.json` bundle check.

---

### Bug #9 [P1]: Предупреждения Windows SmartScreen и отсутствие Provenance-аттестации в релизном CI

* **Root Cause (`File:Line`):**
  * `.github/workflows/release.yml:97-110` собирает Windows-инсталляторы (`NSIS` / `MSI`) без цифровой подписи Authenticode и без SLSA Build Provenance, из-за чего 68% пользователей (аудитория Windows) сталкиваются с агрессивным блоком Microsoft SmartScreen.
* **Fix:**
  1. Добавить генерацию криптографического **GitHub Build Provenance Attestation** (`actions/attest-build-provenance@v2`, `id-token: write`, `attestations: write`) для всех артефактов релиза (`.dmg`, `.exe`, `.msi`, `.tar.gz`).
  2. Добавить опциональную/guarded джобу/шаг **SignPath.io OSS Authenticode Signing** в `.github/workflows/release.yml` (активируется при наличии `vars.SIGNPATH_ENABLED == 'true'` и секрета `SIGNPATH_API_TOKEN`, чтобы конвейер оставался зелёным до и после завершения верификации OSS-проекта в SignPath.io).
  3. Подкрепить UX-снижение отвала на Windows **2-кадровым визуальным гайдом SmartScreen / Gatekeeper** (Раздел 4.2.3).
* **Tests:** Dry-run проверка синтаксиса workflow (`actionlint` / `workflow_dispatch`) и прохождение `scripts/verify-release.mjs` с сохранённым набором ассетов и `latest.json`.

---

## 6. Pillar 5 — Миграция `AppState`, поэтапный план внедрения, E2E-матрица верификации и DoD

### 6.1. Обратно-совместимая миграция `AppState` (`v2.3.0 → v3.0.0`)

В `src-tauri/src/state/schema.rs` обновляем `CURRENT_SCHEMA_VERSION: u32 = 3` (`schema.rs:17`) с **100% обратной совместимостью** (все новые поля имеют `#[serde(default)]`, без удаления старых полей):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BunkerSettings {
    #[serde(default = "default_true")]
    pub auto_backup_enabled: bool,
    #[serde(default = "default_bunker_interval_hours")] // 24
    pub interval_hours: u32,
    #[serde(default = "default_bunker_retention")] // 7
    pub retention_count: usize,
    #[serde(default)]
    pub last_backup_at: Option<u64>,
    #[serde(default)]
    pub last_backup_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PersonaSelfCheck {
    #[serde(default)]
    pub bought_or_grey_account: bool,
    #[serde(default)]
    pub virtual_sms_used: bool,
    #[serde(default)]
    pub reseller_payment_used: bool,
    #[serde(default)]
    pub multi_account_same_browser: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CleanRoomState {
    #[serde(default)]
    pub profiles: Vec<crate::clean_room::CleanRoomProfile>,
    #[serde(default)]
    pub active_profile_id: Option<String>,
    /// IP-адреса/выходы, помеченные как скомпрометированные (бан/Persona), с Unix timestamp.
    #[serde(default)]
    pub tainted_ips: HashMap<String, u64>,
}
```
* **Поля, добавляемые в `AppStateData` (`state/schema.rs:189`):**
  * `#[serde(default)] pub clean_room: CleanRoomState`
  * `#[serde(default)] pub bunker: BunkerSettings`
  * `#[serde(default)] pub persona_self_check: PersonaSelfCheck`
  * `#[serde(default)] pub onboarding_v3_done: bool`
  * `#[serde(default)] pub whats_new_v3_seen: bool`
  * `#[serde(default)] pub dismissed_hints: Vec<String>`
* **Правила миграции `AppStateData::migrate` (`state/migration.rs:10`) и `state/persistence.rs:68`:**
  * **Однократный бэкап `state.v2.bak.json`:** перед выполнением миграции `v2 → v3` `state/persistence.rs:68` атомарно сохраняет однократную резервную копию `state.v2.bak.json` (если файл ещё не существует).
  * **Ноль потерь пользовательских данных `v2.3.0`:** `routes`, `provider_routes`, `default_route_id`, `profile_route_id`, `pinned_ips`, `trusted_exceptions`, `ip_history`, `ip_change_cooldown_until`, `last_safe_logout_at`, `custom_ai_domains`, `disabled_providers`, `cli_mode`, `sync_ai_tz_enabled` переносятся без изменений.
  * Для мигрированных пользователей `v2 → v3`: `whats_new_v3_seen` инициализируется как **`false`** (чтобы показать 3-карточный Upgrade Sheet *«Что нового в v3.0»*), а `onboarding_v3_done` перенимает статус `onboarding_v2_2_done` (с возможностью перезапустить обучение в любое время).
  * Для чистой новой установки `v3.0.0`: после прохождения 5-шагового онбординга выставляются `onboarding_v3_done = true` и `whats_new_v3_seen = true`.
  * Если в `v2.3.0` уже был запущен `warmup_started_at: Some(ts)` (`schema.rs:219`), он отображается и синхронизируется с активным Launchpad-профилем.
  * `bunker.auto_backup_enabled` для мигрированных пользователей инициализируется `true` по умолчанию.

### 6.2. Поэтапный план реализации (Phased Rollout)

| Фаза | Состав работ | Критерий приёмки фазы |
|---|---|---|
| **Phase 1: Core & Bug Fixes (Win + Mac)** | Фиксы **Bugs #1–#7** (`cache_cleaner.rs` + MSIX + process path filter + `remove_dir_contents` count, `GUIDE_OS_NETWORK` + `routing.ts`, `via_zastava_key` 3 preconditions, `fc00::/18` + anti-SSRF public `hickory`/DoH `A`/`AAAA` fallback, `sysproxy:macos` dedup, Route Toggle OFF→Direct с проверкой `profile_route_id`, глобальный `cowork-guard://status` баннер + `watchers.rs:270` + mount fetch). | Все новые unit/integration-тесты зелёные; `check-architecture.mjs` зелёный. |
| **Phase 2: Чистая комната & Песочница** | Модуль `src-tauri/src/clean_room/*`, per-profile loopback listener alias (full AI + non-AI `CONNECT` & `plain HTTP` без `transit_tunnel` fallback, alias-порты в `validate_tunnel_target`/`is_gateway_loop`, block при `manual_killswitch`, hardened Chromium flags + `<profile>/Default/Preferences`), миграция `AppState v3` + `state.v2.bak.json`, UI `src/features/clean-room/` + 4-step Launchpad + прямой вход «Оплата и прогрев». | Pre-flight аудит на Win (Classic + MSIX) и Mac, Hard Readiness Gate, параллельный запуск изолированного Chrome/Edge без non-AI утечек и с fail-closed профилем. |
| **Phase 3: SOS, Бункер и Индекс риска** | Модуль `src-tauri/src/bunker/*` (Claude + Cursor + Web JSON/ZIP helper + 7-snapshot retention), `auditor/persona_risk.rs`, интерактивное дерево `src/features/sos/`, 1-click переход `Account disabled` → Чистая комната (`navStack` push). | Автобэкап работает в фоне с ротацией `7` снапшотов, `restore_prompt.md` копируется через `writeClipboard`, SOS Persona RU-docs доводит до Бункера и Plan B. |
| **Phase 4: UI/UX, Онбординг, Навигация, Маскот, Иконки и Трей** | Каркас «Разделы» (`src/features/shell-v3/`) с реальным `navStack` и `AlertStrip` (`460×660` zero-scroll `~610–635px`), 5-шаговый онбординг `onboarding_v3_done` + переписанный `ru/onboarding.ts`, `WhatsNewSheet` (`whats_new_v3_seen`), `HintCard` (`dismissed_hints`), click+hover `InfoTip`, `EmptyState`, 5-состоячный `WatchdogMascot` (0% idle CPU), унификация `tray/events.rs` + `PowerPill` sync, `src-tauri/icons/*` + `tray-gray.png`, `.github/workflows/release.yml` (Bug #9). | `pnpm lint:hex`, `check-tray-main-thread.mjs`, `check-architecture.mjs`, визуальный аудит `460×660` (zero scroll в норме) и `440×470` без скролла в popup. |
| **Phase 5: Full E2E, Adversarial QA & Release** | Полный прогон кроссплатформенной E2E-матрицы из 16 сценариев (ниже), adversarial-ревью независимым агентом, обновление `CHANGELOG.md` / `README.md`, release tag `v3.0.0` и мониторинг CI до зелёного `publish`. | Все 16 E2E-сценариев пройдены на macOS и Windows без регрессий `v2.3.0`. |

### 6.3. Обязательная сквозная E2E-матрица пользовательских сценариев (macOS + Windows 68%)

Согласно стандарту качества проекта, изолированные happy-path unit-тесты **недостаточны**. Перед релизом `v3.0.0` каждый сценарий проверяется в реальном или максимально приближённом к боевому окружении:

1. **Обрыв и смена сети / Прыжок ASN `< 4h`:**
   * Эмуляция/реальный обрыв VPN и смена `AS_A -> AS_B` внутри одной страны (`DE -> DE`) → `alert-popup` (`440×470` без прокрутки), блокировка трафика до решения пользователя, `executeAllowSequence` + сохранение `trusted_exceptions`.
2. **Windows MSIX Store Claude & ChatGPT Clean-Room Wipe (и защита Claude Code CLI):**
   * Наличие файлов в `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude` при запущенных Claude Desktop и терминальном **Claude Code CLI (`claude.exe`)** → «Детектор хвостов» блокирует запуск (`ready_to_launch == false`) → 1-click fix закрывает только MSIX/Desktop процесс (не убивая Claude Code CLI!), чистит `Cookies`/`ant-device-registry.json`, **строго сохраняет `claude_desktop_config.json`**, залоченные файлы честно попадают в `locked_targets` (не в `files_removed`), открывает Hard Readiness Gate. При повторном запуске на чистой директории тост показывает нейтральный «уже чист».
3. **Coexistence с TUN Fake-IPv6 (`fc00::/18`) и Anti-SSRF порядок резолва:**
   * Системный DNS возвращает `fc00::1` / `198.18.0.1` или мусорный локальный IP для entry-хоста маршрута Заставы → `resolve_entry_checked_with` не падает ранним `?`, **сначала** вызывает public `hickory` (`1.1.1.1`/`8.8.8.8`) + DoH (`A`/`AAAA`) для получения реального публичного IP, принимая Fake-IP лишь как last-resort при отказе public DNS/DoH под активным TUN, и логирует отклонённые IP в `diagnostics::record("routing:dns", ...)`.
4. **Route Toggle OFF → Direct vs Fail-Closed & `profile_route_id` Priority Trap:**
   * Выключение активного привязанного маршрута в `VPN и ключи` → выбор «Остановить (блокировать)» оставляет fail-closed блок; выбор «Перейти на свой VPN (Direct)» безопасно снимает привязки. При привязке через `profile_route_id` диалог отдельно запрашивает подтверждение `handleResetActiveProfileRoute()` с предупреждением о мультиаккаунт-изоляции.
5. **Предусловия оценки DNS с активным «ВПН Заставы» (`via_zastava_key`):**
   * На домашнем РФ-интернете при активном ключе Заставы, `usable = true`, `is_sysproxy_active() == true` и `!os_pac_deferred` → `dns` показывает `Ok("DNS_KEY_REMOTE_RESOLVE")` (с пояснением про non-AI трафик) и `trust_score >= 95`. При выключенном `sysproxy` или `os_pac_deferred == true` или в режиме `Direct` предупреждение `DNS_DOMESTIC_WARNING` (`-15`) остаётся активным.
6. **Песочница: изоляция non-AI `CONNECT` / `plain HTTP`, alias SSRF и `manual_killswitch`:**
   * Личный Chrome с открытой вкладкой (Сбербанк/почта) продолжает работать напрямую; два параллельных чистых окна с разными маршрутами изолируют через `bound_route_id` **весь** трафик — включая Stripe, `withpersona.com`, Cloudflare Turnstile, Apple/Auth0 OAuth, `ipinfo.io` и `plain HTTP` — без fallback в `transit_tunnel`. Попытка подключения к ephemeral alias-порту через туннель отклоняется `validate_tunnel_target`/`is_gateway_loop`; при `manual_killswitch == true` `launch_clean_browser` блокируется; при запуске на устаревшем порту старое окно профиля перезапускается.
7. **Chromium Fail-Closed `Preferences` и hardened-флаги вне Zastava:**
   * Проверка сгенерированного `<profile>/Default/Preferences` (`proxy.mode = "fixed_servers"`, `dns_over_https.mode = "off"`) и аргументов запуска (`--host-resolver-rules`, `--proxy-bypass-list`, `--disable-quic`, `--disable-features=DnsOverHttps`, отсутствие `--disable-features=WebRtcHideLocalIpsWithMdns`). Повторный запуск того же профиля напрямую (при закрытой Zastava) блокирует сеть fail-closed без утечки в ISP DNS/HTTP3.
8. **SOS Persona (РФ-доки) + Бункер данных + Восстановление контекста (и Web-only):**
   * Ветка `Persona → Только РФ доки` выдаёт красный `STOP` → 1-click «Сохранить в Бункер» экспортирует `~/.claude` + Cursor + ротация `7` снапшотов → копирование `restore_prompt.md` через нативный буфер (`writeClipboard`) → переход в `Account disabled` → 1-click в Чистую комнату с автоматическим добавлением старого IP в `tainted_ips`. Для веб-пользователя без `~/.claude` при `0` снапшотах открывается `EmptyState` с Web Export Helper.
9. **Фоновый `CoworkVMService` алерт на Windows (на mount и при `Start=3`):**
   * При закрытом `SettingsModal` сразу на mount (`getCoworkGuardStatus()` без ожидания 5с) и по `cowork-guard://status` при `needs_repair === true` появляется спокойный жёлтый баннер с 1-click Repair; в `watchers.rs:270` при `task_installed && service_running && !is_claude_process_running()` срабатывает авто-триггер guard-задачи.
10. **Синхронизация трея, `PowerPill` и анимаций (`~0%` idle CPU):**
    * Переключение защиты из системного трея (`tray/events.rs`) синхронизирует CLI-тумблер и `os_tz::restore_if_synced_on_disable` и эмитит фактический статус (без ложного `!active` при ошибке); `PowerPill` заблокирован при `startupPending || togglingSysproxy` и перечитывает статус после ошибок; при выключении защиты трей переходит в `tray-gray.png`; при `visibilityState === "hidden"` `WatchdogMascot` ставится в `.zs-mascot--paused`.
11. **Миграция `state.json` `v2.3.0 → v3.0.0` + `state.v2.bak.json` + Upgrade Sheet:**
    * Загрузка реального `state.json` + `profiles.json` от `v2.3.0` → однократно создаётся `state.v2.bak.json`, `schema_version` обновляется до `3`, ни одна настройка не потеряна, `whats_new_v3_seen == false` открывает 3-карточный sheet *«Что нового в v3.0»* с кнопкой «Пройти знакомство заново».
12. **5-шаговый v3.0 Онбординг первого запуска (`onboarding_v3_done`):**
    * На чистом профиле выбор цели на Шаге 1 (*Чистая комната* / *SOS*) + анимация Split-Routing на Шаге 2 (со сворачиваемым SmartScreen/Gatekeeper) + Шаги 3–5 автоматически приводят на выбранный экран и выставляют `onboarding_v3_done = true` и `whats_new_v3_seen = true`; в текстах нет устаревших отсылок к `v2.2` и старым вкладкам.
13. **Реальная навигация `navStack` без тупиков:**
    * `Проверки` (выбран провайдер) → `Что исправить` (`guide_ref`) → `Гайды` → `← Назад` возвращает в `Проверки` с сохранённым `checksProvider`; `Чистая комната Шаг 4` → `Гайд по оплате` → `← Назад` возвращает на Шаг 4; `SOS (Ветка 4)` → `Чистая комната` → `← Назад` возвращает в `SOS`; «Проверка карты (BIN) и адрес США 0%» доступна и через быструю подвкладку «Оплата и прогрев», и из «Гайда по оплате», а «Краш-тест» виден вверху «Проверок».
14. **Контекстные подсказки (`HintCard`, click+hover `InfoTip`, `EmptyState`):**
    * Первый вход в каждый из 5 разделов, «Чистую комнату» и `SOS` показывает `HintCard` с сохранением в `dismissed_hints`; клик (а не только hover) по `InfoTip` раскрывает пояснения ключевых терминов; «Сбросить подсказки и обучение» в `SettingsModal` возвращает подсказки; проверены `EmptyState` для `0` профилей, `0` маршрутов и `0` браузеров.
15. **Жёсткий визуальный бюджет окна `460×660` (Zero-Scroll Home Hub):**
    * Проверка на Windows и macOS при DPI `100%`/`125%`: в штатном состоянии Home Hub с горизонтальным Hero, 5 разделами и `StopNetwork` укладывается в `~610–635px` без вертикального скролла; при нескольких одновременных баннерах `AlertStrip` схлопывается до `1` приоритетного баннера + `ещё N`.
16. **Повторяемость Bug #2 (`GUIDE_OS_NETWORK`) & CLI / Release CI:**
    * Клик «Что исправить» у DNS / IPv6 / STUN открывает `OsGuide` на секции сети/DNS (`part: "geo"`), а не на часовом поясе (`part: "tz"`); `scripts/verify-release.mjs` и `actions/attest-build-provenance` проходят без регрессий.

### 6.4. Definition of Done (DoD) для `v3.0.0`

Релиз `v3.0.0` считается готовым только при выполнении **всех** условий:
* `node scripts/check-architecture.mjs --self-test` — **PASS** (пустой `LEGACY_ALLOWLIST`, все prod-файлы `≤ 500` строк).
* `node scripts/check-tray-main-thread.mjs --self-test` — **PASS**.
* `pnpm lint:hex` — **PASS** (`0` raw hex/rgb в компонентах).
* `pnpm build && pnpm test` — **PASS**.
* `cargo test --manifest-path src-tauri/Cargo.toml && cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets` — **PASS** (0 warnings).
* `node --test scripts/*.test.mjs` — **PASS**.
* Все **16 E2E-сценариев** из Раздела 6.3 подтверждены на macOS и Windows; релизный workflow `.github/workflows/release.yml` полностью зелёный до `publish` без застревания в `draft`.
