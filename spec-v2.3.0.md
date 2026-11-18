# Спецификация Zastava v2.3.0 (`spec-v2.3.0.md`)

> **Статус:** Реализовано и выпущено в релизе `v2.3.0` (Tag: `v2.3.0`).
> **Стек:** Rust (`edition = "2024"`) + Tauri v2 + React 19 / TypeScript / Vite / Tailwind CSS 4.

---

## Раздел A. Модульная архитектура и Конституция (`CONSTITUTION.md`)

### A.1. Целевая 4-слойная архитектура (`src-tauri/src/` и `src/`)

В `v2.3.0` кодовая база настольного приложения переведена на гибридную архитектуру **Clean Hexagonal (Ports & Adapters) + Vertical Domain Slices** (документирована в [`ARCHITECTURE.md`](ARCHITECTURE.md) и закреплена в [`CONSTITUTION.md`](CONSTITUTION.md)):

```text
Layer 3: Delivery / Shell
  main.rs, lib.rs (composition root)
  app/ (mod, watchers, deep_links, ...)
  commands/* (тонкие IPC-адаптеры без бизнес-логики)
  tray/, popup.rs, startup.rs, autostart.rs
    │
    ▼
Layer 2: Domain Services & Platform Adapters
  proxy/{guard, server, coverage, transit, upstream, pac, hold_queue}
  auditor/{checks, network, seams, profile_switcher, probes, leaks, ...}
  sysproxy/{platform, browser_policies, journal, cleanup, macos, windows, relaunch}
  updater/, cowork_guard/, os_tz/, diagnostics/, bin_checker/, win_reg/
  (взаимодействие с Layer 3 только через Trait Ports / callbacks)
    │
    ▼
Layer 1: State & Routing Contracts
  state/{schema, migration, persistence, stats, pinning, routes, exceptions, settings}
  routing/{mod, key, net}
    │
    ▼
Layer 0: Core Primitives (0 зависимостей на Tauri и доменные сервисы)
  core/{mod, net_safety, sanctions, redact, shutdown, timing}
```

Ключевые структурные изменения:
* **Layer 0 (`src-tauri/src/core/`):** единые примитивы без дублирования — `net_safety.rs` (SSRF/special-IP/`is_tun_fake_ip`), `sanctions.rs`, `redact.rs` (маскировка секретов и санитизация диагностик), `shutdown.rs`, `timing.rs`.
* **Инверсия контроля через Ports:**
  * `NetworkGuard` (`src-tauri/src/proxy/guard/`) разбит на модули (`mod.rs`, `types.rs`, `gates.rs`, `policy.rs`, `audit_summary.rs`, `audit_outcome.rs`, `alerts.rs`, `baseline_restore.rs`, `decisions.rs`, `killswitch.rs`, `orchestrator.rs`, `probe_apply.rs`, `probe_loop.rs`, `routes_sync.rs`, `session_confirm.rs`, `waiter.rs`) и не импортирует `commands::*`, `app::*`, `tray::*`.
  * `sysproxy/relaunch.rs` содержит порт перезапуска (`AppLauncher` / `RealLauncher` / `QuitTiming`), разрывая прежний обратный цикл `sysproxy` → `commands::restart_app`.
  * Взаимный цикл `sysproxy` ↔ `proxy::coverage` устранён; бизнес-логика и санитизация вынесены из `commands/` в `diagnostics/`, `proxy/allow_error.rs` и `commands/interception/helpers.rs`.
* **Разделение prod / fakes / tests:** тестовые двойники вынесены в `fakes.rs` под `#[cfg(any(test, feature = "test-support"))]`, а крупные тестовые наборы — в отдельные `tests.rs` / `*_tests/` (например, `src-tauri/src/proxy/guard_tests/`, `src-tauri/src/state/tests/`, `src-tauri/src/routing/net/tests.rs`).
* **Изоляция фронтенда (`src/utils/api/`):** монолитный `src/utils/api.ts` сохранён как re-export barrel для обратной совместимости, а транспорт `invoke()` / `listen()`, доменные модули (`audit.ts`, `coverage.ts`, `diagnostics.ts`, `events.ts`, `gateway.ts`, `interception.ts`, `profiles.ts`, `routes.ts`, `sysproxy.ts`, `updater.ts`) и браузерные моки (`src/utils/api/mocks/`) строго изолированы вокруг `src/utils/api/client.ts`. `SettingsModal.tsx` декомпозирован с выделением `useSettingsController.ts` и секционных компонентов.

### A.2. Бюджеты строк, Guardrails и Zero-Regression Baseline

Правила [`CONSTITUTION.md`](CONSTITUTION.md) (проверяются автоматически в [`scripts/check-architecture.mjs`](scripts/check-architecture.mjs)):
* **Production-файлы (`src-tauri/src/`, `src/`):** мягкий лимит **≤ 350 строк**, жёсткий лимит **≤ 500 строк**.
* **Тестовые файлы и inline-тесты:** жёсткий лимит **≤ 700 строк**; inline `#[cfg(test)] mod` допустим только при общем размере файла **≤ 400 строк**.
* **`LEGACY_ALLOWLIST` обнулён:** в `scripts/check-architecture.mjs` `rustProd: {}` и `rustTest: {}` пусты (проверено на 300 Rust `src`-файлах, 15 интеграционных тестах и 223 фронтенд-файлах).
* **Инварианты безопасности и контрактов (Zero Regression):**
  * Fail-closed маршрутизация (`__direct__`, `profile:invalid`, `manual_killswitch`), изоляция `pinned_ips["anthropic"]`.
  * Signed-only updater (`tauri-plugin-updater` + `UPDATER_PUBKEY`).
  * Запрет `RealPlatform` в тестах, изоляция трея (`scripts/check-tray-main-thread.mjs`), 0 сырых hex/rgb цветов (`scripts/check-no-hex.mjs` / `pnpm lint:hex`), запрет `.unwrap()` / `.expect()` / `println!` на runtime-путях.
  * 100% обратная совместимость `state.json`, `profiles.json`, всех Tauri-команд и событий.

---

## Раздел B. Пользовательские кейсы и Anti-Fraud Hardening

### B.1. Надёжный буфер обмена на macOS и строгий откат `apply_pac`

1. **Нативный буфер обмена (`src/shared/lib/clipboard.ts`):**
   * Устранена ошибка `NotAllowedError` в `WKWebView` на macOS при копировании после асинхронных IPC-операций (например, в `useClaudeBackup.ts` после `exportClaudeLocalData()`).
   * Единый helper `writeClipboard(text)` работает по цепочке: нативная Tauri-команда `copy_text_to_clipboard` (`pbcopy` на macOS / Win32 `CF_UNICODETEXT` на Windows) → `navigator.clipboard.writeText` → `document.execCommand("copy")`.
   * На `writeClipboard` переведены `CopyErrorLogButton.tsx`, `useClaudeBackup.ts`, `useProtectionToggles.ts`, `usePinning.ts`, `useCopy.ts`, `useSettingsController.ts`.
2. **Строгий откат `AdminAuthRequired` в `apply_pac` (`src-tauri/src/sysproxy/macos/apply.rs`, `src-tauri/src/app/mod.rs`):**
   * При `AdminAuthRequired` (exit code `14` у `networksetup`) на любой физической сетевой службе (включая chain/bypass) `apply_pac` откатывает частичные изменения и возвращает `Err(MSG_ADMIN_AUTH_REQUIRED)` вместо ложного `sysproxy_active = true`.
   * Ошибки прав на автостарте пробрасываются в UI через событие `sysproxy://admin-auth-required` (`src/utils/api/events.ts`, `useTrayEvents.ts`) с предложением «Разрешить с паролем».

### B.2. Устойчивость маршрутов поверх другого VPN на Windows

1. **Fallback через `chained_proxy` (`src-tauri/src/proxy/upstream/chained.rs`, `entry_connect.rs`, `handshakes.rs`):**
   * Если прямой TCP-коннект до публичной entry-ноды падает или уходит в таймаут при активном `chained_proxy` (внешний VPN с системным прокси), маршрут подключается к entry-ноде через `chained_proxy` (HTTP CONNECT / SOCKS5) с защитой от петель на loopback, приватные подсети и сам `chained_proxy`, полностью сохраняя fail-closed для целевого ИИ-трафика.
2. **Happy Eyeballs и `SO_KEEPALIVE` (`src-tauri/src/proxy/upstream/handshakes.rs`, `src-tauri/src/proxy/transit.rs`):**
   * В `tcp_connect_addrs` внедрён конкурентный `race_connect` (`HAPPY_EYEBALLS_STEP = 250ms`) с чередованием IPv6/IPv4 адресов.
   * Включён `SO_KEEPALIVE` (`time = 30s`, `interval = 10s` через `socket2`) для предотвращения подвисания долгих HTTP/2 и SSE потоков в half-open состоянии при NAT-таймаутах VPN.
3. **Бюджет таймаутов DNS vs Connect и 2-часовой аварийный stale-fallback (`src-tauri/src/routing/net/mod.rs`, `dns.rs`, `proxy/server/mod.rs`):**
   * `ROUTE_ENTRY_TIMEOUT_SECS` увеличен до `12` с (`proxy/server/mod.rs`).
   * Системный DNS сокращён до `1200` мс, резервный `hickory-resolver` + DoH распараллелены в окно `2500` мс, чтобы fallback успевал отработать внутри бюджета маршрута.
   * Штатный `ENTRY_DNS_STALE_TTL = 900` с (15 мин) дополнен аварийным stale-кэшем до `7200` с (2 часа) с фоновым обновлением при деградации DNS.
4. **Телеметрия отказов `[proxy:route]` (`proxy/server/route_guard.rs`, `proxy/upstream/{mod,entry_connect}.rs`, `routing/net/mod.rs`):**
   * Запись фаз отказа (`dns`, `tcp_direct`, `tcp_chained`, `tls`, `connect`) в `diagnostics::record("proxy:route", ...)` без утечки секретов и паролей ключей.

### B.3. Anti-Fraud Hardening (разбор кейса бана Amnezia DE → is.hosting DE + Playerok)

1. **Перехват прыжка между ASN/ДЦ внутри одной страны (`src-tauri/src/auditor/history.rs`, `src-tauri/src/proxy/guard/policy.rs`):**
   * `evaluate_impossible_travel_with_exit` проверяет `<4h` окно не только при смене страны (`prev_country != current_country`), но и при смене ненулевых ASN (`prev_asn != current_asn` и `prev_ip != current_ip`) внутри одной страны (например, `DE -> DE`), возвращая `TRAVEL_ASN_JUMP_SAME_COUNTRY` (при этом смена IP внутри одного провайдера `AS_A -> AS_A` и `TRAVEL_PINNED_RETURN` не дают ложного срабатывания).
   * `NetworkGuard` не выполняет тихий `accept_locked` при `TRAVEL_ASN_JUMP_SAME_COUNTRY` или активном 4-часовом кулдауне смены IP — требуется явное подтверждение пользователя в `alert-popup` (с корректным переносом длинных причин в `.zs-alert-reason` через `overflow-wrap: anywhere` в `src/features/alert/alert.css`).
2. **Безопасный выход и 4-часовой таймер (`auditor/profile_switcher/safe_logout.rs`, `commands/claude.rs`, `state/schema.rs`, `state/settings.rs`, `CooldownBanner.tsx`):**
   * Команда `safe_logout_claude_cmd` (`safe_logout_claude`) мягко завершает процессы Claude Desktop и помощников (только при `os_effects_enabled()`), удаляет только cookies и session storage (`Cookies`, `Local Storage`, `Session Storage`, `IndexedDB`, `WebStorage`, `SharedStorage`, `DIPS`) и OAuth-токены CLI, **строго сохраняя `ant-device-registry.json` (`deviceId`), `ccd-ids.json`, `claude_desktop_config.json` и `.claude/settings.json`**.
   * В `AppStateData` добавлены `ip_change_cooldown_until` и `last_safe_logout_at` (`#[serde(default)]`); запускается 4-часовой таймер (`14400` с) с живым обратным отсчётом в `CooldownBanner.tsx` и ручным сбросом `clear_ip_change_cooldown_cmd`.
3. **Реальный Reverse DNS (PTR) lookup (`auditor/seams/dns/`, `auditor/network/mod.rs`):**
   * В `DnsLookup` / `SystemDns` добавлен `reverse_ptr` на базе `hickory_resolver::TokioResolver::reverse_lookup`; `evaluate_reverse_dns_ptr_with_dns` проверяет реальную PTR-запись выходного IP (`rdns:ptr`).
4. **Честный статус Datacenter IP и обновление гайдов (`auditor/ip_type.rs`, `rules/guides/*.md`, `providers.ts`, `hostings.ts`):**
   * `IpType::Hosting` честно отображается как «Datacenter / VPS IP (не резидентский)» с напоминанием избегать резких смен IP/ASN.
   * Хостер `is*hosting` заменён на **Vultr** (`https://www.vultr.com/?ref=9936768`); убраны обещания «100% защиты» и «идеального ASN»; добавлено жёсткое предупреждение против реселлеров оплаты (`Playerok`, `FunPay`, Telegram-ботов, чужого Apple Pay) и переключения VPN на лету через `Cmd+Q`.

---

## Раздел C. Релизные артефакты, верификация и E2E-покрытие

### C.1. Релизные артефакты и документация

* [`CONSTITUTION.md`](CONSTITUTION.md) — архитектурная конституция проекта.
* [`ARCHITECTURE.md`](ARCHITECTURE.md) — актуализирована под `v2.3.0` и 4-слойную архитектуру.
* [`scripts/check-architecture.mjs`](scripts/check-architecture.mjs) — CI-проверка бюджетов строк, ацикличного графа зависимостей и изоляции `invoke()` с пустым `LEGACY_ALLOWLIST`.
* [`CHANGELOG.md`](CHANGELOG.md) — раздел `[2.3.0] — 2026-11-18`.

### C.2. E2E-сценарии и верификационные гейты `v2.3.0`

* **Маршрутизация и `chained_proxy` (`src-tauri/tests/routing_fail_closed.rs`):** E2E-тест `test_public_route_falls_back_via_chained_proxy_when_direct_fails` проверяет автоматический fallback через локальный `chained_proxy` при отказе прямого подключения к публичному entry-узлу, а также fail-closed при отказе обоих путей.
* **DNS-фолбэк и аварийный stale-кэш (`src-tauri/src/routing/net/tests.rs`):** покрытие бюджета DNS-таймаутов, 2-часового аварийного stale-кэша (`7200` с) и записи `[proxy:route]` при полном отказе резолверов.
* **Anti-Fraud и 4h Cooldown (`src-tauri/src/proxy/guard_tests/asn_cooldown_tests.rs`, `auditor/history.rs`, `auditor/profile_switcher/safe_logout.rs`, `state/tests/persistence.rs`):**
  * Перехват `TRAVEL_ASN_JUMP_SAME_COUNTRY` при смене ASN в одной стране (`DE -> DE`) и отсутствие ложного алерта при `AS_A -> AS_A` / `TRAVEL_PINNED_RETURN`.
  * Персистентность `ip_change_cooldown_until` в `state.json` и блокировка тихого `accept_locked` во время кулдауна.
  * Тест `safe_logout_claude_fs_in`: удаление auth/session storage при строгом сохранении `ant-device-registry.json`, `ccd-ids.json` и `claude_desktop_config.json`.
* **macOS `apply_pac` и буфер обмена:** unit-тесты на откат при частичном `AdminAuthRequired` в `sysproxy/macos/` и Vitest-тесты на fallback-цепочку `writeClipboard` и `useClaudeBackup`.
* **Полный CI-гейт:** `node scripts/check-architecture.mjs --self-test`, `node scripts/check-tray-main-thread.mjs --self-test`, `pnpm lint:hex`, `pnpm build`, `pnpm test`, `node --test scripts/*.test.mjs`, `cargo test --manifest-path src-tauri/Cargo.toml`, `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets`.
