# Конституция архитектуры Застава (`CONSTITUTION.md`)

> Обязательный стандарт разработки и сопровождения настольного приложения **Застава** (v2.3.0+).  
> Все правила проверяются автоматически в CI с помощью [`scripts/check-architecture.mjs`](scripts/check-architecture.mjs), [`scripts/check-tray-main-thread.mjs`](scripts/check-tray-main-thread.mjs) и [`scripts/check-no-hex.mjs`](scripts/check-no-hex.mjs).

---

## 1. Область действия (Scope)

Конституция распространяется исключительно на код **настольного приложения**:
- Backend: `src-tauri/src/` и `src-tauri/tests/`
- Frontend: `src/`

Вспомогательный веб-аудитор `site/`, дизайн-песочница `design/`, а также генерируемые схемы (`src-tauri/gen/`) не подпадают под действие этих лимитов.

---

## 2. Бюджет размера файлов (Agent-Context First)

Ограничение размера файлов удерживает каждый модуль в пределах одного контекстного окна и предотвращает появление god-объектов:

1. **Production-файлы (Rust и TypeScript/React/CSS)**:
   - Мягкий предел: **≤ 350 строк**
   - Жёсткий предел: **≤ 500 строк** (исключая генерируемые схемы и чистые декларативные таблицы данных).
   - Для файлов Rust считаются только строки production-кода (до начала секции тестов `#[cfg(test)] mod ...`).
2. **Тестовые файлы и inline-тесты**:
   - Жёсткий предел: **≤ 700 строк** (как для `tests.rs` / `tests/*.rs` / `src-tauri/tests/*.rs` / `*.test.ts`, так и для inline-модуля `#[cfg(test)] mod tests`).
   - **Правило inline-тестов**: встроенный `#[cfg(test)] mod ...` допускается **только если общий размер файла ≤ 400 строк**. Если файл превышает 400 строк, тесты должны быть вынесены в отдельный `tests.rs` или `tests/*.rs`.
3. **Изоляция тестовых двойников (`fakes`)**:
   - Тестовые двойники (`FakePlatform`, `FakePolicyStore`, `FakeFs`, `fakes` и аналоги) запрещено размещать в production-файлах.
   - Они должны находиться в выделенных файлах `fakes.rs` (или `fakes/*.rs`) под защитой `#[cfg(any(test, feature = "test-support"))]`.

*(На время поэтапной миграции v2.3.0 нетронутые legacy-монолиты зафиксированы в `LEGACY_ALLOWLIST` внутри `scripts/check-architecture.mjs` с верхними порогами, не допускающими их дальнейшего роста. По завершении рефакторинга `LEGACY_ALLOWLIST` обнуляется.)*

---

## 3. Ацикличная 4-слойная архитектура (`src-tauri/src/`)

Зависимости между модулями ядра строго однонаправлены сверху вниз:

```text
Layer 3: Delivery / Shell
  app/, commands/, tray/, popup, startup, autostart
    │
    ▼
Layer 2: Domain Services & Platform Adapters
  proxy/, auditor/, sysproxy/, updater/, cowork_guard/, os_tz/, diagnostics/, bin_checker/
    │  (обращаются к Layer 3 только через Trait Ports / callbacks!)
    ▼
Layer 1: State & Routing Contracts
  state/, routing/
    │
    ▼
Layer 0: Core Primitives (0 зависимостей на Tauri и доменные сервисы)
  core/ (net_safety, sanctions, redact, errors)
```

### Жёсткие запреты зависимостей:
1. **Запрет импортов снизу вверх**: модули Layer 0–2 (`core/`, `state/`, `routing/`, `proxy/`, `auditor/`, `sysproxy/`, `updater/`, `cowork_guard`, `os_tz`, `diagnostics`, `bin_checker/`) **не имеют права** импортировать `crate::commands`, `crate::app` или `crate::tray`. Обратная связь с оболочкой (уведомления, алерт-окна, обновление трея, перезапуск) строится только через порты (traits) или события.
2. **Изоляция Layer 0 (`core/`)**: `src-tauri/src/core/` не зависит от `tauri`, `commands`, `app`, `tray`, `proxy`, `auditor`, `sysproxy`, `state` и `routing`.
3. **Запрет циклов на одном слое**: между независимыми доменами Layer 2 запрещены двунаправленные импорты (например, цикл `sysproxy` ↔ `proxy::coverage` должен быть разорван вынесением общих контрактов/дескрипторов вниз).
4. **Тонкие IPC-адаптеры (`commands/*`)**: модули в `src-tauri/src/commands/` выполняют только десериализацию аргументов, вызов доменного сервиса/состояния, обновление UI/трея (при необходимости) и маппинг ошибок. Вся бизнес-логика, парсинг системного вывода, санитизация диагностик и многошаговая оркестрация выносятся в Layer 2 / Layer 0.

---

## 4. Изоляция фронтенда (`src/`)

1. **Единая транспортная граница (`invoke`)**: прямые вызовы Tauri `invoke(...)` разрешены **только** внутри `src/utils/api/` (`src/utils/api/client.ts` и legacy-фасад `src/utils/api.ts`). Экраны, фичи и хуки работают с бэкендом исключительно через типизированные модули `src/utils/api`.
2. **Разделение транспорта и моков**: браузерный dev-режим (`!isTauri()`, `?mockVpn=` и др.) изолирован в `src/utils/api/mocks/`, не смешиваясь с реальными IPC-адаптерами.
3. **Изоляция дизайн-системы**: 0 сырых hex-цветов (`#rrggbb`), `rgb()` и `rgba()` в `src/ui/` и `src/features/` — используются только CSS-переменные из `src/styles/tokens.css` (контролируется `pnpm lint:hex`).

---

## 5. Инварианты безопасности и нулевой регрессии (Zero Regression)

Следующие контракты и защитные механизмы неприкосновенны при любых изменениях:

1. **Fail-Closed маршрутизация**:
   - Несуществующий, отключённый, истёкший или некорректный маршрут (`__direct__`, `profile:invalid`, `manual_killswitch`) обязан отклонять соединение и никогда не откатываться в прямой выход без явного разрешения пользователя.
   - Привязка `profile_route_id` действует только на целевого провайдера (`anthropic`) и не протекает на других провайдеров.
2. **Signed-Only Updater**:
   - Обновления устанавливаются только через `tauri-plugin-updater` с проверкой подписи ключом `UPDATER_PUBKEY`. Запрещены legacy-загрузчики, URL из фронтенда и внешние команды установки (`hdiutil`, `msiexec`, `download_and_install_legacy`).
3. **Безопасность тестов и ОС (`RealPlatform` Guard)**:
   - В `src-tauri/tests/` и во всём `#[cfg(test)]` / `test-support` коде запрещено ссылаться на `RealPlatform` — для тестов используются только `FakePlatform` и `os_effects_enabled() == false` (`force_os_dry_run()` / `test-support`).
4. **Безопасность трея (Main-Thread Guard)**:
   - Все обращения к `TrayIcon`, `MenuItem` и их клонам вне `src-tauri/src/tray/` запрещены и должны выполняться только через функции `tray::with_tray_on_main` (проверяется `scripts/check-tray-main-thread.mjs`).
5. **Защита секретов и надёжность runtime-путей**:
   - В `Debug`-выводе, логах, событиях и диагностических архивах секреты, пароли и ключи `zastava://` обязательно маскируются (`core::redact`, `redacted_for_ui`).
   - В production-коде на путях обработки клиентских запросов запрещены `.unwrap()`, `.expect()` и `println!`.
6. **Обратная совместимость контрактов**:
   - Форматы `state.json` (миграции v0/v1/v2.2.0/v2.2.1), `profiles.json` (UTF-8 BOM-safe), имена и сигнатуры всех Tauri-команд, структур ошибок (`AllowError`, `UpdateFailure`) и Tauri-событий сохраняются на 100%.
