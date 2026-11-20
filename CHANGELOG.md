# История изменений (Changelog)

Все заметные изменения проекта **Застава** документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
и проект придерживается [Семантического версионирования](https://semver.org/lang/ru/).

---

## [3.0.0] — 2026-11-20

Крупный мажорный релиз **Застава v3.0.0**: новая оболочка «Разделы» с маскотом-сторожем и 4-состоянным треем, интерактивная «Чистая комната» с изолированной песочницей браузеров (пер-профильный loopback proxy alias), бесплатный локальный Бункер с экспортом Cursor и веб-чатов, антикризисный раздел «SOS-верификация» с индексом риска `Persona Risk Index`, очистка кэша Windows MSIX Claude, защита DNS-проб под TUN Fake-IPv6 (anti-SSRF) и SLSA-аттестации сборок GitHub Build Provenance.

### Добавлено
* **Оболочка v3 «Разделы» и маскот-сторож (`src/features/shell-v3/`, `src/features/mascot/`, `src/app/AppShell.tsx`):**
  * Новый главный экран-хаб (`HomeHub`, `SectionList`, `PowerPill`, `ProtectedRows`, `ServicesPage`, `StopNetwork`, `WhatsNewSheet`) с единым центром управления, компактной навигацией по разделам и экраном «Что нового».
  * Анимированный маскот-сторож (`WatchdogMascot`, `KillSwitchAnim`, `CleanRoomRadarAnim`, `SplitRoutingAnim`, `SmartScreenGuide`) для наглядного отображения состояний шлюза и подсказок.
* **«Чистая комната» и Browser Sandbox с пер-профильным loopback proxy alias (`src-tauri/src/clean_room/`, `src-tauri/src/proxy/server/alias.rs`, `src-tauri/src/commands/clean_room.rs`, `src/features/clean-room/`):**
  * Пошаговый мастер чистого запуска (`PreFlightAuditCard`, `LaunchpadSteps`, `SandboxProfilesCard`): проверка остаточных процессов и переменных окружения (`detector.rs`, `detector_env.rs`), обнаружение браузеров (`browser_discovery.rs`) и контроль часового пояса (`tz_guard.rs`).
  * Изолированная песочница профилей браузера (`browser_sandbox.rs`) с выделенным loopback-alias прокси (`proxy/server/alias.rs`) на каждый профиль для жёсткого разделения сессий и маршрутов.
* **Бесплатный локальный Бункер и экспорт Cursor / веб-чатов (`src-tauri/src/bunker/`, `src-tauri/src/commands/bunker.rs`, `src/features/bunker/`):**
  * Локальный архив контекста (`Local Bunker`) с политикой хранения (`retention.rs`), санитизацией секретов (`sanitize.rs`), планировщиком автоснимков (`scheduler.rs`) и генерацией промпта восстановления (`restore_prompt.rs`).
  * Экспорт истории и контекста из **Cursor** (`cursor_export.rs`) и помощник экспорта веб-чатов (`web_helper.rs`, `web_parsers.rs`, `WebExportHelper.tsx`).
* **«SOS-верификация» и `Persona Risk Index` (`src/features/sos/`, `src-tauri/src/auditor/persona_risk.rs`, `src-tauri/src/commands/sos.rs`):**
  * Специализированный раздел помощи при проверках и ограничениях (`SmsBranch`, `PersonaBranch`, `PaymentBranch`, `BannedBranch`) с расчётом индекса риска личности/сессии (`persona_risk.rs`, `PersonaRiskCard.tsx`).
* **4-состоянный системный трей (`src-tauri/icons/tray-gray.png`, `src-tauri/src/tray/`):** добавлено серое состояние иконки трея (`tray-gray.png`) для режима без защиты (в дополнение к зелёному, жёлтому и красному).
* **Очистка кэша Windows MSIX Claude (`src-tauri/src/auditor/cache_cleaner.rs`, `cache_cleaner_process.rs`):** безопасное завершение фоновых процессов и очистка кэша MSIX-версии Claude Desktop на Windows.
* **TUN Fake-IPv6 anti-SSRF DNS fallback (`src-tauri/src/auditor/leaks_dns.rs`, `src-tauri/src/core/net_safety.rs`):** безопасный DNS fallback при работе с TUN Fake-IPv6 с проверкой адресов против SSRF-утечек во внутренние сети.
* **GitHub Build Provenance (`.github/workflows/release.yml`):** добавлена публикация SLSA/build-provenance аттестаций (`actions/attest-build-provenance@v2`) для релизных артефактов macOS и Windows.

### Изменено
* **Актуализированы тарифы ВПН Заставы (`src/shared/copy/ru/connect.ts`):** `PROMO_COPY.keyPriceLabel` обновлён на подтверждённый тариф `"769 ₽/мес · 1 949 ₽ за 3 мес"`, удалены релизные маркеры `[CONFIRM_BEFORE_RELEASE]`.
* **Расширена схема состояния (`src-tauri/src/state/schema_v3.rs`, `src-tauri/src/commands/state_v3.rs`):** добавлены настройки оболочки v3, бункера и чистой комнаты с полной обратной совместимостью при миграции с v2.3.0.

---

## [2.3.0] — 2026-11-18

Релиз, выросший из разбора реального кейса бана со «100% защитой» и превративший слепую зону в рабочую броню: перехват скачка ASN внутри одной страны, «Безопасный выход» с сохранением `deviceId` и 4-часовым таймером, реальная PTR-проверка и честные гайды без посредников, плюс фикс 20-минутных таймаутов маршрутов поверх VPN на Windows, нативный буфер обмена и строгий откат `apply_pac` на macOS и 4-слойная архитектура ядра с [`CONSTITUTION.md`](CONSTITUTION.md).

### Добавлено
* **Безопасный выход из Claude и 4-часовой таймер смены IP/VPN (`auditor/profile_switcher/safe_logout.rs`, `commands/claude.rs`, `state/schema.rs`, `state/settings.rs`, `ProfilesSection.tsx`, `ProfileModals.tsx`, `CooldownBanner.tsx`):**
  * Кнопка **«Безопасный выход (смена IP / VPN)»** (`safe_logout_claude_cmd`) мягко завершает процессы Claude Desktop и помощников (только при `os_effects_enabled()`), удаляет только cookies и хранилище сессий (`Cookies`, `Local Storage`, `Session Storage`, `IndexedDB`, `WebStorage`, `SharedStorage`, `DIPS`) и OAuth-токены CLI, **строго сохраняя `ant-device-registry.json` (`deviceId`), `ccd-ids.json`, `claude_desktop_config.json` и `.claude/settings.json`**, а также напоминает выйти из `claude.ai` в браузерах.
  * В `AppStateData` добавлены поля `ip_change_cooldown_until` и `last_safe_logout_at` (обратная совместимость через `#[serde(default)]`); после безопасного выхода запускается 4-часовой таймер (`14400` с) с живым баннером обратного отсчёта `HH:MM:SS` на экране «Обзор» и кнопкой ручного сброса (`clear_ip_change_cooldown_cmd`).
* **Перехват смены ASN/дата-центра внутри одной страны (`auditor/history.rs`, `proxy/guard/{policy,audit_summary,audit_outcome,alerts,baseline_restore}.rs`):**
  * `evaluate_impossible_travel_with_exit` теперь отслеживает смену провайдера/ASN даже при совпадении страны (`prev_country == current_country`, например `DE -> DE`), если оба ASN ненулевые и различаются (`AS_A -> AS_B`), сменился IP, не прошло 4 часов и возврат не является `TRAVEL_PINNED_RETURN` — возвращается предупреждение `TRAVEL_ASN_JUMP_SAME_COUNTRY` (при этом смена IP у одного провайдера `AS_A -> AS_A` остаётся `TRAVEL_NORMAL`).
  * `NetworkGuard` больше не выполняет тихий `accept_locked` при `TRAVEL_ASN_JUMP_SAME_COUNTRY` или при активном 4-часовом кулдауне во время внезапной смены IP — требуется явное подтверждение пользователя в `alert-popup` (с сохранением работы `TRAVEL_PINNED_RETURN` и `trusted_exceptions`).
* **Реальный Reverse DNS (PTR) lookup (`auditor/seams/dns/`, `auditor/network/mod.rs`):** в `DnsLookup` / `SystemDns` добавлен `reverse_ptr` на базе `hickory_resolver::TokioResolver::reverse_lookup`; `evaluate_reverse_dns_ptr_with_dns` проверяет реальную PTR-запись выходного IP на маркеры публичных анонимайзеров (с пометкой `rdns:ptr`).
* **4-слойная модульная архитектура и Конституция (`CONSTITUTION.md`, `ARCHITECTURE.md`, `scripts/check-architecture.mjs`):** ядро `src-tauri/src/` и фронтенд `src/` декомпозированы на строгую 4-слойную архитектуру (`core/` → `state/`, `routing/` → доменные сервисы → `app/`, `commands/`, `tray/`) с жёсткими бюджетами размеров файлов (`<= 500L` prod / `<= 700L` test), вынесенными тестовыми двойниками `fakes.rs`, тонкой границей `invoke()` в `src/utils/api/` и автоматическими проверками CI без функциональных регрессий.

### Изменено
* **Честный статус Datacenter / VPS IP (`auditor/ip_type.rs`):** для `IpType::Hosting` отображается честная формулировка «Datacenter / VPS IP (не резидентский)» с напоминанием избегать резких смен IP/ASN (при сохранении `Status::Ok` для личных VPS).
* **Обновлены гайды по VPS и оплате (`rules/guides/*.md`, `src/features/guides/providers.ts`, `src/features/connect/hostings.ts`, `src/shared/copy/ru/guides.ts`, `src/shared/copy/ru/connect.ts`):**
  * `is*hosting` заменён на **Vultr** (`https://www.vultr.com/?ref=9936768`);
  * убраны завышенные формулировки про «100% защиту на VPS», «идеальный ASN» и «нулевой риск»;
  * добавлено жёсткое предупреждение против посредников (`Playerok`, `FunPay`, Telegram-ботов, чужого Apple Pay) и уточнение, что способ через Apple App Store подразумевает **собственный личный Apple ID** с пополнением Gift Card;
  * добавлено предупреждение никогда не переключать VPN/VPS на лету через `Cmd+Q` без безопасного выхода и 4-часовой паузы.

### Исправлено
* **Стабильность маршрутов Заставы поверх другого VPN на Windows (`proxy/upstream/{entry_connect,handshakes,chained,mod}.rs`, `routing/net/{mod,dns}.rs`, `proxy/server/{mod,tunnel,route_guard}.rs`, `src-tauri/Cargo.toml`):**
  * добавлен автоматический fallback через системный `chained_proxy` для публичных входных узлов при сбое или таймауте прямого TCP-соединения (с защитой от петель на loopback, приватные подсети и сам `chained_proxy`, при полном сохранении fail-closed для целевого ИИ-трафика);
  * в `tcp_connect_addrs` внедрён алгоритм Happy Eyeballs (`race_connect`, шаг `250 мс`, чередование IPv6/IPv4) и включён `SO_KEEPALIVE` (`time = 30s`, `interval = 10s` через `socket2`) для предотвращения подвисаний на мёртвом первом адресе или полуоткрытых VPN/NAT-сокетах;
  * исправлен бюджет таймаутов DNS vs `ROUTE_ENTRY_TIMEOUT_SECS` (увеличен до `12s`, `system_lookup` сокращён до `1200 мс`, fallback через `hickory` и DoH распараллелен в `2500 мс`, добавлен аварийный stale-кэш DNS на `7200` с / 2 часа с фоновым обновлением);
  * добавлена запись фазы ошибки (`dns`, `tcp_direct`, `tcp_chained`, `tls`, `connect`) в `[proxy:route]` журнала диагностики (`diagnostics::record`).
* **Надёжное копирование текста в буфер на macOS WKWebView (`src/shared/lib/clipboard.ts`, `CopyErrorLogButton.tsx`, `useClaudeBackup.ts`, `useProtectionToggles.ts`, `usePinning.ts`, `useCopy.ts`, `useSettingsController.ts`):** все вызовы `navigator.clipboard.writeText` заменены на единый helper `writeClipboard`, который сначала вызывает нативную Tauri-команду `copy_text_to_clipboard` (`pbcopy` / Win32 `CF_UNICODETEXT`), устраняя `NotAllowedError` после асинхронных операций (включая «Скопировать промпт переноса» и копирование CLI-команды / IP / диагностического отчёта).
* **Строгий откат частичных ошибок прав администратора в `apply_pac` на macOS (`sysproxy/macos/apply.rs`, `app/mod.rs`, `src/utils/api/events.ts`, `useTrayEvents.ts`):** при `AdminAuthRequired` (код 14 `networksetup`) на любой физической сетевой службе (включая chain/bypass) `apply_pac` откатывает частичные изменения и возвращает `Err(MSG_ADMIN_AUTH_REQUIRED)` вместо ложного `sysproxy_active = true`; ошибки прав на старте теперь отправляются в интерфейс через `sysproxy://admin-auth-required` с предложением «Разрешить с паролем».
* **Перенос длинных причин блокировки в окне перехвата (`src/features/alert/alert.css`):** в `.zs-alert-reason` добавлен корректный перенос длинных строк (`overflow-wrap: anywhere`), чтобы причины `TRAVEL_ASN_JUMP_SAME_COUNTRY` и таймера кулдауна не обрезались.

---

## [2.2.2] — 2026-11-16

Патч-релиз с надёжным ядром при обрыве и восстановлении VPN, расширенным покрытием клиентов и доменов Gemini (`oauth2.googleapis.com`, `iamcredentials.googleapis.com`, `OpenCode`, честный статус `Antigravity`), обновлённым интерфейсом для ключей и хостингов, исправлением `CoworkVMServiceManualGuard` на Windows, постоянными исключениями `(Сервис + Exit IP)`, пер-сервисными тумблерами мониторинга и повышенной надёжностью мультиаккаунтинга.

### Добавлено
* **Обнаружение `OpenCode` и расширение доменного списка Gemini (`proxy/coverage.rs`, `rules/provider_matrix.json`, `proxy/pac.rs`, `auditor/geo_matrix.rs`):** в «Покрытие» и «Обзор» добавлено обнаружение `OpenCode`, а в доменный список Gemini добавлены `oauth2.googleapis.com` и `iamcredentials.googleapis.com`.
* **Постоянные исключения `(Сервис + Exit IP)` (`state/mod.rs`, `commands/audit.rs`, `commands/interception.rs`, `SettingsModal.tsx`):** нажатие «Разрешить принудительно» (в окне перехвата или на экране «Обзор») сохраняет пару `(provider, exit_ip)` в `trusted_exceptions` в `state.json` (переживает перезапуски и смены сети); в «Настройках» добавлены просмотр активных исключений, удаление отдельных записей (`remove_trusted_exception`) и полная очистка (`clear_trusted_exceptions`).
* **Пер-сервисные тумблеры мониторинга ИИ (`state/mod.rs`, `commands/audit.rs`, `proxy/pac.rs`, `proxy/server.rs`, `proxy/guard.rs`, `SettingsModal.tsx`):** в «Настройках» добавлены отдельные переключатели мониторинга для **Claude**, **ChatGPT** и **Gemini** (`disabled_providers`, команда `set_provider_monitoring`); отключённый провайдер исключается из фоновых проверок `NetworkGuard`, генерации PAC (`get_all_ai_domains_filtered`) и проксирования, включая общие домены Google при выключении Gemini.

### Изменено
* **Понятный интерфейс для ВПН Заставы и рекомендованных хостингов (`src/features/connect/`, `src/features/guides/`, `src/shared/copy/ru/`):** переименован «Ключ Заставы» → **«ВПН Заставы»**, добавлена зелёная кнопка **«Получить ВПН»**, удалены пустые окна промокодов, а стрелка у рекомендованных хостингов заменена на понятную кнопку **«Перейти»**.
* **Политика `Yellow` vs `Critical` в щите ИИ-сервисов (`proxy/guard.rs`, `OverviewScreen.tsx`, `useOverviewModel.ts`):** некритичные `Yellow`-предупреждения (страны `KZ`, `RS`, часовой пояс, предупреждение AI Studio и др.) больше не останавливают трафик и не вызывают всплывающих модалок перехвата, оставаясь информативными в интерфейсе; убраны тихие авто-блокировки на `Yellow`.

### Исправлено
* **Надёжное ядро при обрыве и восстановлении VPN (`proxy/guard.rs`, `proxy/hold_queue.rs`, `proxy/server.rs`, `auditor/network.rs`, `auditor/history.rs`, `tray/events.rs`):**
  * устранена 1-секундная перезагрузка аудита `ProbeRegular`, восстановлен мгновенный `Gate::Pending` с асинхронным `alert_first` при смене сети;
  * устранены «осиротевшие» 60-секундные таймауты `HoldQueue` за счёт `HoldResolution::Superseded` и счётчика `restore_epoch`;
  * устранена гонка кэша в `NetworkResolver` с помощью `cache_generation`;
  * исправлен ложный возврат в «СТОП СЕТИ» при возврате на закреплённый IP (`apply_pinned_travel_grace`);
  * починен клик **«Снять СТОП СЕТИ»** в системном трее.
* **Честный статус `Antigravity` в «Покрытии» (`proxy/coverage.rs`):** исправлена ложная отметка `Configured` для `Antigravity` — теперь отображается реальный статус до запуска с переменными прокси.
* **Создание задачи планировщика `CoworkVMServiceManualGuard` на Windows (`cowork_guard.rs`):** XML задания кодируется в `UTF-16 LE` с BOM (`encode_utf16_le_with_bom`) и приведено к валидной XSD-схеме Task Scheduler 1.2 (удалён недопустимый `<LogonType>ServiceAccount</LogonType>` для `S-1-5-18`), добавлена предварительная валидация (`validate_windows_task_xml`), декодирование `UTF-16 LE` вывода утилит (`decode_windows_cmd_text`), резервный перевод службы через `SYSTEM`-задачу при `ERROR_ACCESS_DENIED` к ключу реестра/SCM и проброс точной диагностики ошибки из elevated-процесса (`--error-file`).
* **Поведение `NetworkGuard` при старте, авто-восстановлении и повторных алертах (`proxy/guard.rs`, `proxy/hold_queue.rs`, `OverviewScreen.tsx`):**
  * добавлено тихое авто-снятие блокировок при восстановлении допустимого IP и отсутствии критических проверок;
  * убран ложный алерт при старте приложения на закреплённом или допустимом IP (`report_allowed_for_state`);
  * подавлены повторные модальные алерты для уже заблокированных сервисов;
  * устранена параллельная гонка при снятии блокировки и разрешении сервиса на экране «Обзор» (`executeAllowSequence`).
* **Надёжность мультиаккаунтинга и привязки ключей к профилю (`auditor/profile_switcher.rs`, `commands/claude.rs`, `commands/routes.rs`, `app.rs`, `routing/mod.rs`, `tray/menu.rs`, `tray/events.rs`, `ProfilesSection.tsx`):**
  * изолирована привязка `pinned_ips["anthropic"]` без затирания `default` и добавлена стартовая синхронизация активного профиля (`reconcile_active_profile_on_startup`);
  * при смене профиля или ключа автоматически снимаются устаревшие блоки и сессионные уступки (`clear_provider_blocks_and_session`);
  * все операции чтения/записи `profiles.json` сериализованы через `PROFILES_LOCK`;
  * исправлено удаление активного профиля (`delete_claude_profile_in` корректно переключается на резервный профиль до удаления, не перезаписывая его);
  * при удалении маршрута, привязанного к активному профилю, маршрут переводится в `invalidate_profile_route` (`DanglingBinding` / fail-closed) вместо тихого отката на прямой выход;
  * добавлено живое обновление подменю профилей в трее (`refresh_profiles_submenu`) и синхронизация списка маршрутов/состояния в UI (`ProfilesSection.tsx`, `useTrayEvents.ts`).

---

## [2.2.1] — 2026-11-15

Патч-релиз с тихими сетевыми пробами без раскрытия Заставы и домашнего IP, устойчивым DNS-резолвом ключей на Windows поверх Happ VPN (`os error 11001`), снятием эвристических триггеров антивирусов (`BroPass`), синхронизацией тумблеров защиты и точечными доработками интерфейса.

### Изменено
* **Управление браузерными политиками и страж `CoworkVMService` на Windows (`sysproxy/browser_policies.rs`, `cowork_guard.rs`, `proxy/coverage.rs`, `main.rs`):** на Windows убрано сканирование каталогов профилей браузеров (`User Data`/`Local State`/`Preferences`) и запуск скрытых команд PowerShell (`-EncodedCommand`); управление браузерами на Windows полностью опирается на официальные политики реестра `HKCU\Software\Policies` и системный PAC (`AutoConfigURL`), а установка стража `CoworkVMService` выполняется через нативный Win32 `ShellExecuteExW` (`runas`, `SW_HIDE`) с флагом `--install-cowork-guard`.
* **Уточнение связанных строк защиты и состояния «Без защиты» (`OverviewScreen.tsx`, `src/shared/copy/ru/overview.ts`, `src/shared/copy/ru/toasts.ts`):** при выключенной системной защите карточки провайдеров переходят в нейтральный статус «Без защиты» вместо устаревших красных/зелёных индикаторов; у строк «Браузеры» и «Десктопные приложения» добавлена явная подпись и подсказка о том, что они переключаются общим системным прокси, а у кнопки «Остановить сеть» / «Возобновить сеть» — поясняющая `!`-подсказка.

### Исправлено
* **Приватность сетевых проб (`auditor/network.rs`, `auditor/mod.rs`, `proxy/guard.rs`):** удалён заголовок `User-Agent: Zastava/1.0` (заменён на нейтральный браузерный `NEUTRAL_USER_AGENT`), а при отсутствии привязанного маршрута (`route: None`) запрещены прямые пробы с домашнего IP пользователя на `claude.ai` и `chatgpt.com` — проверка использует нейтральный `https://1.1.1.1/cdn-cgi/trace` (или активный `chained_proxy`).
* **Ошибка `os error 11001` при старте маршрута поверх Happ VPN / нестабильного DNS на Windows (`routing/net.rs`, `auditor/network.rs`, `commands/sysproxy.rs`):** в `resolve_entry_checked` добавлены короткие повторные попытки системного DNS, резервный резолв через `hickory-resolver` и DoH (`1.1.1.1/dns-query`, `dns.google/resolve`) с проверкой IP через `check_entry_ip`, а также потокобезопасный in-memory кэш (TTL 60 с, stale-on-error 15 мин); в `checked_entry_addr` разделены ошибки DNS-резолва и отклонения политикой; в снимок `get_error_diagnostics` добавлены активные TUN/VPN-адаптеры и их DNS-серверы (`parse_windows_ipconfig_snapshot`).
* **Ложные срабатывания антивирусов `BroPass` на Windows (`sysproxy/browser_policies.rs`, `cowork_guard.rs`):** устранены поведенческие и строковые эвристики, вызывавшие ложную реакцию Kaspersky и движков VirusTotal на неподписанный бинарник, при полном сохранении защиты браузеров, отключения QUIC/DoH и `CoworkVMService`.
* **Синхронизация тумблера «IDE и терминал» (`src/shared/hooks/useProtectionToggles.ts`):** после выключения или переключения системной защиты статус `cliProtected` принудительно обновляется через `checkCliProtectionStatus()`, чтобы строка «IDE и терминал» не оставалась ложно зелёной.
* **Компактность модалок, обрезка подсказок, видимость обновления и легенда покрытия (`CrashTestModal.tsx`, `alert.css`, `Tooltip.tsx`, `AppShell.tsx`, `AppHeader.tsx`, `Menu.tsx`, `Toast.tsx`, `CoverageSection.tsx`):** модальные окна адаптированы под экран без вертикальной прокрутки (`compact`), `!`-тултипы выравниваются с учётом границ окна (viewport clamping), в шапке добавлена заметная кнопка «Обновить» (`zs-update-pill`) и точка на меню, в баннере недоступного маршрута и тостах ошибок закреплена кнопка «Скопировать лог», а в «Покрытии» появилась сворачиваемая легенда «Что значат статусы».

---

## [2.2.0] — 2026-11-14

Релиз с полной совместимостью ключей Заставы поверх TUN VPN (V2Box Pro и др.), автоматическими PAC-политиками браузеров, мгновенной двухуровневой синхронизацией часового пояса для ИИ, DoH-проверкой спам-баз под FakeDNS, прелоадером выхода/обновления, обновлённым онбордингом и UX/диагностическим пакетом v2.2.

### Добавлено
* **Автоматическая PAC-политика браузеров, `Preferences` профилей Chromium и перезапуск в один клик поверх TUN VPN (`sysproxy/browser_policies.rs`, `proxy/coverage.rs`, `commands/coverage.rs`, `proxy/pac.rs`):** при включении защиты прописываются `ProxyMode = "pac_script"` и `ProxyPacUrl` (в дополнение к `QuicAllowed` и `DnsOverHttpsMode`), а также объект `"proxy"` в файлы `Preferences` профилей Chromium-браузеров (с отложенным согласованием после выхода и откатом через журнал владения); расширена поддержка браузеров (Comet, Yandex Browser, Opera, Opera GX, Dia, OpenAI Atlas, Chrome/Brave Beta) и ИИ-расширений, включая полные эндпоинты Google/Gemini; добавлены команда `reapply_browser_policies_cmd`, перезапуск браузеров в один клик с `--proxy-pac-url` и признаки `browser_pac_policy_active` / `browsers_needing_restart` в `CoverageSnapshot`.
* **Изолированная привязка IP, `ip_history` и `NetworkGuard` по маршрутам и провайдерам (`state/mod.rs`, `auditor/mod.rs`, `proxy/guard.rs`):** `pinned_ips: HashMap<String, String>` (с миграцией legacy `pinned_ip`) и `ip_history` изолированы по маршрутам (`ip_history_key_for_selection`), а блокировка `NetworkGuard` изолирована по конкретному провайдеру; исключены ложные срабатывания `Impossible Travel` и побочная блокировка других ИИ-провайдеров; сервисы на выделенном ключе Заставы получают статус `PINNED_BY_ZASTAVA_KEY` без конфликта с основным VPN.
* **Подписанный откат на предыдущие релизы GitHub (`updater/mod.rs`, настройки «Версия и откат»):** добавлена возможность безопасно откатиться на предыдущий релиз GitHub с проверкой криптоподписи minisign.
* **Резервный канал DoH для DNSBL (`auditor/dnsbl.rs`):** автоматический fallback на `https://dns.google/resolve` при получении Fake-IP или отказе системного резолвера (`< 2` ответивших зон).
* **Экран завершения работы и обновления (`ShutdownOverlay`, `sysproxy/cleanup.rs`, `tray/events.rs`, `updater/mod.rs`):** единая защита от повторной зачистки при выходе/обновлении и пошаговые события `app://shutdown-progress` по 4 этапам.
* **Быстрые действия в карточке VPN (`CoverageSection.tsx`):** кнопки «Перезапустить браузеры» (в один клик при открытых браузерах без PAC), «Привязать браузеры» / «Обновить привязку браузеров», «Перепроверить» и «Настройки сети ОС», спокойный информационный стиль при активной браузерной PAC-политике.
* **Режим «Скрыть IP» (`hide_ip_mode`):** переключатель в шапке (`AppShell.tsx`) и Tauri-команды `get_hide_ip_mode` / `set_hide_ip_mode` для маскировки IP-адресов и подсетей во всём UI.
* **Предупреждение о заблокированной стране и чистые подписи стран:** плашка-предупреждение в «Подключении» при выходе маршрута в санкционную страну для выбранного ИИ и чистый формат `Страна (CC)` без дублирования кода (`formatCountryWithCode`).
* **Причина перехвата (`gate_reason`) и пауза «До следующей смены сети»:** поле `gate_reason` в событиях перехвата, режим паузы `UntilNetworkChange` (`InterceptionAction::BlockUntilNetworkChange`) и команды `pause_until_network_change_cmd`, `set_guard_pause_mode_cmd`, `get_guard_pause_status_cmd`.
* **Экспорт очищенного диагностического отчёта и предпросмотр изменений:** команды `export_diagnostic_bundle_cmd` (санитизированный JSON без ключей, паролей и IP) и `preview_protection_changes_cmd` (список управляемых изменений в `system_pac`, `browser_policy`, `shell_rc`, `cli_settings`, `ide_settings`).
* **Обновлённый онбординг v2.2 (`src/features/onboarding/`):** переработан под ключи `zastava://` поверх VPN, разделение защиты браузеров и CLI/IDE, двухуровневый часовой пояс и 14 проверок; состояние перенесено в `state.json` (`onboarding_v2_2_done`, команды `get_onboarding_v2_2_done` / `set_onboarding_v2_2_done`).

### Изменено
* **Двухуровневая синхронизация часового пояса (`auditor/os_env.rs`, `TimezoneModal.tsx`, `CoverageSection.tsx`):** «Синхронизировать для ИИ» (*Рекомендуется*) переводит проверку часового пояса в зелёный статус `TIMEZONE_SYNCED_AI` для приложений, CLI и IDE без смены системных часов ОС; синхронизация часов ОС вынесена как необязательная опция для браузеров с ненавязчивым напоминанием для браузеров/расширений в «Покрытии» и окне часового пояса.
* **Изоляция проверок на ключах Заставы (`auditor/probes/stun.rs`, `auditor/leaks.rs`, `auditor/mod.rs`):** для сервисов на выделенном ключе Заставы исключены ложные предупреждения `UDP_STUN_MISMATCH` (`UDP_KEY_TCP_PROTECTED` при зарубежном/заблокированном UDP и отключённом QUIC), а также ложные расхождения стран для `dns_country` и `ipv6`.

### Исправлено
* **Работа с Happ Plus и AmneziaVPN на macOS без ошибки временного DNS при включении защиты (`sysproxy/macos.rs`, `sysproxy/platform.rs`, `sysproxy/mod.rs`, `proxy/coverage.rs`):** обнаружение временных DNS VPN (`temp_dns_overrides`) больше не прерывает `enable_with_mode` и `toggle_sysproxy(true)` — системный `networksetup` PAC бережно откладывается (`os_pac_deferred`), а управляемые PAC-политики браузеров и защита CLI/IDE включаются сразу (с автоматическим доприменением системного PAC после отключения VPN); в `RealPlatform::temp_dns_overrides` отфильтрованы неактивные физические службы без `State:/Network/Service/*/IPv4|IPv6`, чтобы устаревшие записи на отключённых адаптерах (например, `P30T`) не блокировали включение и откат.
* **Мгновенная инвалидация кэша часового пояса (`auditor/cache.rs`, `commands/sysproxy.rs`, `useGatewayState.ts`):** включение `system_tz` и `sync_ai_tz_enabled`/`sync_ai_tz_active` в ключ кэша `cache.os`, немедленный сброс кэша при любом действии с TZ и принудительное обновление отчётов всех трёх провайдеров.
* **DNS-проба под FakeDNS (`auditor/probes/whoami.rs`):** `combine_sources` использует подтверждённый публичный DNS-резолвер, если второй источник вернул Fake-IP (`198.18.0.0/15`), и возвращает `Ok` (`DNS_TUN_FAKE_IP_SAFE`) в чистом Fake-IP режиме без резолверов РФ.
* **Таймаут IPv6-пробы за kill-switch VPN (`auditor/leaks.rs`):** таймаут IPv6-пробы на хосте с IPv6 (или без ответа ОС) при блокировке со стороны VPN kill-switch корректно считается безопасным (`Ok`), а не сбоем проверки.
* **Сохранение завершающего переноса строки (`sysproxy/cli_protection.rs`):** при удалении блока Заставы из профилей оболочки (`restore_profile`) сохраняется исходный trailing newline.

---

## [2.1.2] — 2026-11-14

Релиз с жёстким перехватом браузерного ИИ-трафика (включая Google Gemini), синхронизацией системного часового пояса ОС, проверкой реального выхода до ИИ-сервисов и исправлением автозапуска на Windows 11 Pro.

### Добавлено
* **14-я проверка сети — реальный выход к ИИ-сервису (`claude_exit`, WP-13):** проверяет фактический выходной IP и страну напрямую до `claude.ai/cdn-cgi/trace`, `chatgpt.com/cdn-cgi/trace` и `ipinfo.io/json` через привязанный маршрут Gemini (привязка к провайдеру без маршрута для Gemini помечается «Не применимо»), с выводом `measured_via` на экране «Проверки».
* **Режим `split_tunnel_mode` в настройках (WP-13):** переключатель «Выборочная маршрутизация VPN (split tunneling)» с подсказкой добавить процесс `zastava` в правила VPN/TUN; в этом режиме не блокируются колебания `1.1.1.1` на общем маршруте и информационные срабатывания IPv6.
* **Синхронизация системного часового пояса ОС (`os_tz.rs`):** кнопка «Синхронизировать системный TZ» / «Восстановить» в настройках (через UAC `tzutil /s` и службу `tzautoupdate` на Windows; через запрос прав администратора `systemsetup -settimezone` и `com.apple.timezone.auto` на macOS). Исходное состояние сохраняется в `os_tz_baseline.json` и автоматически восстанавливается при выключении, выходе или восстановлении после сбоя; интерфейс напоминает перезапустить браузеры и Claude Desktop.
* **Журналируемые политики браузеров (`sysproxy/browser_policies.rs`):** при активном системном прокси отключают QUIC (`QuicAllowed = 0`) и встроенный DoH (`DnsOverHttpsMode = "off"` для Chrome/Edge/Brave, `DNSOverHTTPS\Enabled = 0` для Firefox) через общий журнал владения с чистым откатом прежних значений при выключении или выходе.
* **Расширен справочник публичных DNS-операторов (`auditor/probes/public_dns.rs`):** добавлены диапазоны NextDNS, Control D, Mullvad DNS и дополнительные подсети Google Public DNS и Quad9.

### Изменено
* **Честный статус часового пояса (`auditor/os_env.rs`):** устранено ложное «зелёное» состояние — если подменены только переменные CLI (`TZ`), а системный пояс ОС не совпадает с поясом выходного IP, возвращается предупреждение `TIMEZONE_SYNCED_CLI_ONLY`.
* **Зелёный статус на «Обзоре» при временном сбое DNS-резолвера:** временный статус `Unknown` у проверок `dns` (индекс 6) и `dns_country` (индекс 10) не снижает общий балл ниже зелёной зоны и не окрашивает главный экран и строки сервисов в жёлтый цвет (за исключением fake-IP `DNS_WHOAMI_FAKE_IP`).
* **Таймауты и кэш DNS-пробы (`auditor/probes/whoami.rs`, `auditor/cache.rs`):** `WHOAMI_LIMIT` увеличен до `2500 мс`, `RESOLVER_UNKNOWN_TTL` увеличен с `5 с` до `25 с` (меньше лишних перепроб при временных таймаутах).

### Исправлено
* **Автозапуск и реестр на Windows 11 Pro (`win_reg.rs`):** все вызовы дочерних процессов `reg` / `reg.exe` заменены на нативный Win32 `advapi32` FFI в `sysproxy/platform.rs`, `auditor/seams.rs`, `cowork_guard.rs` и `autostart.rs` (устранена ошибка `0xc0000142` при автозапуске).
* **Утечки Google Gemini и перехват маршрутов:**
  * Синхронизированы все 34 домена Google/Gemini (включая `clients6.google.com`, `gemini.google`, `aisandbox-pa.googleapis.com`, `ai.google.dev`, `bard.google.com`, `deepmind.google`, `jules.google.com`, `accounts.google.com`, `ogs.google.com`, `apis.google.com`) между `rules/provider_matrix.json`, `proxy/pac.rs` и `auditor/geo_matrix.rs`;
  * Исправлено различие между привязкой «напрямую» и маршрутом по умолчанию (`DIRECT_ROUTE_ID = "__direct__"`);
  * Повышена надёжность цепочки PAC поверх VPN: сброс `HealGuard` при отключении VPN на macOS (`sysproxy/macos.rs`, `sysproxy/mod.rs`) и корректная цепочка `RegKind::ExpandSz` на Windows (`sysproxy/platform.rs`, `sysproxy/windows.rs`).
* **Стабильность DNS-пробы (`auditor/probes/whoami.rs`, `auditor/seams.rs`):** запрос A-записи `whoami.akamai.net` выполняется в обход системного кэша (`lookup_uncached`) в паре с TXT-запросом `o-o.myaddr.l.google.com`.

---

## [2.1.1] — 2026-11-13

Хотфикс по первым отзывам после релиза `2.1.0`.

### Исправлено
* **Проверка DNS-резолвера через VPN (`auditor::seams`, `whoami`):**
  * На macOS системный TXT-запрос теперь берёт активные достижимые резолверы из `scutil --dns` (только глобальные, если они есть, без гонки со scoped LAN DNS) и отфильтровывает `0.0.0.0`, `::`, link-local и `fec0:0:0:ffff::*` даже на fallback-пути;
  * На Windows системный TXT-запрос сначала идёт через `DnsQuery_W` (`dnsapi`) с флагами `DNS_QUERY_BYPASS_CACHE | DNS_QUERY_TREAT_AS_FQDN`, с безопасным fallback на `hickory-resolver`;
  * `WHOAMI_LIMIT` установлен в `2000 мс` (вместе с `GEO_TOTAL_LIMIT = 1800 мс` укладывается в `CHECK_LIMIT_IO = 4000 мс`), включены `attempts = 2`, `num_concurrent_reqs = 2` и `UDP + TCP`.
* **Нативное копирование логов («Скопировать лог»):** добавлена Tauri-команда `copy_text_to_clipboard` (`pbcopy` с UTF-8 `LANG`/`LC_ALL` на macOS, `CF_UNICODETEXT` с ретраями `OpenClipboard` на Windows), устраняющая потерю user activation в WebView после асинхронного сбора диагностики.
* **Выключение защиты поверх VPN с временными DNS (Happ Plus и др.):** добавлены `RecoveryReport::is_only_vpn_dns_deferred()` и префикс `TEMP_DNS_DEFERRED:` для `toggle_sysproxy(false)` и `force_clean_os_proxy_cmd`. UI корректно переводит тумблер в выключенное состояние с информационным пояснением вместо красной ошибки и противоречивого баннера, а сообщение в «Покрытии» про активный VPN стало яснее.
* **Диагностика macOS 27 (`26A428`):** расширено распознавание ошибок авторизации в `is_admin_auth_error`, добавлен вывод `macos_version` (`sw_vers`) в диагностический отчёт и очистка/проброс `last_os_error()` в детали ошибки `apply_pac`.

---

## [2.1.0] — 2026-11-13

Релиз про честные проверки, стабильный трей и безопасное восстановление сетевых настроек. Описание для пользователей — в разделе «Что нового» описания релиза.

### Добавлено
* Статус проверки **«Не удалось проверить»** (нейтральный, не «Чисто»): проверка, которая не выполнилась (таймаут, сбой, отказ резолвера), больше не считается пройденной. Итоги показываются как «N из M», при неполном отчёте — «Проверено частично».
* Проверки сети: всего **13**. Новые:
  * DNS-резолвер: какой DNS-сервер реально видит запросы (системный резолвер запрашивает `whoami.akamai.net` и `o-o.myaddr.l.google.com`);
  * UDP/STUN: идёт ли UDP мимо туннеля (STUN-серверы Cloudflare и Google).
* DNSBL: 5 зон (Spamhaus ZEN, DroneBL, Barracuda, SpamCop, UCEPROTECT уровня 1). Каждая зона проверяется контрольным адресом; «не в списке» засчитывается, только если ответили не менее двух зон.
* Тип адреса выхода внутри проверки «Провайдер адреса» (число проверок не меняется, их по-прежнему 13): хостинг, жилой или мобильный провайдер, выход Tor, массовый VPN или не определён. Хостинг не штрафуется: личный VPS — нормальный сценарий («Хостинг (ожидаемо для личного VPS)»). Замечание дают только выход Tor и адрес из пула массового VPN. Список выходов Tor загружается с `check.torproject.org/torbulkexitlist` раз в 6 часов; если он недоступен, проверка показывает «Не удалось проверить», а не «Чисто». Источник и лицензия каждой записи справочника `rules/dangerous_asns.json` указаны в поле `source`.
* Выход по IPv6: в отчёте появился признак `ipv6_exit`; проверки по спам-базам и списку Tor отмечаются «Не применимо» с пояснением на экране «Проверки».
* Окно предупреждения при смене IP открывается сразу. Страна и детали догружаются асинхронно; кнопка «Разрешить» активна после завершения проверки.
* «Покрытие приложений»: статусы по факту (подтверждено трафиком, настроено и ожидает первого запроса, неизвестно, не настроено); инструкция «Как настроить» с адресом шлюза; обновление статуса при возврате в окно; кнопка «Проверить снова».
* Режим покрытия CLI: **«Только ИИ-клиенты и IDE»** (по умолчанию) и **«Глобальный перехват терминала»** (в настройках).
* Независимый тумблер «Подменять часовой пояс и локаль для ИИ в терминале/IDE» (переменные `TZ`, `LANG`, `LC_TIME`).
* Журнал владения: Застава запоминает исходные значения настроек, которые меняет сама, и возвращает только их; чужие значения не трогаются. Команда `--cleanup`; удаление через установщик Windows возвращает настройки.
* Локальная сеть (`*.local`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `localhost`) не направляется через прокси: правило есть и в PAC, и в `NO_PROXY`.
* Шлюз для обычного трафика: HTTP-запросы без шифрования проксируются (вместо заглушки); при недоступном внешнем VPN или прокси трафик идёт напрямую; быстрый перебор IPv6 и IPv4 (RFC 8305, шаг 250 мс); кэш DNS.
* Бейджи на вкладках: число непройденных проверок на «Проверках»; красная точка на «Обзоре» при остановке или заморозке трафика.
* «Разрешить принудительно» для сервиса с подтверждением; действует до смены сети или перезапуска Заставы; автоснятие блока при возврате эталонного/разрешённого IP (`verify_and_restore_baseline_locked`) и корректный жёлтый статус трея при активной сессионной уступке.
* Автозапуск в трей (`--minimized`) на macOS (LaunchAgent) и Windows (`HKCU\...\Run` с очисткой при удалении) и страж службы `CoworkVMService` на Windows.
* Персональная привязка ключа маршрута `zastava://` к профилю Claude Desktop, предупреждения о скором истечении срока действия ключа, приоритизация проверок по провайдерам (Claude, ChatGPT, Gemini) и обновлённая матрица регионов.
* Встроенная проверка BIN карты и справочник платёжных адресов в разделе «Гайды → Оплата».
* Повторная настройка системного прокси macOS с запросом прав администратора (`toggle_sysproxy_privileged`) при ошибках авторизации `networksetup` (включая `Command requires admin privileges` и коды `-60005`..`-60008`), защита виртуальных интерфейсов `utun*` и кнопка **«Скопировать лог»** с санитизированным сетевым снимком в уведомлениях и баннерах ошибок.
* Кнопка **«Перезапустить Antigravity с защитой»** (macOS): после подтверждения Застава мягко закрывает Antigravity 2.x (без принудительного завершения) и открывает его заново с адресом шлюза в окружении; если приложение не закрылось за 15 секунд, ничего не запускается. Первый раз macOS спросит разрешение «Автоматизация».
* Фоновый запуск: окно и трей отвечают сразу, первые проверки стартуют параллельно и показывают состояние «Проверяем» до получения данных вместо ложных ошибок старта.
* Честный статус **Antigravity 2.x** (разделение редакторской сборки, 2.x и CLI; ручная команда с реальным адресом шлюза; предупреждение при трафике в обход шлюза).
* Структурированные коды отказа для кнопки «Разрешить» в окне перехвата (`AllowErrorCode`) и согласованный контракт шагов теста обрыва VPN между Rust и интерфейсом.

### Изменено
Изменения поведения по сравнению с 2.0.0:
* Застава не меняет настройки VPN-служб macOS (NetworkExtension, PPP, IPSec): системный PAC, цепочка и список исключений пишутся только в физические службы (Wi-Fi, Ethernet, USB, Thunderbolt). Остаток PAC версии 2.0.0 в VPN-службах снимается один раз и только у отключённого VPN; подключённый не трогается. Если системный прокси не действует поверх подключённого VPN, «Покрытие» говорит об этом и подсказывает, что делать.
* Покрытие CLI по умолчанию — «Только ИИ-клиенты и IDE»: обычный терминал, `npm`, `brew`, `git` и `cargo` работают напрямую. Перехват всего терминала включается в настройках.
* Подмена часового пояса и локали — отдельный тумблер. Используются только `TZ`, `LANG` и `LC_TIME`; `LC_ALL` не используется.
* Застава больше не пишет в `~/.zshenv`, а старый блок в нём вычищается. Прокси-переменные не выставляются в графическую сессию macOS через `launchctl`.
* Локальная сеть и принтеры не направляются через прокси.
* Часовой пояс IP сравнивается с системным по смещению UTC (допуск 1 час).
* Радар покрытия не запускает `lsof` для обычного (не ИИ) трафика.
* Апдейтер использует только штатный подписанный механизм; старый путь загрузки удалён.
* Проверки с неполным отчётом выводятся как «Проверено частично», а не как полностью пройденные.
* Адреса хостинга (Hetzner, DigitalOcean, Vultr и другие) больше не дают замечания «массовый хостинг/VPN»: это информативный тип «Хостинг». Замечание остаётся для пулов массовых VPN (M247, Datacamp) и выходов Tor; закреплённый IP снимает замечание про VPN-пул, но не про Tor.
* Проверка DNS-резолвера считает два разных адреса одного публичного провайдера (Cloudflare, Google, Quad9, OpenDNS, AdGuard) согласованными, а при расхождении показывает, что ответил каждый источник и что делать.
* Жёлтая точка на вкладке «Обзор» загорается только при реальном непокрытом ИИ-приложении или недействующем поверх VPN системном прокси; статус «Неизвестно» (JetBrains и др.) её не зажигает.

### Исправлено
* Застава не меняет настройки VPN-служб macOS: из-за этого подключённый VPN мог разорваться при первом запуске. Раньше при первом запуске после 2.0.0 каждая служба, включая VPN, получала подряд две записи («снять» остаток PAC и «поставить» заново); теперь физическая служба получает одну запись или ни одной, VPN-службы не получают ни одной.
* Самолечение системного PAC не воюет с VPN-клиентом, который сам переписывает PAC: после трёх таких переписываний за 120 с служба оставляется в покое до смены сети или перезапуска защиты.
* Устранена причина вылета трея при смене сети на macOS: все обращения к иконке и меню выполняются в главном потоке.
* Сбой проверки (таймаут, паника, ошибка источника) даёт статус «Не удалось проверить», а не «Чисто».
* Спам-база, которая не отвечает или отказывает резолверу, не даёт ложного «Чисто».
* Plain HTTP-запросы (например, `npm`, OCSP/CRL) больше не получают заглушку и проходят через шлюз.
* Перепроверка сети не обрывает загрузки, которые идут через шлюз.
* Устранён шторм вызовов `lsof` в радаре покрытия.
* Остатки 2.0.0 (блок в `~/.zshenv`, прокси-переменные в `launchctl`) вычищаются один раз и только по признакам, оставленным самой Заставой.
* Исправления интерфейса (меню «…», гайды).

### Безопасность
* Обновление устанавливается только после проверки подписи (minisign) по закреплённому публичному ключу. При ошибке проверки ничего не устанавливается.
* Защита проверки подписи апдейтера действует начиная с 2.1.0: обновление с 2.0.0 на 2.1.0 ещё идёт по прежней схеме.
* Приложение не подписано Apple Developer ID и Microsoft Authenticode: Gatekeeper и SmartScreen могут предупреждать.
* Журнал владения (`ownership/journal.json`) создаётся в версии 2.1.0 и не читается более старыми версиями. Откат на 2.0.0 после установки 2.1.0 не поддерживается.

---

## [2.0.0] — 2026-11-11

Крупный релиз с полной переработкой архитектуры ядра, переходом на собственную дизайн-систему, многосервисной маршрутизацией и поддержкой цепочки системного PAC.

### Добавлено
* **Модульная архитектура ядра Rust**: разделение монолитного `lib.rs` на специализированные модули `proxy/`, `routing/`, `commands/`, `sysproxy/` и тонкие IPC-обертки.
* **Маршрутизация по сервисам (`routes`)**:
  * Независимая привязка отдельных ключей и upstream-прокси к каждому ИИ-провайдеру (Claude, ChatGPT, Gemini, Antigravity).
  * Выбор приоритетного маршрута: `Profile Route -> Provider Route -> Default Route`.
  * Режим `fail-closed`: при недоступности маршрута трафик блокируется со статусом «Недоступен», исключая утечки в открытую сеть.
  * Сторож активных туннелей `RouteWatch` для непрерывного контроля доступности upstream-узлов.
* **Формат ключей `zastava://` v2**:
  * Поддержка нескольких входных нод (`entry[]`) с автоматическим отказоустойчивым переключением (failover).
  * Контроль заявленного IP выхода (`exit_ip`), пользовательские метки, страна и срок действия ключа.
  * Полная обратная совместимость с ключами формата v1.
* **Сквозное шифрование до входной ноды на `rustls`**:
  * Нативная поддержка HTTPS-прокси (CONNECT inside TLS) без использования сторонних бинарных утилит.
* **Цепочка системного PAC (PAC Chaining)**:
  * Бесконфликтная работа поверх любых VPN-клиентов (v2rayN, Throne, Hiddify, WireGuard, AmneziaWG, Happ, v2box).
  * Каскадная отдача трафика: ИИ-домены идут в шлюз Заставы `127.0.0.1:8899`, а весь остальной трафик системы возвращается в клиентский прокси пользователя.
  * Совместимость с TUN-режимом (loopback-адрес `127.0.0.1` не перехватывается туннелем, исключая FakeIP-конфликты `198.18.0.0/15`).
* **Мониторинг покрытия приложений (App Coverage)**:
  * Прозрачный учет приложений и CLI-процессов, реально направляющих трафик в шлюз.
* **Новый пользовательский интерфейс на Zastava DS**:
  * 5 вкладок: **Обзор**, **Подключение**, **Проверки**, **Бэкап**, **Гайды**.
  * Атомарные примитивы дизайн-системы в `src/ui/` (`Button`, `Badge`, `Switch`, `Row`, `Card`, `Stat`, `Field`, `Banner`, `Tabs`, `Dialog`, `Steps`, и др.).
  * Пошаговый 4-этапный онбординг для новых пользователей с автоматическим вердиктом сети.
  * Интерактивный краш-тест обрыва VPN (Safe Canary Probe): проверяет, как шлюз реагирует на обрыв туннеля.
* **Claude Vault**:
  * Изолированные профили Claude Desktop с уникальными `device_id` (`ant-device-registry.json`), изолированным кэшем и персональной привязкой ключей.
  * Резервное копирование контекста Claude Code (`~/.claude`): архивация истории, планов и долгосрочной памяти (`MEMORY.md`) с генерацией `RESTORE_PROMPT.md`.
  * Глубокая очистка сессионных меток с сохранением пользовательских MCP-конфигураций.
* **Инструменты контроля качества**:
  * Скрипт-страж `scripts/check-no-hex.mjs` и команда `pnpm lint:hex` для контроля правила «0 сырых hex-цветов во фронтенде».
  * Разделенный CI: быстрый запуск тестов для PR и релизная кросс-компиляция для тегов (macOS Universal + Windows x64).

### Изменено
* Полный переход на локальные шрифты `@fontsource/golos-text` и `@fontsource/jetbrains-mono` (удалены внешние запросы к Google Fonts).
* Удалены устаревшие шаблоны Vite/Tauri (`tauri.svg`, `vite.svg`, `react.svg`, команда `greet`).
* Удалены устаревшие служебные документы и дублирующиеся графические ассеты из репозитория.

### Безопасность
* Автоматическое маскирование паролей и учетных данных ключей в UI-моделях и логах ядра (`redacted_for_ui`).
* Строгая фильтрация адресов входных нод для предотвращения SSRF-атак на локальные и приватные подсети.

---

## [1.3.1] — 2026-11-10

### Добавлено
* Мгновенный запуск сетевого радара при старте приложения без задержки.
* Оптимизированное фоновое чтение системных таблиц маршрутизации.

### Исправлено
* Синхронизация часового пояса и системной таймзоны на Windows 11.
* Очистка шапки и стабилизация вкладки бэкапа профилей.

---

## [1.3.0] — 2026-11-09

### Добавлено
* Поддержка Throne TUN и расширение гео-матрицы доступности ИИ-сервисов.
* Дебют вкладки **Claude Vault** для управления профилями Claude Desktop.
* Брендированные подменю в системном трее / меню-баре.
* Угловые всплывающие уведомления при изменении сетевых маршрутов.
* Авто-правила переключения поведения шлюза по известным Wi-Fi сетям.

### Исправлено
* Обработка системного прокси и таймзон в Windows 11.
* Чистое удаление следов инсталлятора NSIS при деинсталляции на Windows.

---

## [1.2.0] — 2026-11-08

### Добавлено
* Тихий режим выполнения системных вызовов на Windows (`CREATE_NO_WINDOW`) без моргания окон `cmd.exe`.
* Интерактивный краш-тест обрыва VPN (Safe Canary Probe).
* Изоляция идентификаторов устройств Claude Desktop (`ant-device-registry.json`).
* Возможность полного отключения проверки автообновлений в настройках.

---

## [1.1.3] — 2026-11-06

### Добавлено
* Селективный 2-Hop шлюз (Custom Upstream Gateway) через SOCKS5/HTTP прокси.
* 12 контуров параллельного сетевого аудита (гео-матрица, DNSBL, IP Pinning, ASN, утечки IPv6, DNS-резолверы, таймзона, локаль).
* Модуль экспорта сессий и памяти Claude Code (`~/.claude`).
* Полупрозрачный HUD перехвата под чёлкой дисплея на macOS.

---

## [1.0.5] — 2026-11-05

### Добавлено
* Автоматическая конфигурация прокси `127.0.0.1:8899` для VS Code, Cursor и Claude Code.
* Автовосстановление исходных системных настроек при выходе из приложения.
