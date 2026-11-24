# Спецификация Zastava v3.2.0 (`spec-v3.2.0.md`)

> **Статус:** RELEASED (v3.2.0) — **PayShield Phase 2 + Телепорт памяти в Бункере + Единая «Чистая комната» для Claude и Gemini** (зависит от `v3.1.1`; нулевая регрессия к `v3.1.1`).
> **Git-инвариант:** По правилу релиза спека `spec-v3.2.0.md` фиксируется и отслеживается в git вместе с релизом (`git add -f spec-v3.2.0.md` при наличии `spec-*.md` в `.gitignore`).
> **Стек:** Tauri v2, Rust (`edition = "2024"`), React 19, TypeScript 6, Cloudflare Workers + D1/KV (опциональный opt-in бэкенд телеметрии и подписанных манифестов), Clean Hexagonal (4 слоя).
> **Архитектурные ограничения:** 4-слойная Clean Hexagonal архитектура (`scripts/check-architecture.mjs`), бюджеты: **≤ 350** строк soft / **≤ 500** строк hard на prod-файл, **≤ 700** строк на test-файл, **≤ 400** строк на файл с inline `#[cfg(test)]`, `0` сырых hex/rgb в компонентах (`pnpm lint:hex`), **Zero-LOLBin** на Windows (`src-tauri/tests/windows_av_and_upgrade_migration/`).

---

## Содержание

1. [Стратегическая цель, инвариант Zero UI Bloat и конкурентный ров](#1-стратегическая-цель-инвариант-zero-ui-bloat-и-конкурентный-ров)
2. [Блок 1 — BIN Radar (Краудсорс-телеметрия проходимости BIN'ов)](#2-блок-1--bin-radar-краудсорс-телеметрия-проходимости-binов)
3. [Блок 2 — Multi-AI Safe Payment Advisor (Интерактивный навигатор оплаты)](#3-блок-2--multi-ai-safe-payment-advisor-интерактивный-навигатор-оплаты)
4. [Блок 3 — Динамический реестр провайдеров и Per-Service Auto-Demote](#4-блок-3--динамический-реестр-провайдеров-и-per-service-auto-demote)
5. [Блок 4 — Телепорт памяти ИИ в Бункере (`BunkerCard` + `SOS`)](#5-блок-4--телепорт-памяти-ии-в-бункере-bunkercard--sos)
6. [Блок 5 — Единая «Чистая комната» (Claude + Gemini/AI Studio), `403` SOS и разделение маршрутов](#6-блок-5--единая-чистая-комната-claude--geminiai-studio-403-sos-и-разделение-маршрутов)
7. [Платформенные фиксы стабильности, безопасности и macOS (из аудита v3.1.1)](#7-платформенные-фиксы-стабильности-безопасности-и-macos-из-аудита-v311)
8. [Архитектурные ограничения, фазы реализации, E2E-тесты и DoD](#8-архитектурные-ограничения-фазы-реализации-e2e-тесты-и-dod)

---

## 1. Стратегическая цель, инвариант Zero UI Bloat и конкурентный ров

### 1.1. Слепые зоны классических антидетект-браузеров

Аудит рынка антидетект-браузеров (`AdsPower`, `Dolphin Anty`, `Multilogin`, `GoLogin`, `Octo Browser`, `Linken Sphere`) показывает фундаментальный разрыв: все перечисленные продукты решают задачу **сетевого и браузерного отпечатка** (Canvas, WebGL, шрифты, `hardwareConcurrency`, менеджмент прокси), но **полностью слепы на платёжном слое и в защите локальных IDE/CLI**:

- **Ноль встроенного BIN-анализа:** ни один антидетект не проверяет 6–8-значный BIN карты, тип фондирования (`PREPAID` / `COMMERCIAL` / `BUSINESS` vs `DEBIT`) и реальную страну эмитента до отправки формы Stripe или привязки к Google Payments.
- **Ноль проверки тройного гео-совпадения:** антидетекты не сверяют `Exit IP Country == Card BIN Country == Billing Address Country`, из-за чего пользователи с «зелёным» IP в Германии или США получают мгновенный **Persona KYC**, платёжный холд (`OR-CCSEH-21` / `OR-HDT-16`) или **ToS-бан** при оплате сингапурской/гонконгской виртуальной картой (например, `Antarctic Wallet` / `Wayment SG 493724`).
- **Ноль перехвата платёжного антифрода:** при использовании обычного браузера без PAC-маршрутизации домены телеметрии Stripe (`m.stripe.com`, `m.stripe.network`), верификации (`withpersona.com`), капч (`challenges.cloudflare.com`) и Google Pay (`pay.google.com`) утекают в обход защищённого маршрута или сталкиваются с несогласованным профилем.
- **Ноль понимания специфики мультимодельных ИИ-стеков:** антидетекты не различают модели риска `Claude (Anthropic)` (Stripe Radar + Persona KYC), `Google Gemini / AI Studio / Antigravity` (гео-проверка по кукам/аккаунту даже при включённом VPN, `403 ToS` за сторонние OAuth-прокси, платёжные проверки `OR-CCSEH-21` / `OR-HDT-16`), `ChatGPT (OpenAI)` (скачки IP и VCC) и `Cursor / Windsurf` (локальные `machineId` / `devDeviceId`).

### 1.2. Рыночный сдвиг (конец 2026) и инвариант «Zero UI Bloat»

Во второй половине — конце 2026 года (октябрь–ноябрь 2026) рынок пережил массовый исход из `Claude` (волны банов Anthropic, запрет компаний и сотрудников из неподдерживаемых юрисдикций по ноябрьской Supported Regions Policy) в **`Google Gemini / AI Studio / Antigravity`**, **`ChatGPT`** и **`Cursor / Windsurf`**.

Фактчекинг задокументированных кейсов (май–ноябрь 2026) подтверждает: у Google нет массовых банов личных Gmail за использование Gemini в браузере, но **четыре реальные боли бьют по пользователям уже сейчас**:
1. **Гео-заглушка при включённом VPN (`User location is not supported for the API use`, `?location=unsupported`, `not eligible`):** основной браузер и старый РФ-аккаунт несут РФ-куки `PREF`/`NID`, локаль, WebRTC, регион Google Play и `+7` (`support.google.com/gemini/thread/410511236`, `r/notebooklm`).
2. **Лимиты и `403 ToS` (`Gemini has been disabled for violation of Terms of Service`):** после закрытия бесплатных консьюмерских квот Gemini CLI (`18.06.2026`, `gemini-cli/discussions/27274`) прошла волна `403 ToS` на сторонних OAuth-клиентах (`OpenCode`, `OpenClaw`, ротаторы). Бан бьёт **только по ИИ-доступу**, но действует **One-Time Appeal Policy** (`discussions/20632`, `r/google_antigravity`).
3. **Платёжные холды (`OR-CCSEH-21`, `OR-HDT-16`, `OR-CBAT-15`):** привязка виртуалки к старому РФ-профилю Google Payments или расхождение страны вешает профиль на проверку паспорта не из РФ (полный же бан всего Google Account возникает почти исключительно за пачку свежих аккаунтов на одноразовые SMS или `chargeback`).
4. **Потеря контекста при переезде:** месяцы работы из `CLAUDE.md`, `MEMORY.md` и чатов остаются в старом клиенте.

#### Инвариант «Zero UI Bloat» (без раздувания меню, навигации и сущностей)

**Количество разделов в меню и верхнеуровневая навигация (`AppShell.tsx` / `SectionList.tsx`: 5 разделов хаба + `Подписка` в меню `Ещё`) НЕ меняются.** Никаких новых экранов, вкладок меню, лишних модалок или дублирующих сущностей. Каждая новая возможность v3.2.0 встраивается туда, где пользователь уже решает эту задачу:

| Задача пользователя | Где живёт в текущем UI v3.1.1 | Что добавляется в v3.2.0 |
|---|---|---|
| Изолированный запуск аккаунта без гео-блока, смена квот и прогрев | **«Чистая комната»** (`SandboxProfilesCard.tsx`, `LaunchpadSteps.tsx`, `PreFlightAuditCard.tsx`) | Выбор сценария при создании профиля: **`Claude (прогрев и оплата)`** или **`Gemini / AI Studio (без гео-блока и смена квот)`** поверх одного механизма `clean_room` + удобное переключение 2–3 профилей в списке. |
| Бэкап и переезд контекста в другой ИИ | **«Аккаунты, Бункер и SOS» → `BunkerCard.tsx`** + `BannedBranch.tsx` | Компактный переключатель формата выгрузки (`Универсальный бэкап` / `Gemini и Antigravity` / `Cursor` / `ChatGPT`) и 1 кнопка копирования/сохранения. |
| Проверка карты и безопасный способ оплаты | **«Оплата и прогрев» / «Подписка» (`PaymentFlowPanel.tsx`)** + **«Гайды → Оплата» (`PaymentGuide.tsx`)** | Встроенный `Safe Payment Advisor` и строка статистики `BIN Radar` (плюс 1-кликовый опросник после чекаута при opt-in). |
| Сброс `403 ToS` в Antigravity / Gemini CLI | **«Аккаунты, Бункер и SOS» → `SosScreen.tsx`** | 1-кликовая очистка кеша входа (`~/.gemini`, `~/.antigravity`) и пошаговый чеклист внутри существующего экрана SOS. |
| Защита стабильности AI Studio / IDE | Невидимый фоновый слой (`provider_matrix.json`, `detector.rs`) | Контроль стабильности IP/ASN для AI Studio и подсказка про локальный `machineId` Cursor/Windsurf без добавления лишних настроек в «VPN и ключи». |

### 1.3. Сетевой эффект PayShield Phase 2

Если `v3.1.0`/`v3.1.1` закрывают **локальную гигиену чекаута** (Clean Room + PAC для Stripe/Persona/Google Pay, локальный 8-значный BIN-чекер, `Checkout Interceptor`, 72-часовой карантин после оплаты, Zero-LOLBin Windows hardening и мгновенный `alert-popup`), то `v3.2.0` строит вокруг Zastava **защищённый сетевой ров (Network-Effect Moat)**:

1. **Краудсорс-телеметрия BIN Radar** (идейный аналог *PST Pulse* для арбитражников, адаптированный под ИИ-подписки): реальные проценты прохождения и мгновенных KYC/банов по 8-значным BIN'ам в разрезе конкретного ИИ-сервиса (`Claude`, `Gemini`, `ChatGPT`, `Cursor`) и канала оплаты.
2. **Детерминированный Multi-AI Safe Payment Advisor:** пошаговый навигатор без галлюцинаций LLM, который подбирает оптимальный путь оплаты **подписки** (`Apple IAP` через US Gift Card, `Direct Stripe Web`, `Google Payments / Google Play`, `Rescue Flow` для токсичного BIN).
3. **Динамический реестр с Per-Service Auto-Demote:** честный механизм защиты бренда, который автоматически понижает даже партнёрских провайдеров (`Kupikod`, `WantToPay`, `Плати по миру` и др.) в UI, если живые данные `BIN Radar` показывают деградацию их BIN'ов (`> 40%` KYC/банов) по любому из сервисов.

Чем больше пользователей из РФ/СНГ пользуются Zastava и анонимно (строго opt-in) фиксируют исходы оплат, тем быстрее выявляются «протухшие» BaaS-эмитенты (`Nium`, `Sunrate`, `Xfers`, абхазские РНКО и т.д.) и тем выше ценность рекомендаций, которую невозможно воспроизвести статической статьёй или обычным антидетектом.

---

## 2. Блок 1 — BIN Radar (Краудсорс-телеметрия проходимости BIN'ов)

### 2.1. Zero-PII / Zero-PCI контракт приватности (строго Opt-In)

Участие в `BIN Radar` **строго добровольное (opt-in)** и выключено по умолчанию до явного согласия пользователя в настройках (`bin_radar_opt_in: bool = false`) или подтверждения в диалоге первого пост-чекаут отчёта.

#### Точная схема отчёта `BinRadarReport`

```json
{
  "bin_prefix": "49372400",
  "service": "claude_pro",
  "channel": "stripe_web_card",
  "geo_match": "triple_mismatch",
  "warmup_bucket": "lt_24h",
  "outcome": "instant_kyc",
  "client_version": "3.2.0"
}
```

#### Rust-контракт (`src-tauri/src/core/bin_radar.rs`, Layer 0)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BinRadarReport {
    /// Строго 8 цифр: `^[0-9]{8}$`
    pub bin_prefix: String,
    pub service: AiPaymentService,
    pub channel: PaymentChannel,
    pub geo_match: GeoMatchClass,
    pub warmup_bucket: WarmupBucket,
    pub outcome: PaymentOutcome,
    pub client_version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiPaymentService {
    ClaudePro,
    ClaudeMax,
    Chatgpt,
    Cursor,
    Gemini,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentChannel {
    StripeWebCard,
    StripeGooglePay,
    StripeApplePay,
    AppleIap,
    GooglePlayIap,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GeoMatchClass {
    FullMatch,
    IpMismatch,
    BillingMismatch,
    TripleMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WarmupBucket {
    Lt24h,
    #[serde(rename = "24_96h")]
    Between24And96h,
    Gt96h,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentOutcome {
    Success,
    SoftDecline,
    InstantKyc,
    InstantBan,
}
```

#### Явные запреты (Zero-PII / Zero-PCI Invariants)

В `BinRadarReport`, HTTP-заголовках клиента и логах Cloudflare Worker **категорически запрещено** передавать или сохранять:
1. **IP-адреса** (включая отключение IP access-логов в настройках Worker; `CF-Connecting-IP` используется только в оперативной памяти для rate-limit/ASN-демпфирования и никогда не пишется в D1/KV/логи).
2. **Идентификаторы аккаунта и личности:** email, номер телефона, имя держателя карты, `account_id`, Stripe `cus_*` / `cs_*` / `pi_*`.
3. **Полные карточные данные (PCI-DSS):** полный PAN (13–19 цифр), `last4`, срок действия (`MM/YY`), `CVV/CVC`. Допустим только 8-значный префикс (`^[0-9]{8}$`); если пользователь ввёл 6 цифр, поле дополняется либо отклоняется до уточнения 8 цифр на стороне UI (предпочтительно требовать 8 цифр в `CardCheck` для точного разделения BaaS-поддиапазонов).
4. **Стабильные отпечатки устройства:** HWID, MAC-адрес, серийный номер диска, UUID профиля Clean Room.

### 2.2. Защита от накрутки (Anti-Poisoning) и статистическая гигиена

Чтобы конкуренты, недобросовестные продавцы карт или ботнеты не могли искусственно «накрутить» 100% успех токсичному BIN'у или обвалить нормальный банк, применяются четыре механизма:

1. **Анонимный суточный rate-limit (`1 отчёт / bin_prefix + service / 24h`):**
   - На Cloudflare Worker в памяти вычисляется эфемерный ключ:
     `bucket_key = HMAC_SHA256(daily_rotating_salt, "{bin_prefix}:{service}:{cf_ip_prefix_or_client_ephemeral}")`.
   - `daily_rotating_salt` ротируется каждые 24 часа и не хранится в долгосрочной БД. При повторной отправке по той же связке `(bin_prefix, service)` в течение 24 часов сервер возвращает `429 Too Many Requests` (клиент молча игнорирует дубль).
2. **Экспоненциальное затухание времени (Exponential Time Decay):**
   - BaaS-эмитенты меняют политику и попадают в блэклисты Stripe за несколько дней. Используются два скользящих окна: **14 дней** (оперативный сигнал) и **30 дней** (среднесрочный тренд).
   - Вес каждого отчёта возраста $\Delta t$ (в днях):
     $$w(\Delta t) = \exp(-\lambda \cdot \Delta t), \quad \lambda = \frac{\ln 2}{\tau_{1/2}}$$
     где для 14-дневного окна период полураспада $\tau_{1/2} = 5$ дней ($\lambda \approx 0.1386$), а для 30-дневного окна $\tau_{1/2} = 12$ дней ($\lambda \approx 0.0578$).
3. **Минимальный порог публикации (`n >= 5`):**
   - Проценты (`Успех %`, `Instant KYC %`, `Decline %`) вычисляются и показываются в UI только при наличии **не менее 5 уникальных отчётов** за выбранное окно (`sample_size_14d >= 5` или `sample_size_30d >= 5`).
   - При `n < 5` API возвращает `status: "insufficient_data"`, а UI отображает спокойную плашку: **`Недостаточно данных (n < 5)`** (вместо вводящих в заблуждение «100%» по 1–2 голосам).
4. **Sybil / Burst Anomaly Dampening:**
   - В Cloudflare Worker ведётся эфемерный счётчик по `(asn, hour_bucket)` в KV с коротким TTL (2 часа) **без сохранения IP**.
   - Если с одного ASN за час приходит более $K$ отчётов (например, $K = 10$), последующие отчёты с этого ASN получают пониженный статистический вес $w_{asn} = \min(1.0, \frac{K}{count_{asn,hour}})$ или отбрасываются при аномальном всплеске по одному `bin_prefix`.

### 2.3. Offline-First контракт и подписанные бандлы (без внешнего сервера в v3.2.0)

В `v3.2.0` система работает **100% автономно (Offline-First)** внутри десктоп-клиента, без раздувания скоупа под отдельный серверный проект Cloudflare Worker + D1/KV:

- **Встроенный + обновляемый подписанный бандл:** базовые агрегаты поставляются во встроенном `rules/bin_radar_snapshot.json` (аналогично `rules/bin_overlay.json`) и могут обновляться из подписанного **Ed25519** `bin_radar_snapshot.json` в `app_data_dir` при наличии обновлений без обязательной зависимости от облачного API.
- **Ed25519 верификация:** публичный ключ вшит в Rust-бинарник (`src-tauri/src/auditor/bin_radar_verify.rs`). При загрузке внешнего `snapshot.json` клиент сначала проверяет подпись через `ed25519-dalek`; невалидный или подменённый файл отклоняется без перезаписи локального кэша.
- **Zero-PII / Zero-PCI валидация отчётов:** клиентский конструктор и команда приёма отчёта (`BinRadarReport`) строго используют `#[serde(deny_unknown_fields)]`, проверяют 8-значный префикс `^[0-9]{8}$` и отклоняют любые лишние поля (`email`, `ip`, `last4`, `pan`).
- **Offline-First:** при отсутствии сети `CardCheck` и `Checkout Interceptor` читают локальный подписанный `bin_radar_snapshot.json` (из `app_data_dir` или встроенного `include_str!`).

```json
{
  "schema_version": 1,
  "generated_at_utc": "2026-11-22T12:00:00Z",
  "ttl_seconds": 86400,
  "entries": [
    {
      "bin_prefix": "49372400",
      "service": "claude_pro",
      "window_14d": {
        "n": 34,
        "success_pct": 14.7,
        "soft_decline_pct": 20.6,
        "instant_kyc_pct": 52.9,
        "instant_ban_pct": 11.8
      },
      "window_30d": {
        "n": 61,
        "success_pct": 19.2,
        "soft_decline_pct": 21.3,
        "instant_kyc_pct": 49.1,
        "instant_ban_pct": 10.4
      }
    }
  ],
  "signature_ed25519_b64": "<base64-подпись канонического payload>"
}
```

- **Ed25519 верификация:** публичный ключ вшит в Rust-бинарник (`src-tauri/src/auditor/bin_radar_verify.rs`). При загрузке `snapshot.json` клиент сначала проверяет подпись через `ed25519-dalek`; невалидный или подменённый файл отклоняется без перезаписи локального кэша.
- **Offline-First:** при отсутствии интернета или недоступности Cloudflare в сети пользователя `CardCheck` и `Checkout Interceptor` читают локально закэшированный `bin_radar_snapshot.json` из директории данных приложения (`app_data_dir`).

### 2.4. UI/UX интеграция

1. **Виджет в `CardCheck` и `Checkout Interceptor`:**
   - Под базовым результатом проверки BIN (страна, банк, `DEBIT`/`PREPAID`) выводится компактная строка статистики `BIN Radar`:
     - При `n >= 5`: `Успех 78% · Instant KYC 14% · Decline 8% · За последние 14 дн., n=42`
     - При `n < 5`: `BIN Radar: недостаточно данных для статистики (n < 5)`
   - Если `instant_kyc_pct + instant_ban_pct > 40%` при `n >= 15`, виджет подсвечивается статусом `Critical` с кнопкой перехода к `Safe Payment Advisor` («Подобрать безопасный способ»).
2. **Отказ от лишних модалок (`Anti-Bloat`):**
   - Отдельный серверный проект Cloudflare Worker + D1/KV и всплывающий опросник `PostCheckoutPrompt` **не входят в скоуп релиза `v3.2.0`** — клиент работает 100% автономно (`Offline-First`) на встроенных и кэшируемых подписанных бандлах (`rules/bin_radar_snapshot.json`, `rules/providers_manifest.json`, `rules/payment_advisor_matrix.json`), без лишних всплывающих окон после оплаты.
   - Локальные отчёты (при opt-in `bin_radar_opt_in`) валидируются через строгий Zero-PII/Zero-PCI контракт `BinRadarReport` (`#[serde(deny_unknown_fields)]`) и учитываются в локальном оверлее/экспорте без сетевого трекера.

---

## 3. Блок 2 — Multi-AI Safe Payment Advisor (Интерактивный навигатор оплаты)

### 3.1. Детерминированный движок правил

Никаких LLM-подсказок в рантайме: рекомендации строятся строго детерминированным движком `src-tauri/src/auditor/payment_advisor.rs` (Layer 2) на базе декларативной матрицы `rules/payment_advisor_matrix.json` (встроена в бинарник через `include_str!` + обновляется через подписанный манифест).

#### Совместимость с `v3.1.1` и расширение `PaymentChannel` / `PassportChannel`

В `v3.1.1` уже реализованы:
- `src-tauri/src/auditor/payment_readiness/mod.rs`: `PaymentChannel::{DirectCard, GooglePayWeb, ApplePayWeb, AppleIAP, Api}` и `SubscriptionPlan::{Pro, Max, Api, Unknown}`;
- `src-tauri/src/bunker/payment_passport.rs`: `PassportChannel::{DirectCard, AppleIAP, Api}` с `#[serde(deny_unknown_fields)]` на `PaymentPassport`.

Для полной поддержки экосистемы Google / Multi-AI в `v3.2.0` без поломки сохранённых паспортов `v3.1.1`:
- В `PassportChannel` (`src-tauri/src/bunker/payment_passport.rs`) и `PaymentChannel` (`src-tauri/src/auditor/payment_readiness/mod.rs`) добавляется вариант **`GooglePlayIap`** (с `#[serde(alias = "google_play_iap", alias = "GooglePayments")]`), сохраняя все прежние JSON-алиасы (`DirectCard`, `AppleIAP`, `Api`).
- Команда `evaluate_payment_readiness` (`src-tauri/src/commands/payment.rs:99`) и `PaymentReadinessCard.tsx` перестают подставлять `ProviderId::Anthropic` как единственный сценарий и учитывают выбранный `target_service: AiPaymentService`.
- **Инвариант UI-копирайта (`BRAND.md` + `src/shared/copy/ru/copyGuards.test.ts`):** все пользовательские заголовки, подсказки и предупреждения Advisor'а пишутся обычным человеческим русским языком без запрещённого жаргона (`PayShield`, `Stripe Radar`, `BIN`, `KYC`, `Persona KYC`, `DirectCard`, `Apple IAP`, `биллинг`, `чекаут`, `ASN`, `Split-IP` — согласно словарю §8.2 `spec-v3.1.0.md`).

#### Входные и выходные контракты (`src-tauri/src/core/payment_advisor.rs`, Layer 0)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorQuery {
    pub target_service: AiPaymentService,
    pub has_iphone_apple_id: bool,
    pub available_bin_prefix: Option<String>,
    pub payment_rails: Vec<PaymentRail>,
    pub willing_to_warmup_96h: bool,
    pub google_payments_country: Option<String>,
    pub is_new_google_account: Option<bool>,
    pub network_state: AdvisorNetworkContext,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentRail {
    RubSbp,
    CryptoUsdt,
    ForeignBankCard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorNetworkContext {
    pub exit_country: Option<String>,
    pub trust_score: u8,
    pub clean_room_ready: bool,
    pub is_zastava_key_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorPlan {
    pub primary: AdvisorRoute,
    pub fallbacks: Vec<AdvisorRoute>,
    pub blocked_red_flags: Vec<BlockedRouteWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorRoute {
    pub route_id: String,
    pub title: String,
    pub kyc_risk_tier: KycRiskTier,
    pub estimated_fees: String,
    pub provider_ids: Vec<String>,
    pub checklist: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KycRiskTier {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}
```

### 3.2. Пять обязательных сценариев навигатора (строго под подписки и API-биллинг)

#### Сценарий 1 — Apple IAP (Tier 1 — минимальный риск Stripe / Persona KYC)

- **Условие:** `target_service` ∈ `{ClaudePro, ClaudeMax, Chatgpt}` и `has_iphone_apple_id == true` (или пользователь готов завести отдельный US Apple ID).
- **Маршрут (`KycRiskTier::Minimal`):**
  1. Отдельный **US Apple ID** (вторичный аккаунт только для Media & Purchases, не основной iCloud) с безналоговым адресом (`OR 97204`, `DE 19801`, `MT 59101` из существующего `AddressCard`).
  2. Оплата подписки через **Apple In-App Purchase (IAP)** в мобильном приложении — полностью обходит веб-чекаут Stripe Radar и триггер мгновенного Persona KYC.
  3. **Легальное пополнение Apple US Gift Card (`RubSbp`):**
     - **`Т-Банк` (без партнёрской ссылки — основной путь):** пошаговый маршрут в приложении `Платежи → Все / Игры → Apple (США)`, фиксированные номиналы **`$2, $5, $10, $20, $50, $100`** (не выбирать «Россия» с наценкой 60%). Обязательный дисклеймер: Т-Банк выступает витриной-посредником (`maxipay.global`), при сбоях доставки возврат бывает спорным — **начинать с тестовой покупки `$2` или `$5`**.
     - **`СберБанк Онлайн` (без партнёрской ссылки — альтернативный путь):** по курсу, близкому к ЦБ РФ (`Платежи → Отдых и развлечения → Онлайн-сервисы / Игры → Apple Card` → регион США, `$2–$500`, чек банка).
     - **`Kupikod`** (`https://kupikod.com/`, слот `pending_ref_link` до аппрува партнёрки `kupikod-partners.com` **8% новый / 6% повторный**): по результатам аудита 2025–2026 **0 подтверждённых жалоб на бан Apple ID** (централизованная агентская модель через юрлица в Гонконге `JILIN BUSINESS LIMITED` / `AZURE WAY TRADING LIMITED`, не P2P). **Обязательные предупреждения:** наценка **~25–34%**, возвраты по умолчанию падают на внутренний баланс **Kupicoin**, строгое окно претензий **2 часа**, обязательна **непрерывная видеозапись экрана** от оплаты до активации кода, отключить/не подключать автоподписку **«Пропуск Kupikod»**, использовать **отдельный US Apple ID**.
  - **Red Flag:** строгий запрет серых P2P-площадок (`Plati.market`, `Avito`, `GGSel`, `Ozon`, `WB`, случайные Telegram-боты) — краденые карты ведут к чарджбэку и перманентной блокировке Apple ID (`Media & Purchases disabled`).

#### Сценарий 2 — Direct Stripe Web (Tier 2 Conditional — прямая оплата картой в браузере)

- **Условие:** пользователю нужен веб-доступ (`ClaudePro`, `ClaudeMax`, `Chatgpt`, `Cursor`), нет Apple ID или нужна оплата картой напрямую.
- **Маршрут (`KycRiskTier::Medium` для виртуальных US-карт; `KycRiskTier::Low` при наличии у пользователя собственной именной карты зарубежного банка):**
  - **`WantToPay`** (`https://telegram.me/WantToPayBot?start=w17851188--ERIEX`, **25–40%** активация + **10–25%** recurring в USDT): **строго тарифы `Easy` или `Smart`** (избегать дешёвого `Prepaid`), строго **US IP + US billing**, обязательное предупреждение о комиссии **`$0.25–$1.00` за каждую отклонённую транзакцию**.
  - **`Плати по миру`** (`https://platipomiru.com/?code=UXCAF1Z9`, CPA **1 500 ₽ / $10**): **строго тариф `«Для подписок»`** (BIN `446614` US Business; travel-карты не проходят), строго **US IP + US billing**.
  - **Обязательный чеклист Zastava (без него `route` помечается предупреждением):**
    1. Запуск строго в изолированной **Чистой комнате (Clean Room)** с роутингом Stripe/Persona через ключ Заставы.
    2. При `willing_to_warmup_96h == true` — **прогрев аккаунта 96 часов** (живые сессии и история чатов до апгрейда).
    3. Жёсткое 3-стороннее совпадение: `Exit IP Country == Card BIN Country == Billing Address Country`.
    4. **72-часовой Quarantine Lock** после оплаты (запрет смены IP, страны и браузерного профиля).

#### Сценарий 3 — Rescue Flow для уже купленного токсичного BIN (например, `Antarctic Wallet`, `Altyn Wallet` или `Wayment SG 493724`)

- **Условие:** `available_bin_prefix` совпадает с известным токсичным/SG-BaaS диапазоном (например, `493724xx` Nium `PREPAID BUSINESS SG`, или BIN, помеченный в `BIN Radar` как `> 40%` KYC/бан) либо `card_country == "SG"` при `exit_country != "SG"`.
- **Поведение Advisor (`blocked_red_flags` + перенаправление):**
  1. **Жёсткий стоп-сигнал:** `Claude Web Stripe` переносится в `blocked_red_flags` (`KycRiskTier::Critical`) с предупреждением о высоком риске мгновенного списания + Persona KYC / бана.
  2. **Понятное объяснение, почему Google Pay не спасёт:**
     > *«Оплата через Google Pay не скрывает карту от Stripe: Google Pay передаёт в Stripe реальную страну эмитента (`SG`) и тип карты (`PREPAID / COMMERCIAL`). При вашем текущем IP и адресе в Германии/США Stripe Radar всё равно видит тройное несовпадение и почти гарантированно запускает проверку паспорта (Persona KYC).»*
  3. **Безопасное перенаправление (Rescue Path):**
     - перейти на **Сценарий 1 (Apple IAP через Т-Банк / СберБанк Онлайн / Kupikod)** как самый безопасный путь для подписки;
     - не пытаться «пробить» Stripe повторными попытками на том же аккаунте, чтобы не сжечь его по `card_velocity_exceeded`.

#### Сценарий 4 — Google Ecosystem (`Gemini`: `Google One AI Pro` / `Google AI Studio` / `Antigravity`)

- **Условие:** `target_service == Gemini`.
- **Почему нужен отдельный профиль в «Чистой комнате»:**
  - Старые РФ-аккаунты Google с привязанным `+7` и РФ-регионом Google Play при попытке привязать зарубежную/виртуальную карту регулярно ловят платёжный холд **`OR-CCSEH-21`**, **`OR-HDT-16`** или **`OR-CBAT-15`** (`Google Payments profile suspended`) с требованием загрузить документ и банковскую выписку не из РФ, а также гео-отлупы `User location is not supported` / `not eligible`.
  - Профиль `Gemini / AI Studio` в существующей **«Чистой комнате»** (см. Блок 5) убирает РФ-хвосты сразу при открытии AI Studio / NotebookLM и изолирует споры по биллингу от основного аккаунта Google (в отличие от локального ИИ-бана `403 ToS`, банковский **chargeback** или пачка свежих аккаунтов на одноразовые SMS могут привести к блокировке всего Google-аккаунта).
- **Правило `Google Payments Profile Lock`:**
  1. **Тройное совпадение для Google:** `Google Payments Profile Country == Card BIN Country == Exit IP Country`. При расхождении (`google_payments_country != card_country` или `card_country != exit_country`) маршрут помечается `KycRiskTier::High`/`Critical` с предупреждением о риске `OR-CCSEH-21` / `OR-HDT-16`.
  2. **Предупреждение о 24-часовом холде смены страны:** смена страны в существующем `Google Payments Profile` требует удаления текущих методов оплаты и блокирует изменения профиля на **24 часа**; для старых аккаунтов с историей РФ-входов надёжнее завести отдельный профиль Google в «Чистой комнате» с нуля (на стабильный номер, **не** на одноразовые виртуальные SMS).
  3. **Защита от фрод-блокировки `Prepaid` на свежем аккаунте:** автоматика Google Payments и Google Cloud часто замораживает новые аккаунты при моментальной привязке prepaid/виртуальной карты ещё до первого вызова AI Studio API. Рекомендуется использовать именную зарубежную `DEBIT`/`CREDIT` карту поддерживаемой страны или проверенный US-маршрут (`WantToPay Easy/Smart` / `Плати по миру «Для подписок»`) строго после прогрева профиля и с подтверждением возраста 18+.
  4. **Разделение сценариев:**
     - *Подписка `Google One AI Pro ($19.99)` / `Antigravity`:* профиль `Gemini` в «Чистой комнате» + согласованный `Google Payments Profile` (или Google Play IAP в соответствующем регионе; запрет на покупку «инвайтов в семейные группы» на серых маркетплейсах вроде `Plati.market`/`GGSel`).
     - *`Google AI Studio` / `Vertex AI` (API-биллинг):* предупреждение о том, что квоты и лимиты привязаны к **Google Cloud Project** (не к отдельному API-ключу), ключ необходимо ограничивать по скоупу, а при утечке публичного ключа боты выжигают лимиты за ночь — **никогда** не делать chargeback через банк без закрытия спора через поддержку Google Cloud.

#### Сценарий 5 — `ChatGPT (OpenAI)` и `Cursor`

- **Условие:** `target_service` ∈ `{Chatgpt, Cursor}`.
- **Для `ChatGPT` (`Plus` / `Pro` / `Codex`):**
  - Приоритетный безопасный канал при наличии iPhone — **Сценарий 1 (`Apple IAP`)** через отдельный US Apple ID (`Т-Банк` / `СберБанк Онлайн` / `Kupikod`), обходящий Stripe pre-auth отлупы.
  - При оплате на сайте (`DirectCard`) — `Clean Room` + `US IP + US card + US billing` + отсутствие резких переключений страны до и в течение 72 часов после оплаты (защита от флага `Suspicious / Fraudulent Activity` с безответной отменой подписки).
- **Для `Cursor`:**
  - Оплата только через веб/Stripe (`Apple IAP` недоступен) в изолированной Чистой комнате с 3-сторонним совпадением `IP == Card == Billing`; обязательное предупреждение о привязке к локальному отпечатку IDE (`machineId` / `devDeviceId`) — не использовать один биллинг/сеть для цикличного создания trial-аккаунтов на одном устройстве.

---

## 4. Блок 3 — Динамический реестр провайдеров и Auto-Demote

### 4.1. Подписанный удалённый манифест `providers_manifest.json`

Чтобы обновлять тарифы, новые токсичные BIN'ы, предупреждения и партнёрские ссылки **без ожидания нового десктоп-релиза** Zastava, вводится удалённый манифест `GET /v1/payshield/providers_manifest.json`.

- **Безопасность:** манифест подписывается тем же **Ed25519** ключом, что и `snapshot.json`. Подпись проверяется в Rust (`auditor/manifest_verify.rs`).
- **Отказоустойчивость:** при недоступности сети или невалидной подписи используется последний валидный кэш на диске, а при первом запуске — встроенный compile-time fallback (`rules/providers_manifest.json`).

#### Схема записи провайдера

```json
{
  "id": "wanttopay",
  "name": "WantToPay",
  "category": "virtual_card",
  "tier": "conditional",
  "status": "active",
  "known_bin_prefixes": ["48331200"],
  "supported_rails": ["rub_sbp", "crypto_usdt"],
  "fees_summary": "Easy 990₽ + $6/мес; Smart 1,590₽ + $6/мес; отказ транзакции $0.25–$1.00",
  "warnings_ru": [
    "Используйте только тарифы Easy или Smart с IP, совпадающим со страной карты (US). Не используйте тариф Prepaid для Claude."
  ],
  "affiliate_url": "https://wanttopay.net/affiliate?ref=...",
  "auto_demote_exempt": false
}
```

### 4.2. Правило Per-Service Auto-Demote (Brand Integrity Guard)

Честность рекомендаций важнее партнёрской комиссии. Механизм **Auto-Demote** распространяется на **`Kupikod`**, **`WantToPay`**, **`Плати по миру`** и любого другого провайдера, добавленного через `providers_manifest.json`. Если провайдер начинает массово выдавать «протухшие» BIN'ы или генерировать массовые отказы/блокировки на любом из целевых ИИ-сервисов, срабатывает автоматическое понижение:

- **Условие срабатывания (раздельно по каждому `service: AiPaymentService`):**
  $$\text{rate}_{14d}(s) = \frac{\text{instant\_kyc}_{14d}(s) + \text{instant\_ban}_{14d}(s)}{n_{14d}(s)} > 0.40 \quad \text{при} \quad n_{14d}(s) \ge 15$$
  где $s \in \{\text{claude\_pro}, \text{claude\_max}, \text{chatgpt}, \text{cursor}, \text{gemini}\}$ — по любому из BIN'ов из `known_bin_prefixes` данного провайдера.
- **Гранулярность и действие:**
  1. На сервере генерации манифеста и **дополнительно локально на клиенте** (при наличии свежего `snapshot.json`) провайдер получает **per-service статус**: в `AdvisorPlan` для затронутого `target_service` этот провайдер автоматически переводится в **`demoted_warning`** (или **`blacklist`** при $> 65\%$); при деградации на **2+ сервисах** или на основном канале провайдер понижается глобально в реестре UI.
  2. В UI карточка провайдера для затронутого сервиса теряет зелёную/нейтральную плашку рекомендации, перемещается в блок предупреждений с понятной причиной без технического жаргона (например: *«Автоматически понижен по статистике пользователей: высокий риск запроса паспорта или блокировки за последние 14 дней»*).
  3. **Независимость от монетизации:** поле `auto_demote_exempt` в коде **игнорируется / запрещено** для партнёрских ссылок — **наличие активной реферальной ссылки не спасает провайдера от Auto-Demote**.

### 4.3. Верифицированная матрица провайдеров подписок и партнёрских программ (v3.2.0)

Ниже зафиксирована актуальная таблица провайдеров **строго для подписок**, согласованная с `spec-v3.1.0.md` (ссылки `pending_ref_link` в `providers_manifest.json` заполняются финальными partner ID владельца после аппрува):

| Провайдер | Категория / Рельсы | Статус в Zastava UI | Условия и нюансы для пользователя | Партнёрская программа (верифицировано) |
|---|---|---|---|---|
| **Т-Банк** | Apple IAP — US Gift Cards (RUB) | **Tier 1 Recommended** | Путь `Платежи → Все / Игры → Apple (США)`, номиналы `$2–$100` (не RU-карта с комиссией 60%). Дисклеймер про `maxipay.global` — начинать с `$2/$5`. | Без партнёрки (якорь доверия) |
| **СберБанк Онлайн** | Apple IAP — US Gift Cards (RUB) | **Tier 1 Recommended** | Резервный банковский путь по курсу, близкому к ЦБ (`Apple Card` США, `$2–$500`). | Без партнёрки (якорь доверия) |
| **Kupikod** (`https://kupikod.com/`) | Apple IAP — US Gift Cards (RUB / СБП / Crypto) | **Tier 1 / Fallback (Apple IAP)** | Аудит 2025–2026: **0 жалоб на бан Apple ID**, централизованная HK-модель. Предупреждения: наценка ~25–34%, возврат в Kupicoin, окно претензий 2 ч, непрерывная запись видео, отключить «Пропуск Kupikod», отдельный US Apple ID. | `pending_ref_link` до аппрува `kupikod-partners.com` (**8%** новый / **6%** повторный) |
| **WantToPay** | Direct Stripe Web — виртуальные карты (`Easy` / `Smart`, SBP / USDT) | **Tier 2 Conditional** | **Только `Easy`/`Smart`**, строго **US IP + US billing**; предупреждение о комиссии **$0.25–$1.00 за отказ** (избегать `Prepaid`). | Активна: `w17851188--ERIEX` (**25–40%** активация + **10–25%** recurring USDT) |
| **Плати по миру** | Direct Stripe Web — виртуальная карта `«Для подписок»` (SBP) | **Tier 2 Conditional** | **Только тариф `«Для подписок»`** (`446614` US Business), строго **US IP + US billing**. | Активна: `UXCAF1Z9` (**CPA 1 500 ₽ / $10**) |

#### Единый чёрный список (`BLACKLIST / DO NOT RECOMMEND`)

- **`Antarctic Wallet`** — подтверждённый триггер мгновенного Persona KYC на Claude (SG prepaid/virtual BIN + несовпадение IP/Billing), а также задокументированные случаи AML-заморозок.
- **`Altyn Wallet`** — абхазское РНКО, prepaid-BIN, риски заморозок и низкая надёжность.
- **`Wayment`** (SG `493724` Nium Prepaid Business на не-SG IP) — критический риск мгновенного Persona KYC при оплате с US/EU IP.
- **`e.pn` (для РФ), `RedotPay`, `PST.net`, `FlexCard`** — блокировка резидентов РФ либо критически высокий процент отказов Stripe на ИИ-подписках (существующая ссылка `e.pn` из `v3.0` удалена).
- **`Plati.market`, `Avito`, `GGSel`, `Ozon`, `WB`, случайные TG-боты** — высокий риск серых/скомпрометированных кодов, чарджбэков по гифт-картам и пожизненного бана Apple ID (`Media & Purchases disabled`).

---

## 5. Блок 4 — Телепорт памяти ИИ в Бункере (`BunkerCard` + `SOS`)

### 5.1. Интеграция в существующий UI без новых экранов

В `v3.1.1` уже работает локальный Бункер (`src-tauri/src/bunker/` + `src-tauri/src/auditor/claude_exporter/`), который собирает локальные артефакты (`~/.claude`, `claude_desktop_config.json`, Cursor, веб-экспорты), санитизирует секреты (`src-tauri/src/core/sanitize.rs`) и строит `RESTORE_PROMPT.md` (`bunker/restore_prompt.rs`, `bunker/web_parsers.rs`).

В `v3.2.0` внутри существующей карточки **`BunkerCard.tsx`** (блок `zs-bunker__prompt-box`, строки 315–327) и ветки **`BannedBranch.tsx`** (`SosScreen.tsx`) добавляется **компактный переключатель формата выгрузки** (`Select`) и **одна кнопка действия** (без новых вкладок и модальных окон):
- `Универсальный бэкап` (`RESTORE_PROMPT.md` — поведение `v3.1.1` по умолчанию)
- `Gemini и Antigravity` (`GEMINI.md` + `SYSTEM_INSTRUCTIONS_GEMINI.txt`)
- `Cursor` (`.cursor/rules/migrated-context.mdc`)
- `ChatGPT` (`CHATGPT_CUSTOM_INSTRUCTIONS.txt` + `MEMORY_SEED.md`)

Одна кнопка — одна готовая папка в `<app_data_dir>/bunker/teleports/<YYYY-MM-DD_HHMMSS>/` (плюс копирование основного промпта в буфер обмена).

### 5.2. Детерминизм, Zero-LLM и санитизация секретов

1. **Zero-LLM:** никакие чаты и файлы проектов не отправляются во внешние LLM; вся конвертация выполняется локально в `core/context_teleport.rs` (Layer 0) и `bunker/teleport.rs` (Layer 2).
2. **Строгая санитизация (`core/sanitize.rs`, `core/redact.rs`):** исключены `.credentials.json`, `Cookies`, `state.vscdb`, `ant-device-registry.json`, `ccd-ids.json` и ключи `oauth`/`token`/`secret`/`password`/`api_key`/`private_key`/`bearer`; в текстовых файлах маскируются инлайн-токены (`sk-ant-*`, `sk-*`, `AIza*`, `ghp_*`, `xoxb-*`).
3. **Приватность ФС:** запись строго через `ensure_private_dir` (`0o700`) и `write_private_file` (`0o600` на Unix).

### 5.3. Источники, целевые форматы и контракты

- **Источники (переиспользуются `v3.1.1` сканеры):** `scan_claude_dir` (`CLAUDE.md`, `MEMORY.md`, `plans/*.md`, последние запросы `.jsonl`), `scan_cursor_data` (`.cursorrules`, имена MCP-серверов), `parse_conversations` (веб-экспорт Claude/ChatGPT).
- **Форматы (`TeleportTarget`):**
  - `gemini_antigravity`: `GEMINI.md` (правила/память проектов) + `SYSTEM_INSTRUCTIONS_GEMINI.txt` (системный промпт для AI Studio / Gems) + перечень MCP без секретных `env`.
  - `cursor`: `.cursor/rules/migrated-context.mdc` (YAML frontmatter `alwaysApply: true` + проектная память) + перечень MCP.
  - `chatgpt`: `CHATGPT_CUSTOM_INSTRUCTIONS.txt` (2 блока строго `≤ 1 500` символов каждый) + `MEMORY_SEED.md`.
  - `universal`: расширенный `RESTORE_PROMPT.md` (совместимый с `v3.1.1`).

```rust
// src-tauri/src/core/context_teleport.rs (Layer 0)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TeleportTarget {
    GeminiAntigravity,
    Cursor,
    Chatgpt,
    Universal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContextTeleportResult {
    pub target: TeleportTarget,
    pub output_dir: String,
    pub sources_used: Vec<String>,
    pub secrets_redacted_count: usize,
    pub primary_paste_text: String,
    pub files_written: Vec<String>,
}
```

- **Tauri-команда (`src-tauri/src/commands/bunker.rs`):** `run_context_teleport(target: TeleportTarget, destination_dir: Option<String>, copy_only: Option<bool>) -> Result<ContextTeleportResult, String>` (при `copy_only == Some(true)` работает только в памяти без записи на диск).
- **Копирайт (`BRAND.md` + `copyGuards.test.ts`):** обычный русский текст без жаргона (`Zero-PII`/`JSONL`/`CLI`), `0` эмодзи, 1 CTA на блок.

---

## 6. Блок 5 — Единая «Чистая комната» (Claude + Gemini/AI Studio), `403` SOS и разделение маршрутов

### 6.1. Единая «Чистая комната» для Claude И Gemini/AI Studio (без отдельной сущности)

В `v3.1.1` **«Чистая комната»** (`src-tauri/src/clean_room/`, `src/features/clean-room/`) уже изолирует `--user-data-dir`, порт `127.0.1.x`, `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, `--disable-quic`, `--host-resolver-rules`, язык `Accept-Language` и уже имеет выбор `provider` (`"anthropic" | "openai" | "gemini" | "custom"` в `SandboxProfilesCard.tsx:221-230` и `providerSignupUrl` в `LaunchpadSteps.tsx:31-37`).

Расширяется сама существующая «Чистая комната» без введения отдельных сущностей и новых полей профиля:
1. **Два готовых сценария при создании/запуске профиля (`SandboxProfilesCard.tsx`, `LaunchpadSteps.tsx`):**
   - **`Claude (прогрев и оплата)`** → стартовый URL `https://claude.ai`, фокус на прогреве 96ч и оплате без Persona KYC.
   - **`Gemini / AI Studio (без гео-блока и смена квот)`** → стартовый URL `https://aistudio.google.com` (плюс быстрые ссылки на `gemini.google.com` и `notebooklm.google.com`), тот же механизм изоляции `clean_room` без РФ-кук `PREF`/`NID`, локали и WebRTC-утечек — чтобы сервис открывался с VPN с первого раза и при привязке оплаты не прилетал холд `OR-CCSEH-21` / `OR-HDT-16` на старый РФ-аккаунт.
2. **Быстрое переключение 2–3 профилей при нехватке лимитов (`Quota Switcher` прямо в списке `SandboxProfilesCard.tsx`):**
   - Пользователь держит в существующем списке профилей 2–3 аккаунта Gemini (`Gemini — Основной`, `Gemini — Резерв`, `Gemini — Оплата`) — у каждого свой `--user-data-dir`, свой порт `127.0.1.x`, привязанный маршрут `bound_route_id` и отдельный `PaymentPassport`, без склейки кук и без сторонних OAuth-ротаторов (`403 ToS`).
3. **Честная проверка среды (`src-tauri/src/clean_room/detector.rs`):**
   - При `target_provider == ProviderId::Gemini` существующее предупреждение `personal_browsers_present` уточняет: *«В обычном браузере и старом РФ-аккаунте (Google Play, +7, куки) Gemini, AI Studio и NotebookLM часто блокируются по стране даже с VPN, а при привязке карты срабатывает проверка платежей (`OR-CCSEH-21` / `OR-HDT-16`). Работайте в окне «Чистой комнаты» и не регистрируйте аккаунты на одноразовые виртуальные SMS»*.

### 6.2. Стабильность IP сессии для AI Studio / Vertex AI

- **Проблема в `v3.1.1`:** в `rules/provider_matrix.json:206` для `gemini` задано `"strict_impossible_travel": false, "max_country_switches_per_12h": 2`, из-за чего смена IP/ASN посреди открытой сессии `aistudio.google.com` / `aiplatform.googleapis.com` проходит без фиксации и провоцирует `FAILED_PRECONDITION` или срез квот.
- **Решение (`rules/provider_matrix.json`, `src-tauri/src/auditor/geo_matrix/`):** добавить `session_ip_stability_for_studio: true` для `gemini` — предупреждать и удерживать маршрут при смене IP/ASN во время активного трафика на `aistudio.google.com`, `generativelanguage.googleapis.com`, `aiplatform.googleapis.com`.

### 6.3. Обратная совместимость маршрутов и защита IDE (без лишних экранов в «VPN и ключи»)

- **Проблема в `v3.1.1`:** в `ConnectScreen.tsx` нет нужды добавлять громоздкую матрицу переопределения под-маршрутов для каждого IDE/роутера — это раздувает интерфейс и запутывает пользователей. При этом необходимо сохранить 100% обратную совместимость `state.json` v3 (`CURRENT_SCHEMA_VERSION = 3`, `KNOWN_PROVIDERS = ["anthropic", "openai", "gemini"]`) и предупреждать пользователей `Cursor / Windsurf` о риске привязки к локальному отпечатку устройства.
- **Решение (без UI-раздувания):**
  1. Сохранить `KNOWN_PROVIDERS = ["anthropic", "openai", "gemini"]` в `state/schema.rs:15`, чтобы существующие `routes`, `ip_history`, `pinned_ips` и `clean_room.profiles` пользователей `v3.1.1` мигрировали без потерь.
  2. Не добавлять новые контролы переопределения `service_route_overrides` в `ConnectScreen.tsx`.
  3. В `clean_room/detector.rs` добавить read-only заметку при наличии локальных файлов `Cursor / Windsurf` (`storage.json` с `telemetry.machineId` / `devDeviceId`) без автоматической модификации чужих файлов: *«Редактор хранит идентификатор устройства локально — частая смена пробных аккаунтов на одном компьютере приводит к блокировке»*.

### 6.4. 1-клик сброс `403 ToS` для Antigravity / Gemini CLI (внутри существующего `SOS`)

В существующем `SosScreen.tsx` (`src/features/sos/SosScreen.tsx` внутри «Аккаунты, Бункер и SOS») добавляется блок помощи при `403 PERMISSION_DENIED` (*"Gemini has been disabled in this account for violation of Terms of Service"*):
1. **Честное предупреждение (One-Time Appeal Policy):** не подключать OAuth-токены Antigravity к сторонним обёрткам и ротаторам (`OpenCode`, `OpenClaw`, `9router`); апелляция даётся **один раз** (48–72 ч), повторное нарушение банит ИИ-доступ навсегда; для сторонних клиентов использовать API-ключ AI Studio / Vertex AI.
2. **Безопасная очистка кешей входа (`clean_antigravity_auth_cache` в `auditor/cache_cleaner.rs`):**
   - По жёсткому allowlist'у удаляет **только** локальные файлы OAuth-токенов/сессий в `~/.gemini/` и `~/.antigravity/` (`oauth_creds.json`, `google_accounts.json` и кеши авторизации), **не трогая** `GEMINI.md`, правила, MCP и проекты.
   - На Windows — **строго Zero-LOLBin**: только `std::fs` и Win32 API (`CreateToolhelp32Snapshot`, `QueryFullProcessImageNameW`, `TerminateProcess`), без `powershell`/`cmd`/`tasklist`/`taskkill`.
3. **Чеклист восстановления:** очистить кеш входа → отозвать сторонние приложения в `myaccount.google.com/connections` → подать единоразовую форму ToS → перезапустить Antigravity через защищённый маршрут.

---

## 7. Платформенные фиксы стабильности, безопасности и macOS (из аудита v3.1.1)

Все шесть фиксов этого раздела устраняют регрессии и краевые дефекты `v3.1.1`, выявленные полевым аудитом, и встраиваются **в существующие экраны и модули** без нарушения инварианта `Zero UI Bloat` и правил `Zero-LOLBin` на Windows.

### 7.1. Синхронизация часового пояса на macOS (`os_tz` / `TerminalSection.tsx` / `useTimezoneSync.ts`)

- **Проблема в `v3.1.1`:** при включённой настройке `keep_system_tz_on_exit` и отсутствии `os_tz_baseline.json` (например, ОС уже находилась в поясе выходного IP `Europe/London`) `build_status_with_keep` (`src-tauri/src/os_tz/sync.rs:13-35`) выставляет `synced = false`. Карточка `TerminalSection.tsx:106-113` проверяет только `osTzStatus?.synced` и ошибочно показывает *«Не синхронизирован с IP»*, а `sync_os_timezone_with_keep` (`os_tz/sync.rs:108-116`) при `existing.is_none() && zones_equivalent(&current_iana, &clean_target)` делает ранний выход с `synced: false` без создания `os_tz_baseline.json` и без объяснения UI.
- **Решение:**
  1. Расширить `OsTzSyncStatus` (`src-tauri/src/os_tz/mod.rs:110-117`) полем `#[serde(default)] pub already_matches_target: bool` (и/или передавать `target_tz` в `get_os_timezone_sync_status_cmd` и `TerminalSection.tsx` / `SettingsModal.tsx`):
     - `build_status_with_keep` при `existing.is_none()` сравнивает `current_os_tz` с резолвленным `target_tz` через `os_tz::mapping::zones_equivalent` и выставляет `already_matches_target = true`.
     - В `sync_os_timezone_with_keep` при совпадении зон без `os_tz_baseline.json` также возвращать `already_matches_target: true` (с `synced: false`, без ненужного вызова `osascript` / изменения ОС).
  2. В `TerminalSection.tsx`: при `osTzStatus?.synced === false && osTzStatus?.already_matches_target === true` отображать нейтрально-зелёный статус **«Совпадает с IP (<current_os_tz>)»** вместо ложного «Не синхронизирован с IP» и отключать/скрывать вводящую в заблуждение кнопку «Синхронизировать».
  3. В `runSharedSyncOsTimezone` (`src/shared/hooks/useTimezoneSync.ts:60-75`): при `res.synced === false && res.already_matches_target === true` не показывать тост об изменении часового пояса и перезапуске браузеров, а выводить информационный тост о том, что часовой пояс ОС уже совпадает с текущим IP.

### 7.2. Автообновление срока действия ВПН Заставы и разблокировка продлённых ключей (`routing/key`, `routes.rs`, `RouteListSection.tsx`)

- **Проблема в `v3.1.1`:** ключи `zastava://<base64 JSON v2>` (`src-tauri/src/routing/key/mod.rs`) статически зашивают `expires_at: Option<u64>` при импорте; при продлении подписки через бота `openZastavaBot` срок в `state.json` никогда не обновляется, а `Route::is_expired_at` / `RouteWatch::is_stale` / `compute_status` жёстко блокируют маршрут раньше проверки живости (`test_route`). При переимпорте ключа без `KeyV2.id` вычисляется новый SHA-256 `id`, что создаёт дубликат маршрута вместо обновления существующего.
- **Решение:**
  1. В `KeyV2` (`src-tauri/src/routing/key/mod.rs`) и `Route` (`src-tauri/src/routing/mod.rs`) добавить опциональное поле `#[serde(default)] pub sub_url: Option<String>` (с валидацией HTTPS-схемы и 100% обратной совместимостью со старыми ключами и `state.json`).
  2. Добавить резолвер метаданных подписки (`refresh_route_subscription` в `src-tauri/src/commands/routes.rs`), поддерживающий заголовок `subscription-userinfo` (`expire=<unix_ts>`) и обновлённый JSON-ключ `KeyV2`:
     - вызывается неблокирующе в фоне при старте приложения (для маршрутов с `sub_url`),
     - автоматически выполняется внутри `test_route` (`commands/routes.rs:209-275`), чтобы продлённый ключ сразу разблокировался проверкой,
     - доступен по кнопке обновления статуса в существующей карточке `RouteListSection.tsx` (без новых экранов).
  3. **Grace-продление для старых уже активированных ключей без `sub_url`:** если у маршрута истёк локальный `expires_at`, но нет `sub_url` (ключ старого формата продлён на сервере бота), при запуске `test_route` (или живом успешном handshake через `entry`) клиент проверяет реальную живость туннеля и при успехе снимает жёсткую блокировку `Expired` (активирует маршрут в статус рабочего/продлённого на сервере с подсказкой при необходимости получить свежий ключ для точной даты), чтобы рабочий продлённый ключ никогда не оставался заблокированным из-за старого локального штампа времени.
  4. При переимпорте ключа (`upsert_route_locked` в `src-tauri/src/state/routes.rs`, deep-link и ручной ввод) и в формате ключей бота использовать стабильный `KeyV2.id`, а при его отсутствии сопоставлять существующий маршрут по нормализованному набору `entries`, обновляя `expires_at` / `sub_url` / `raw_key` на месте без создания дубликатов и потери привязок провайдеров/профилей.

### 7.3. Зависшее предупреждение браузеров без PAC (`relaunch.rs`, `coverageModel.ts`, `reconcile.rs`, `CoverageSection.tsx`)

- **Проблема в `v3.1.1`:** в `relaunch_browsers_with_pac_with` (`src-tauri/src/sysproxy/browser_policies/relaunch.rs:22`) таймаут ожидания закрытия Chrome составляет `BROWSER_QUIT_TIMEOUT = 3500 ms` — незакрывшийся браузер попадает в `summary.skipped`, но `relaunchBrowsersResult` (`src/features/coverage/coverageModel.ts:156-179`) не проверяет `res.skipped.length > 0` и возвращает ложный зелёный тост *«Перезапуск не потребовался»*, пока жёлтый баннер остаётся. Одновременно `detect_browser_pac_status_with` (`reconcile.rs:85-132`) игнорирует активную macOS-политику `PolicyStore` и живое подтверждение в `CoverageTracker` (`Confirmed`), а `all_prefs_match_pac` требует `Preferences["proxy"]` даже в неиспользуемых профилях (`Guest Profile`, `System Profile`). `CoverageSection.tsx:55` также не синхронизирует обновлённый снимок с `gw.coverageSnapshot`.
- **Решение:**
  1. В `relaunch_browsers_with_pac_with` (`relaunch.rs:22`) увеличить `BROWSER_QUIT_TIMEOUT` с `3500 ms` до `9000 ms` (согласовано с окном закрытия вкладок macOS).
  2. В `relaunchBrowsersResult` (`src/features/coverage/coverageModel.ts:156-179`) добавить явную ветку при `res.skipped.length > 0` (до финального fallback): `tone: "warn"`, явное сообщение закрыть перечисленные браузеры вручную через `Cmd+Q` и нажать «Перепроверить».
  3. В `detect_browser_pac_status_with` (`reconcile.rs:115`) и `compute_config_facts` (`pac_verify.rs:42-140`):
     - учитывать активную macOS-политику `PolicyStore` (`ProxyMode = "pac_script"` и совпадение `ProxyPacUrl`) вместе с живым подтверждением трафика `CoverageTracker` (`Confirmed` в актуальной сессии), чтобы реально защищённый Chrome не висел в `browsers_needing_restart`;
     - исключить системные/гостевые неиспользуемые профили (`Guest Profile`, `System Profile`, профили без активной конфигурации) из строгого требования `all_prefs_match_pac`.
  4. Прокинуть обновление в `gw.setCoverageSnapshot` при `applySnapshot` / `recheck` в `CoverageSection.tsx`, чтобы `AppShell` и `HomeHub` получали актуальный снимок без перезагрузки.

### 7.4. Усиление сверки ASN и детекции пулов массовых VPN (`dangerous_asns.json`, `ip_type.rs`, `rules.rs`, `cascade.rs`, `routes.rs`)

- **Проблема в `v3.1.1`:** встроенная база `rules/dangerous_asns.json` (`v1.2.0`) содержит только `3` VPN ASN (`AS9009`, `AS212238`, `AS60068`) и `0` ключевых слов в `isp_keyword_groups["vpn"]`; `keyword_kind` (`rules.rs:115-120`) ищет подстроки без границ слов; `ip_type.rs:197-203` проверяет `if is_pinned` **раньше** `if ip_type == IpType::Vpn`, из-за чего `PINNED_BY_ZASTAVA_KEY` маскирует `HIGH_RISK_MASS_VPN_ASN` под `ASN_VERIFIED_PINNED`; при IPv6 `TorLookup::NotApplicable` (`ip_type.rs:258-268`) обрывает классификацию `Hosting`/`Residential`; `test_route` (`commands/routes.rs:209-275`) не запускает `evaluate_ip_reputation`.
- **Решение:**
  1. Расширить `rules/dangerous_asns.json`: добавить актуальные ASN популярных коммерческих VPN-пулов, Cloudflare WARP (`AS13335`) и массовых дешёвых хостингов + секцию `isp_keyword_groups["vpn"]`; в `rules.rs:115-120` перевести `keyword_kind` на word-boundary матчинг.
  2. В `NetworkResolver::cascade_query` (`src-tauri/src/auditor/network/cascade.rs`) сделать парсинг `AS<num>` в `ipinfo.io` регистронезависимым и не полагаться на пустой по ASN/ISP ответ `1.1.1.1/cdn-cgi/trace` как на достаточный источник при наличии privacy/hosting метаданных из основных источников.
  3. В `evaluate_ip_reputation` (`src-tauri/src/auditor/ip_type.rs`):
     - проверять `IpType::Vpn` / `Tor` **до** смягчения по `PINNED_BY_ZASTAVA_KEY`, чтобы ключ или закрепление не скрывали факт выхода через массовый VPN-пул (различая явный пользовательский `pin` домашнего/личного VPS и авто-флаг маршрута);
     - при `TorLookup::NotApplicable` (IPv6) не делать ранний выход, а продолжать классификацию `Hosting` / `Residential` / `ASN_CLEAN`.
  4. В `commands/routes.rs` (`test_route`) возвращать результат `evaluate_ip_reputation` для выходного IP ключа, чтобы UI при импорте стороннего ключа сразу предупреждал о shared/hosting/mass-VPN пуле.

### 7.5. Стабильность ключа Заставы поверх системного VPN (`V2BOX Pro` / TUN: `cascade.rs`, `connect.rs`, `routing/net/`, `entry_connect.rs`, `entry_relay.rs`, `handshakes.rs`)

- **Проблема в `v3.1.1`:** при работе ключа Заставы поверх системного VPN (`V2BOX Pro` / TUN) запросы идут двойным туннелем (`Client -> Zastava -> V2BOX TUN -> Entry -> Target`). Это приводит к регулярным таймаутам из-за: (а) жёсткого `REQUEST_TIMEOUT_MS = 3500` ms + `.pool_max_idle_per_host(0)` в `entry_client_builder` (`cascade.rs:82-86`) на синхронном первом `CONNECT` (`connect.rs:308-338`), где любой таймаут аудита роняет маршрут в `RouteDownReason::Unreachable`; (б) сжигания `2.5–3.7s` в `parallel_fallback_resolve_addrs` при FakeIP (`198.18.0.0/15`) от V2BOX и `ENTRY_DNS_CACHE_TTL = 60s` до использования `chained_proxy`; (в) IPv6-first в `order_socket_addrs` и отсутствия Happy Eyeballs в `entry_relay.rs:134` (`TcpStream::connect`), плюс пропуска `entry_relay` для HTTPS-entry с IP-литералом (`cascade.rs:106-107`); (г) последовательного перебора `route.entries` с таймаутом `12s` на каждый и побайтового чтения в `http_connect_exchange` / `entry_relay`.
- **Решение:**
  1. **Раздельные таймауты и fail-soft аудита живого маршрута (`cascade.rs`, `evaluate.rs`, `connect.rs`):** для `route.is_some()` (двойной туннель) увеличить `REQUEST_TIMEOUT_MS` (до `8000 ms`) и `CHECK_LIMIT_IO` (до `8–10s`), переиспользовать один keep-alive `route_client` внутри одного прохода каскада вместо `.pool_max_idle_per_host(0)`. В `handle_connect_request` (`connect.rs:325-338`) не сбрасывать живой туннель при таймауте внешнего GeoIP-пробера, если `connect_via_route` / недавняя телеметрия маршрута жива.
  2. **Оптимизация DNS при FakeIP и `chained_proxy` (`routing/net/mod.rs`, `dns.rs`, `entry_connect.rs`):** увеличить `ENTRY_DNS_CACHE_TTL` до `300–600s` (с фоновым обновлением), а при активном `chained_proxy` / FakeIP-ответе `198.18.0.0/15` не блокировать старт коннекта `2.5–3.7s` ожиданием `parallel_fallback_resolve_addrs` (делегируя доменный коннект `chained_proxy` или используя асинхронный DoH-кэш).
  3. **Happy Eyeballs IPv4-first при TUN и фикс `entry_relay` (`handshakes.rs`, `entry_relay.rs`, `cascade.rs`):** в `entry_relay.rs:134` заменить `TcpStream::connect(&addrs[..])` на `tcp_connect_addrs` (Happy Eyeballs) с приоритетом IPv4 при активном `chained_proxy`/TUN или недавних ошибках IPv6; убрать пропуск `entry_relay` для `EntryProto::Https` с IP-литералом (`cascade.rs:106-107`).
  4. **Ускорение handshake и `route.entries` (`proxy/upstream/mod.rs`, `handshakes.rs`, `entry_relay.rs`):** внедрить staggered/hedged старт по `route.entries` (например, 400–600 ms headstart вместо последовательных `12s`) и заменить побайтовое чтение в `http_connect_exchange` / `entry_relay` на буферизованный `BufReader`.

### 7.6. Жёсткий контроль `trusted_exceptions` и фикс «самопоявляющихся» исключений (`exceptions.rs`, `decisions.rs`, `interception/helpers.rs`, `audit/helpers.rs`, `useOverviewModel.ts`, `ServiceRow.tsx`, `probe_changed.rs`, `audit_outcome.rs`)

- **Проблема в `v3.1.1`:** при смене IP срабатывает связка из 4 дефектов:
  1. Любое нажатие `AllowSession` / `allow_provider_session` (`decisions.rs:228`, `commands/interception/helpers.rs:188`, `commands/audit/helpers.rs:173`) **безусловно** пишет IP навечно в `trusted_exceptions` в `state.json` без отдельного согласия пользователя.
  2. В `allow_network_alert` (`decisions.rs:191`) используется `inner.observed_ip.clone().unwrap_or_else(|| tel.ip.clone())` (риск сохранить устаревший `observed_ip` вместо `tel.ip` нового аудита), а `resolve_exit_ip_for_provider` / `resolve_provider_telemetry_for_allow` при сбое резолва откатываются к `current_observed_ip()` / прошлому алерту.
  3. В `useOverviewModel.ts:105-113` совпадение `pinned_ip` при единственном критическом флаге `IMPOSSIBLE_TRAVEL_CRITICAL` возвращает `status = "allowed"`, из-за чего `ServiceRow.tsx:41-44` (`overview.ts:55`) через несколько секунд выводит строку **«Разрешён для текущего IP (исключение в Настройках)»**, даже когда `trusted_exceptions` пуст. Кроме того, `begin_changed_probe` (`probe_changed.rs:120`) сначала тормозит все провайдеры, а через 2–6 с `apply_audit_outcome_locked` (`audit_outcome.rs:157-164`) асимметрично разблокирует часть провайдеров (по старым вечным `trusted_exceptions` или по `Yellow` `IMPOSSIBLE_TRAVEL_WARNING` у OpenAI/Gemini).
  4. `allow_provider_for_session` (`state/exceptions.rs:40`) удаляет провайдера из `blocked_providers` до проверки `!guard.is_manual_killswitch()` в `interception/helpers.rs:178` и `audit/helpers.rs:160`.
- **Решение:**
  1. **Разделить эфемерное разрешение на сессию и постоянное исключение (`trusted_exceptions`):** убрать автоматический вызов `add_trusted_exception` из `AllowSession` (`allow_network_alert`, `resolve_interception_with_params`) и `allow_provider_session_inner`. Запись в `trusted_exceptions` должна происходить **исключительно** по явному отдельному действию / опции пользователя (`persist_exception: true` с явным перечнем провайдера и точного нового IP).
  2. **Устранить захват устаревшего IP при записи исключения:** в `decisions.rs:191` использовать исключительно подтверждённый `tel.ip` текущего аудита (не `inner.observed_ip`); в `audit/helpers.rs` и `interception/helpers.rs` запрещать запись в `trusted_exceptions`, если свежий egress IP конкретного провайдера не разрешился на текущем запросе.
  3. **Исправить UI-индикацию в `useOverviewModel.ts` и `ServiceRow.tsx`:** разделить состояния:
     - реальное постоянное исключение из `state.trusted_exceptions` → *«Разрешён для текущего IP (исключение в Настройках)»*;
     - эфемерное `session_allowed_providers` → *«Разрешён только для текущей сессии»*;
     - `pinned_ip` с `IMPOSSIBLE_TRAVEL_CRITICAL` → отдельный статус *«Доступен (закреплённый IP)»* без ложной ссылки на «исключение в Настройках».
  4. **Запретить мутацию состояния при ручном Kill-Switch и выровнять поведение при смене IP:** в начале `AllowSession` (single-provider) и `allow_provider_session_inner` проверять `guard.is_manual_killswitch()` **до** вызова `allow_provider_for_session`, возвращая `BlockedByManualKillswitch`; синхронизировать `probe_changed.rs` и `audit_outcome.rs`, чтобы поведение при наличии активного `trusted_exceptions` было прозрачным и не создавало эффекта «самопоявляющихся» исключений.

### 7.7. Strict Fail-Closed Guard, мгновенный детект переключения VPN и честный статус UI (live-тест v3.2.0)

* **Проблема (подтверждена кодом ядра и UI):**
  1. `compute_local_route_fingerprint` (`proxy/guard/types.rs`) хэширует только `local_ip` и `chained_proxy` — при переключении сервера внутри того же VPN-клиента (`V2BOX Pro`, `Happ` TUN или локального прокси-порта) `last_route_fp` не меняется, `check_route_fingerprint_sync` оставляет `Gate::Open` и ждёт медленный `ProbeRegular`.
  2. `apply_regular_probe_unlocked` (`probe_loop.rs`, `probe_apply.rs`) при `probe() == None` (кратковременный разрыв/переключение VPN) делает ранний `return` с `Gate::Open`, не вызывая `abort_active_tunnels()` и не поднимая `alert-popup`.
  3. Во время проверки / «Нет данных» и на активных туннелях (`connect.rs`, `tunnel.rs`) доступ к Claude остаётся открытым (не сработавший триггер на `CONNECT`, кэш 15с, неочищенный `session_allowed_providers`, плюс тихий авто-допуск чистого не-закреплённого IP без исключения через `report_allowed_for_state` в `policy.rs`).
  4. UI (`useGatewayState.ts`, `useTrayEvents.ts`, `useOverviewModel.ts`) не инвалидирует прежние `reports` при `network://changed` / `interceptor://risk-detected` (`phase: "detecting"`) и проверяет `refreshing` только при `!report`, показывая «Доступен» на фоне «Нет данных»; а при активном `route://unavailable` общий щит продолжает показывать зелёный «Вы защищены · 100 из 100».
* **Решение:**
  1. **Мгновенный Fail-Closed при `probe() == None` и смене VPN-узла:** `ROUTE_CHECK_INTERVAL_MS` снижен до `150 мс`, в `compute_local_route_fingerprint` добавлен in-process детект активных сетевых интерфейсов/туннелей (`libc::getifaddrs`: `utun`/`tun`/IPv4/IPv6), а для HTTP-проб заданы `connect_timeout(500ms)` и fast-fail при первом сбое: при любом обрыве или переключении после установленного `baseline` unrouted gates **немедленно** переходят в `Gate::Pending`, сбрасывается unrouted `session_allowed_providers`, чистятся DNS/telemetry кэши, вызывается `abort_active_tunnels()` и поднимается `alert-popup` (`phase: "detecting"`) ДО старта фоновых ретраев/аудита.
  2. **Строгий блок до завершения аудита и устойчивая «Пауза до смены сети»:** пока состояние `Gate::Pending`, «Нет данных» или идёт перепроверка, любые входящие `CONNECT` и открытые туннели по защищённым провайдерам режутся сразу; решение об открытии принимается строго **после** завершения полного аудита, сверки `pinned_ip` и проверки `trusted_exceptions`. Если новый IP не закреплён и для него нет валидного `trusted_exception` (`AskPopup`), доступ не открывается молча и запрашивает решение в `alert-popup`. При нажатии **«Пауза до смены сети»** (`PauseMode::UntilNetworkChange`) в `detecting`/окне фиксируются `pause_epoch` и `pending_pause_ip_bind`: окно сразу закрывается, фоновые эмиттеры алертов (`risk-detected`/`enriched`) подавляются на бэкенде и во фронтенде (`AlertWindow.tsx`, `useTrayEvents.ts`), а первый завершившийся аудит усыновляет установившийся IP/fingerprint как baseline паузы вместо повторного открытия окна.
  3. **Честный UI-статус и инвалидация кеша:** на `network://changed`, `interceptor://risk-detected` (`detecting`) и `guard://pause-status-changed` фронтенд переводит unrouted отчёты в `checking` (stale), `useOverviewModel.ts` приоритетно показывает статус проверки/блокировки вместо устаревшего «Доступен», а при активных ошибках `route://unavailable` щит не отображает «Вы защищены · 100 из 100».
  4. **Мгновенный нативный попап/трей, полный авто-анлок на `pinned_ip` и Windows-паритет:** `probe_loop`/`gates` работают с `pool_max_idle_per_host(0)` и `400ms` fast-fail, `freeze_providers_pending_quiet` исключает промежуточное мерцание иконки трея перед авторитетным эмиттом, `popup.rs` напрямую поднимает окно (`unminimize`/`always_on_top`/`show`/`focus`) без ожидания JS скрытого WebView, `tray/view.rs` + `app/watchers.rs` (`tokio::select!`) мгновенно обновляют иконку/меню трея (`check-tray-main-thread`); `try_silent_paused_recovery`, `try_silent_recovery_on_startup`, `ensure_open_for_verified`, `baseline_restore.rs`, `audit_outcome.rs` и `policy.rs` бесшовно снимают `blocked_providers`, `PauseMode::UntilNetworkChange` и travel-блок при любом многохоповом возврате на `pinned_ip`/`pinned_ips` без спама окнами при реальных критических флагах; `fingerprint.rs` на Windows использует нативный `Win32 GetAdaptersAddresses` (Zero-LOLBin).

### 7.8. Стабильность и скорость ключа Заставы поверх активного VPN (Gemini / V2BOX Pro) и на длинных сессиях

* **Проблема (подтверждена профилированием `connect.rs`, `auditor`, `routing` и тестами длинного ризонинга):**
  1. На каждый новый `CONNECT` для `route.is_some()` `connect.rs` синхронно запускает полный 14-чековый аудит `evaluate_all_with(..., false)` (Step 4 не кэширует `session_allowed_providers` / `RiskReport` на маршрут).
  2. Каждый такой вызов в двойном туннеле (VPN + ключ Заставы) делает некешированные запросы с таймаутами `8–10s`: `Provider Exit` (`https://ipinfo.io/json` через `spawn_entry_relay` + `DIRECT_HEADSTART = 700ms`), `Reverse DNS` (`4s`), последовательный `cascade_via_route` (`ipwho.is` -> `ipinfo.io` -> `freeipapi.com` до `8s` каждый), а ошибки DNSBL/Tor кешируются лишь на `5s`.
  3. `GEMINI_DOMAINS` (`geo_matrix/domains.rs`, `pac.rs`) включает 44 широких Google-домена (`www.google.com`, `accounts.google.com`, `apis.google.com`, `play.google.com`, `clients6.google.com`), умножая число одновременных `CONNECT` и синхронных `10s`-ожиданий.
  4. В режиме TUN VPN без `chained_proxy` (`V2BOX Pro` / `Happ`) `fast_fake_ip_with_chained == false` заставляет `resolve_entry_checked_with` ждать `1500ms`, `tcp_connect_addrs` (`handshakes.rs`) пробует IPv6 раньше IPv4 (`prefer_v4_hint = false`), а `clear_entry_dns_cache()` сбрасывает DNS-кеш без смены внешнего пути.
  5. На длинных сессиях (ризонинг моделей в Antigravity) провал фонового GeoIP-аудита по таймауту мог отравить последующие `CONNECT`, а «тихие» паузы в 60–180 с без OS `TcpKeepalive` рвались NAT-таблицами VPN/xray (`model unavailable`).
* **Решение:**
  1. **Per-route кэш аудита с grace TTL на сбой фонового GeoIP (`route_audit.rs`, `connect.rs`):** `RouteReportCache` (single-flight, 60 s TTL, 30 s фоновое обновление) + `10m` `ROUTE_REPORT_GRACE_TTL` (`30s` cooldown): провал фонового GeoIP-запроса сохраняет последний валидный `RiskReport` и не помечает маршрут `unreachable` (`can_soft_bypass_audit` отключается только если сам маршрут помечен недоступным по живому сокету/ошибке).
  2. **Стабильность длинных стримов и ризонинга (`tunnel.rs`, `handshakes.rs`):** OS-level `TcpKeepalive` (`15s` idle / `15s` interval) + `TCP_NODELAY` на клиентском и upstream `TcpStream`, буферы релея `64 KiB`, `flush()` перед `shutdown()` на half-close EOF и устойчивость к `is_peer_gone`.
  3. **Оптимизация TUN + double-tunnel (`routing/net`, `handshakes`, `entry_relay`, `cascade`) и очистка `GEMINI_DOMAINS`:** хеджированный `cascade_query`, быстрое принятие TUN FakeIP, `prefer_v4_hint = true` по умолчанию и удаление 10 шумовых не-AI доменов Google из `GEMINI_DOMAINS` с сохранением Gemini/AI Studio и Auth.

### 7.9. Платформенные фиксы macOS по инциденту пользователя (ChatExport 2026-11-24)

* **Диагностика инцидента:** внешний прокси `64.176.194.110` (`AS20473` Vultr US) проверен и чист (не в Tor exit list, чист по DNSBL, доступен); при этом приложение пользователя на macOS сломалось из-за двух локальных дефектов:
  1. **`Too many open files (os error 24)` (`EMFILE`):** macOS `.app` наследует лимит `RLIMIT_NOFILE = 256`, равный `MAX_CONCURRENT_CONNECTIONS = 256` (`proxy/server/mod.rs`), из-за чего заканчиваются дескрипторы сокетов и падает запуск `networksetup`.
  2. **Ошибка `clear_pac_url` на macOS 15.6.1:** вызов `networksetup -setautoproxyurl <svc> ""` падает с `code=Some(4): ** Error: The parameters were not valid` (`sysproxy/platform/macos.rs`, `real.rs`, `macos/privileged.rs`).
* **Решение:**
  1. Поднимать `RLIMIT_NOFILE` при запуске процесса на Unix/macOS (`min(rlim_max, 8192)`) с логированием, исключая `os error 24` под нагрузкой.
  2. Исправить `clear_pac_url` на macOS: вместо передачи невалидного `""` в `-setautoproxyurl` выключать PAC штатно через `-setautoproxystate <svc> off` во всех местах (`macos.rs`, `real.rs`, `macos/privileged.rs`).

---

## 8. Архитектурные ограничения, фазы реализации, E2E-тесты и DoD

### 8.1. 4-слойная Clean Hexagonal архитектура, совместимость и бюджеты

Все новые модули соблюдают `scripts/check-architecture.mjs` (без восходящих импортов и без расширения пустого `LEGACY_ALLOWLIST`):

- **Layer 0 (`src-tauri/src/core/`):**
  - `core/bin_radar.rs`: `BinRadarReport`, `BinRadarStats`, валидация `^[0-9]{8}$`, экспоненциальное затухание и порог `n >= 5`.
  - `core/payment_advisor.rs`: `AdvisorQuery`, `AdvisorPlan`, `KycRiskTier`, правила для Сценариев 1–5 и Per-Service Auto-Demote (`> 40%` при `n >= 15`).
  - `core/providers_manifest.rs`: `ProviderEntry`, `ProvidersManifest`.
  - `core/context_teleport.rs`: `TeleportTarget`, `ContextTeleportResult`, детерминированные форматтеры + инлайн-редакция секретов поверх `core/sanitize.rs` и `core/redact.rs`.
- **Layer 1 (`src-tauri/src/state/`, `src-tauri/src/routing/`):**
  - `schema.rs` (`CURRENT_SCHEMA_VERSION = 3`, все новые поля с `#[serde(default)]` для 100% обратной совместимости с `v3.1.1`): `bin_radar_opt_in: bool`.
  - `routing/key/mod.rs` + `routing/mod.rs`: опциональное `sub_url: Option<String>`, дедупликация при переимпорте по `id` / `entries` и снятие локальной блокировки `Expired` при успешном живом тесте старых ключей без `sub_url`.
  - `state/exceptions.rs`: строгое разделение `session_allowed_providers` и `trusted_exceptions`.
- **Layer 2 (`src-tauri/src/auditor/`, `src-tauri/src/bunker/`, `src-tauri/src/clean_room/`, `src-tauri/src/bin_checker/`, `src-tauri/src/os_tz/`, `src-tauri/src/sysproxy/`, `src-tauri/src/proxy/`):**
  - `auditor/bin_radar_verify.rs`, `auditor/payment_advisor.rs` (+ встроенные `rules/bin_radar_snapshot.json`, `rules/providers_manifest.json`, `rules/payment_advisor_matrix.json`).
  - `bunker/teleport.rs`, `bunker/payment_passport.rs` (`PassportChannel::GooglePlayIap` с алиасами `v3.1.1`).
  - `clean_room/detector.rs` + `auditor/cache_cleaner.rs` (`clean_antigravity_auth_cache`, read-only проверка `machineId`).
  - `auditor/geo_matrix/` + `rules/provider_matrix.json` (`session_ip_stability_for_studio`).
  - `os_tz/` (`already_matches_target`), `sysproxy/browser_policies/` (`BROWSER_QUIT_TIMEOUT`, `PolicyStore`/`Confirmed`, пропуск `Guest`/`System`), `auditor/ip_type.rs` + `rules/dangerous_asns.json` + `auditor/network/cascade.rs`, `proxy/upstream/` + `routing/net/` (двойной туннель, FakeIP, Happy Eyeballs, `BufReader`), `proxy/guard/` (`decisions.rs`, `probe_changed.rs`, `audit_outcome.rs`).
- **Layer 3 (`src-tauri/src/commands/`, `src/`):**
  - `commands/payment.rs`: `get_payment_advice`, `submit_bin_radar_report`, `get_bin_radar_stats`, `get_providers_manifest`, мультисервисный `evaluate_payment_readiness`.
  - `commands/bunker.rs`: `run_context_teleport`.
  - `commands/clean_room/` / `audit/` / `routes.rs` / `interception/`: `clean_antigravity_auth_cache`, `refresh_route_subscription`, явный opt-in флаг `persist_exception` для `trusted_exceptions`.
  - UI встраивается **только в существующие компоненты** (`PaymentFlowPanel.tsx`, `PaymentGuide.tsx`, `BunkerCard.tsx`, `BannedBranch.tsx`, `SosScreen.tsx`, `SandboxProfilesCard.tsx`, `LaunchpadSteps.tsx`, `TerminalSection.tsx`, `RouteListSection.tsx`, `CoverageSection.tsx`, `ServiceRow.tsx`, `AlertWindow.tsx`), вызовы `invoke()` строго в `src/utils/api/`.
- **Бюджеты и стиль:** `≤ 350` soft / `≤ 500` hard строк на prod-файл, `≤ 700` на test-файл, `≤ 400` с inline `#[cfg(test)]`; `0` сырых hex/rgb (`pnpm lint:hex`); `BRAND.md` + `copyGuards.test.ts` (без жаргона, `0` эмодзи, 1 `brand` CTA на экран).

### 8.2. Фазы реализации (Фаза 1–6)

1. **Фаза 1 — Платформенные фиксы стабильности, безопасности и macOS (§7.1–7.6):** macOS TZ (`already_matches_target`), автообновление `expires_at` / `sub_url` + grace-продление, Chrome PAC relaunch & detector, ASN/VPN-база + IPv6/pinned fix, стабильность двойного туннеля (`V2BOX Pro` / FakeIP / `BufReader`), строгая изоляция `trusted_exceptions`.
2. **Фаза 2 — PayShield Phase 2 Core (`src-tauri/`):** `bin_radar.rs`, `payment_advisor.rs` (Сценарии 1–5 + Per-Service Auto-Demote), `providers_manifest.rs`, `GooglePlayIap`, Ed25519 верификация и встроенные бандлы `rules/*.json`.
3. **Фаза 3 — Телепорт памяти в Бункере (`src-tauri/`):** `core/context_teleport.rs`, `bunker/teleport.rs`, `run_context_teleport`, unit-тесты на санитизацию секретов и лимиты `ChatGPT`.
4. **Фаза 4 — Единая «Чистая комната», `403` SOS и AI Studio stability (`src-tauri/`):** сценарии в `clean_room/`, `session_ip_stability_for_studio`, Zero-LOLBin `clean_antigravity_auth_cache`.
5. **Фаза 5 — Интеграция в существующий UI (`src/`):** `PaymentFlowPanel`/`PaymentGuide` (Advisor + строка `BIN Radar`), `BunkerCard` + `BannedBranch` (переключатель формата телепорта), `SandboxProfilesCard` + `LaunchpadSteps` (пресет Gemini/AI Studio и переключение 2–3 профилей), `SosScreen` (сброс `403 ToS`), плюс UI-части §7.1–7.6 (`TerminalSection`, `RouteListSection`, `CoverageSection`, `ServiceRow`, `AlertWindow`).
6. **Фаза 6 — Сквозные E2E-тесты, Zero-Regression & DoD (macOS + Windows).**

### 8.3. Обязательные E2E-тесты и DoD (критерии приёмки)

1. **Ed25519 Tamper & Offline Fallback E2E:** подмена 1 байта в `snapshot.json` / `providers_manifest.json` → отклонение с сохранением кэша; при `503` / офлайне UI работает без ошибок.
2. **Zero-PII / Zero-PCI Fuzz Test:** лишние поля (`email`, `ip`, `last4`, `pan`) или 16-значный PAN → `400 Bad Request` на Worker и отказ сериализатора клиента.
3. **Statistical Hygiene & Per-Service Auto-Demote E2E:** при `n = 4` → `insufficient_data`; при `n = 15` и `7` `instant_kyc + instant_ban` (`46.7% > 40%`) по `gemini` / `claude_pro` провайдер с партнёрской ссылкой понижается до `demoted_warning`.
4. **Safe Payment Advisor 5-Scenario E2E:** проверка всех 5 сценариев (`Apple IAP`, `Direct Stripe Web`, `Rescue Flow SG BIN`, `Gemini + Google Payments Profile Lock / OR-CCSEH-21`, `ChatGPT/Cursor`).
5. **Телепорт памяти Zero-Secret E2E:** на фикстуре `~/.claude` с токеном `sk-ant-api03-SECRET123` и `.credentials.json` → `run_context_teleport` генерирует `GEMINI.md`, `SYSTEM_INSTRUCTIONS_GEMINI.txt`, `.cursor/rules/migrated-context.mdc`, `CHATGPT_CUSTOM_INSTRUCTIONS.txt` (`<= 1500` симв./блок), `RESTORE_PROMPT.md` с **0 утечками** секретов и правами `0o600`/`0o700`.
6. **Единая «Чистая комната», `state.json` v3 Compatibility & `403` SOS E2E:**
   - Два профиля `provider = "gemini"` запускаются в `SandboxProfilesCard` с независимыми `--user-data-dir`, `127.0.1.x` и `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` без пересечения кук `PREF`/`NID`.
   - Загрузка `state.json` от `v3.1.1` без новых полей проходит без ошибок с сохранением всех маршрутов, `pinned_ips`, `ip_history` и `PaymentPassport`.
   - `session_ip_stability_for_studio` удерживает предупреждение/защиту при смене IP/ASN во время трафика к `aistudio.google.com`.
   - `clean_antigravity_auth_cache` удаляет только OAuth-кеши из `~/.gemini` и `~/.antigravity`, сохраняя `GEMINI.md`, и проходит Zero-LOLBin тест (`windows_av_and_upgrade_migration`).
7. **Платформенные фиксы v3.1.1 E2E (по §7.1–7.6):**
   - **macOS TZ E2E:** при `keep_system_tz_on_exit = true`, удалённом `os_tz_baseline.json` и совпадении системного пояса с поясом выходного IP `already_matches_target == true`, UI отображает *«Совпадает с IP»*, а клик синхронизации не показывает ложный тост смены пояса.
   - **VPN Subscription Expiry E2E:** продление подписки с новым `expires_at` на mock-endpoint `sub_url` (или `subscription-userinfo`) через `refresh_route_subscription` / `test_route`, снятие блокировки `Expired` при успешном живом тесте для старого ключа без `sub_url`, а также переимпорт ключа с тем же `id`/`entries` обновляют существующий маршрут в `state.json` без создания дубликата и переводят статус из `Expired` в рабочий.
   - **Browser PAC Relaunch & Detector E2E:** возврат непустого `res.skipped` в `relaunchBrowsersResult` выдаёт warning *«закройте вручную через Cmd+Q»* вместо зелёного «Перезапуск не потребовался»; при активном `PolicyStore` (`pac_script`) + `Confirmed` трафике неиспользуемые `Guest`/`System` профили не держат ложный баннер; `gw.coverageSnapshot` обновляется синхронно.
   - **ASN & VPN Pool Detection E2E:** массовый VPN ASN (`AS9009` / WARP `AS13335` / слово из `isp_keyword_groups["vpn"]` с word-boundary) не маскируется `PINNED_BY_ZASTAVA_KEY` в `ASN_VERIFIED_PINNED`, IPv6-адреса при `TorLookup::NotApplicable` корректно классифицируются как `Hosting`/`Residential`, а `test_route` возвращает оценку репутации выходного IP.
   - **Double-Tunnel (`V2BOX Pro` / FakeIP) E2E:** имитация `chained_proxy` + FakeIP (`198.18.x.x`) + мёртвый IPv6 + медленный TLS/CONNECT: `entry_relay` выбирает IPv4 через Happy Eyeballs, `connect_via_route` не жжёт 3.7s в fallback DNS, аудит использует буферизованное чтение и увеличенные таймауты без ложного `RouteDownReason::Unreachable`.
   - **Strict `trusted_exceptions` & Kill-Switch E2E:** вызов `AllowSession` / `allow_provider_session` без явного `persist_exception: true` разрешает только текущую сессию и оставляет `trusted_exceptions` пустым; при ручном Kill-Switch `allow_provider_session` / `AllowSession` отклоняются с `BlockedByManualKillswitch` без очистки `blocked_providers`; при сбое резолва stale `observed_ip` не попадает в `trusted_exceptions`; UI не рисует «исключение в Настройках» для `pinned_ip` с `IMPOSSIBLE_TRAVEL_CRITICAL`.
8. **Ремедиация live-теста v3.2.0 и инцидента macOS E2E (по §7.7–§7.9):**
   - **Strict Fail-Closed Switch, Instant Popup, Reactive Tray & Pinned Auto-Unlock E2E:** при `probe() == None`, fast-fail ошибке пробы (`400ms`, `pool_max_idle_per_host(0)`) или смене VPN/TUN/DNS узла (детект каждые `150 мс` через `fingerprint.rs`: `getifaddrs` на macOS / `Win32 GetAdaptersAddresses` на Windows Zero-LOLBin) unrouted gates **мгновенно** переходят в `Gate::Pending`, обрывают туннели, поднимают `"alert"` напрямую из `popup.rs` (`.unminimize`/`.show`/`.set_focus`) и синхронно обновляют трей (`tray/view.rs` + `tokio::select!` `app/watchers.rs`). При нажатии *«Пауза до смены сети»* в момент проверки (`detecting`) дальнейшее разрешение IP усыновляется как baseline паузы без повторного открытия окна. При возврате на `pinned_ip`/`pinned_ips` после многохоповых переключений/блокировок (`Pinned -> RU -> DE -> Pinned`) `blocked_providers` и travel-блоки снимаются автоматически без ручной разблокировки (`instant_popup_pause_e2e.rs`, `pinned_unlock_v321_e2e.rs`, `windows_av_and_upgrade_migration`). Пока проверка идёт / «Нет данных» и если у нового IP нет ни `trusted_exception`, ни `pinned_ip` (`AskPopup`), входящие `CONNECT` и туннели Claude/AI блокируются; UI (`useOverviewModel.ts`) показывает *«Проверяем…»*/*«Заблокирован»*, а при `route://unavailable` щит не светится зелёным «Вы защищены · 100».
   - **Zastava Key over VPN (Gemini) Speed & Long Reasoning Session E2E:** параллельные `CONNECT` для Gemini при активном маршруте и `chained_proxy` / TUN FakeIP не запускают синхронно 14-чековый аудит (`RouteReportCache`); сбой фоновой GeoIP-пробы сохраняет последний валидный отчёт на `10m` grace TTL и не помечает маршрут `unreachable`; сокеты туннеля держат `15s` OS `TcpKeepalive`, `TCP_NODELAY`, `64 KiB` буферы и корректный half-close для длинного ризонинга без `model unavailable` (`key_long_session_e2e.rs`, `key_vpn_perf_and_macos_e2e.rs`).
   - **macOS `RLIMIT_NOFILE` & `clear_pac_url` E2E:** на Unix/macOS мягкий лимит дескрипторов при старте поднимается выше `256` (`>= 4096` при доступном `rlim_max`), а `clear_pac_url` вызывает `-setautoproxystate <svc> off` без пустого аргумента `""` (zero `code=4` в `networksetup`).

#### Команды верификации (DoD)

```bash
pnpm build
pnpm lint:hex
node scripts/check-architecture.mjs --self-test
pnpm test
node scripts/check-tray-main-thread.mjs --self-test
cargo test --manifest-path src-tauri/Cargo.toml
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets
```

#### Проверка Git-инварианта

Перед любым коммитом и релизом обязательна проверка, что черновик и релизные спеки не попали в индекс git:

```bash
git ls-files 'spec-v3.2*.md'
# Ожидаемый вывод: пусто (exit code 0, 0 строк)
```
