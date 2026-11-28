// Данные хостингов и платёжных маршрутов.

export interface VpsProvider {
  id: string;
  name: string;
  tier: string;
  badge: string;
  price: string;
  locations: string[];
  payments: string[];
  specs: string;
  url: string;
  description: string;
}

export type PaymentProviderTier = "tier1_iap" | "tier2_conditional";

export interface ProviderAlternative {
  title: string;
  text: string;
}

export interface VirtualCardProvider {
  id: string;
  name: string;
  subtitle: string;
  badge: string;
  tier: PaymentProviderTier;
  url?: string;
  description: string;
  steps?: string[];
  alternative?: ProviderAlternative;
  warnings: string[];
  nuances?: string[];
}

export interface BlacklistedProvider {
  id: string;
  name: string;
  reason: string;
}

export const VIRTUAL_CARD_PROVIDERS: VirtualCardProvider[] = [
  {
    id: "tbank",
    name: "Т-Банк (подарочная карта США)",
    subtitle: "Покупка в приложении банка · также СберБанк Онлайн",
    badge: "Рекомендуем",
    tier: "tier1_iap",
    description:
      "Подарочная карта США для оплаты подписки через App Store. Проходит без проверки документов на сайте ИИ.",
    steps: [
      "В приложении Т-Банка откройте **«Платежи» → «Все» (или «Игры»)**, найдите **«Apple»** и выберите регион **США** (не «Россия», там наценка около +60%).",
      "Выберите номинал от `$2` до `$100` (для первой проверки возьмите `$2` или `$5`) и укажите почту — код придёт письмом (проверьте «Спам»).",
      "В App Store на отдельном аккаунте США откройте профиль → **«Погасить подарочную карту или код»** → **«Ввести код вручную»**.",
    ],
    alternative: {
      title: "Вариант через СберБанк Онлайн",
      text: "«Платежи» → «Отдых и развлечения» → «Онлайн-сервисы / Игры» → `Apple Card` → **США** (номиналы от `$2`, цена близка к курсу ЦБ).",
    },
    warnings: [
      "Выбирайте только регион **США** — позиция «Россия» идёт с наценкой около +60%.",
      "Используйте собственный отдельный **US Apple ID** (не покупайте готовый и не используйте основной личный iCloud).",
    ],
    nuances: [
      "Начинайте с тестового номинала `$2` или `$5`, чтобы проверить зачисление кода на аккаунт.",
      "Банк выступает витриной для поставщика кодов, поэтому возврат по зависшим кодам может занять время.",
    ],
  },
  {
    id: "kupikod",
    name: "Kupikod",
    subtitle: "Покупка подарочной карты США онлайн",
    badge: "Через App Store",
    tier: "tier1_iap",
    url: "https://kupikod.com/",
    description:
      "Пополнение отдельного US Apple ID подарочной картой для оплаты подписок Claude Pro и Max (включая Claude Code).",
    warnings: [
      "Наценка около 25–34% к курсу; перед оплатой снимите галочку «Пропуск Kupikod» (подписка 299 ₽/мес).",
      "Используйте отдельный **US Apple ID** и начинайте с тестового номинала `$2` или `$5`.",
    ],
    nuances: [
      "Сделайте непрерывную видеозапись экрана от оплаты до активации кода в App Store.",
      "Если код не сработал, написать на `support@kupikod.com` нужно в течение **2 часов**; возвраты по умолчанию начисляются в `Kupicoins`.",
    ],
  },
  {
    id: "wanttopay",
    name: "WantToPay",
    subtitle: "Виртуальная карта в Telegram · тарифы Easy / Smart",
    badge: "Картой на сайте",
    tier: "tier2_conditional",
    url: "https://telegram.me/WantToPayBot?start=w17851188--ERIEX",
    description:
      "Подходит для подписки на сайте `claude.ai`. Выбирайте только тариф `Easy` или `Smart` — предоплаченная карта не подходит.",
    warnings: [
      "Берите только тариф `Easy` или `Smart` (не предоплаченная) при совпадении карты, адреса оплаты и подключения США.",
      "Проверьте первые 6–8 цифр карты и выдержите **96 часов** прогрева до оплаты и **72 часа** защиты маршрута после.",
    ],
    nuances: [
      "Сервис удерживает комиссию `$0.25–$1.00` за каждую отклонённую попытку оплаты.",
      "Подходит для подписки на сайте при стабильном US-маршруте.",
    ],
  },
  {
    id: "platipomiru",
    name: "Плати по миру",
    subtitle: "Карта с пополнением через СБП · тариф «Для подписок»",
    badge: "Картой на сайте",
    tier: "tier2_conditional",
    url: "https://platipomiru.com/?code=UXCAF1Z9",
    description:
      "Выпуск зарубежной карты через СБП в рублях. Для подписки на сайте подходит только тариф **«Для подписок»**.",
    warnings: [
      "Оформляйте только тариф **«Для подписок»** — обычные карты для путешествий на сайте Claude не проходят.",
      "Оплачивайте строго с подключения США и US-адресом оплаты после **96 ч** прогрева и с защитой маршрута **72 ч**.",
    ],
  },
];

export const BLACKLISTED_PROVIDERS: BlacklistedProvider[] = [
  {
    id: "antarctic-wallet",
    name: "Antarctic Wallet",
    reason: "Частые запросы паспорта и заморозка счёта из-за несовпадения страны карты и подключения.",
  },
  {
    id: "altyn-wallet",
    name: "Altyn Wallet",
    reason: "Высокий риск мгновенной проверки документов и блокировки счёта.",
  },
  {
    id: "wayment",
    name: "Wayment",
    reason: "Страна карты конфликтует с подключением и сразу вызывает проверку паспорта.",
  },
  {
    id: "epn",
    name: "e.pn",
    reason: "Блокирует пользователей из РФ при проверке документов, а карты часто отклоняются на продлении.",
  },
  {
    id: "redotpay",
    name: "RedotPay",
    reason: "Частые проверки документов и отказы при ежемесячном продлении подписки.",
  },
  {
    id: "pstnet",
    name: "PST.net",
    reason: "Высокий риск проверок и массовые отказы карт при регулярном списании за подписку.",
  },
  {
    id: "flexcard",
    name: "FlexCard",
    reason: "Массовые отказы виртуальных карт при продлении подписки.",
  },
  {
    id: "gray-marketplaces",
    name: "Plati.market / Avito / GGSel / Ozon / WB / Playerok / FunPay / случайные боты в Telegram",
    reason:
      "Нелегальные подарочные карты ведут к вечной блокировке Apple ID с потерей баланса, а передача пароля нарушает правила сервиса.",
  },
];

export const VPS_PROVIDERS: VpsProvider[] = [
  {
    id: "hostvds",
    name: "HostVDS",
    tier: "Зарубежный VPS №1 для выходного узла (NL / US / FI)",
    badge: "От $0.99/мес",
    price: "от ~$0.99 / мес",
    locations: ["NL", "US", "FI", "FR"],
    payments: ["Карты", "СБП", "Crypto"],
    specs: "1 vCPU · 1 ГБ RAM · NVMe · IPv4 + /64 IPv6",
    url: "https://hostvds.com/?affiliate_uuid=3d2b6c0c-5d99-4065-9d37-a941a46e9282",
    description:
      "Самый доступный выделенный статический IPv4 и чистая /64 подсеть IPv6 в Амстердаме, Хельсинки и США. Идеален как зарубежный узел.",
  },
  {
    id: "vultr",
    name: "Vultr",
    tier: "Облачные VPS в 32 дата-центрах мира (NL / DE / US)",
    badge: "32 локации",
    price: "от ~$5.00 / мес",
    locations: ["NL", "DE", "US", "FR", "UK"],
    payments: ["Зарубежные карты", "PayPal", "Crypto"],
    specs: "1 vCPU · 1 ГБ RAM · NVMe · IPv4 + IPv6",
    url: "https://www.vultr.com/?ref=9936768",
    description:
      "Крупный облачный провайдер с узлами в Амстердаме, Франкфурте и США. Личный выделенный IP без соседей по массовому VPN, поддержка Ubuntu 24.04 и IPv6. Оплата зарубежной картой, PayPal или Crypto.",
  },
  {
    id: "timeweb",
    name: "Timeweb Cloud",
    tier: "Облачный провайдер РФ + ЕС (идеален для входного узла Каскада)",
    badge: "Каскад РФ → ЕС",
    price: "от ~180 ₽/мес",
    locations: ["RU", "NL", "DE", "KZ"],
    payments: ["Карты РФ", "СБП", "T-Pay"],
    specs: "1 vCPU · 1 ГБ RAM · Dual-Stack IPv4/IPv6",
    url: "https://timeweb.cloud/?i=138893",
    description:
      "Лучший выбор для транзитного российского VPS (Москва / СПб) при сборке каскадного VPN (РФ → Зарубежье), а также узлов в Амстердаме и Франкфурте.",
  },
];

export type VpnSetupMethod = "amnezia" | "vless_one_cmd" | "terminal" | "cascade";
