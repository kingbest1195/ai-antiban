// Данные хостингов и сервисов карт. Перенесены из прежнего GuideViewer без изменений:
// названия, цены и ссылки (с партнёрскими параметрами) менять нельзя.

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

export interface VirtualCardProvider {
  id: string;
  name: string;
  badge: string;
  tier: string;
  url: string;
  description: string;
}

export const VIRTUAL_CARD_PROVIDERS: VirtualCardProvider[] = [
  {
    id: "platipomiru",
    name: "Плати по миру",
    badge: "КАРТА №1 · СБП",
    tier: "Виртуальные карты Visa / Mastercard с пополнением в рублях",
    url: "https://platipomiru.com/?code=UXCAF1Z9",
    description:
      "Быстрый выпуск зарубежных карт для оплаты подписок Claude Pro, ChatGPT Plus, Cursor и зарубежных VPS через СБП.",
  },
  {
    id: "wanttopay",
    name: "WantToPay",
    badge: "TELEGRAM-БОТ №2",
    tier: "Выпуск карт в Telegram за 2 минуты (3D Secure)",
    url: "https://telegram.me/WantToPayBot?start=w17851188--ERIEX",
    description:
      "Удобный бот для выпуска виртуальных карт US / EU / HK с поддержкой 3D Secure. Проверяйте первые цифры карты в разделе «Чистая комната → Оплата и прогрев».",
  },
  {
    id: "epn",
    name: "e.pn",
    badge: "STRIPE PRO №3",
    tier: "Трастовые банковские BIN США и Европы с AVS",
    url: "https://e.pn?a=nomadnocode",
    description:
      "Десятки проверенных банковских BIN США и ЕС с поддержкой проверки адреса (AVS) и максимальной проходимостью в Stripe.",
  },
];

export const VPS_PROVIDERS: VpsProvider[] = [
  {
    id: "hostvds",
    name: "HostVDS",
    tier: "Зарубежный VPS №1 для выходного узла (NL / US / FI)",
    badge: "ОТ $0.99/МЕС",
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
    badge: "32 ЛОКАЦИИ",
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
    badge: "КАСКАД РФ → ЕС",
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
