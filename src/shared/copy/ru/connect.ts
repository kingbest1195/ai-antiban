/** Промо-параметры ключа Заставы. */
export const PROMO_COPY = {
  keyPriceLabel: "769 ₽/мес · 1 949 ₽ за 3 мес",
  keyIssuanceTime: "Ключ выдаётся за 1 минуту",
  keyBenefits: [
    "Чистый резидентский/выделенный IP с высоким доверием",
    "Только трафик ИИ — банки и российские сайты идут напрямую",
    "Готовый ключ zastava:// без настройки сервера",
  ],
  salesServerBenefits: [
    "Полный контроль над собственным VPS",
    "Оплата картой РФ или СБП от 180–190 ₽/мес",
    "Пошаговая инструкция занимает 15 минут",
  ],
} as const;

/** Экран «Подключение»: свой VPN, ключ Заставы, маршруты. */
export const connect = {
  vpn: {
    title: "Свой сервер (VPS) за 15 минут",
    text: "Личный сервер с IP, которым никто больше не пользуется. Оплата картой РФ или СБП.",
    open: "Открыть инструкцию",
    hostings: {
      hostvds: "Нидерланды · от 190 ₽ в месяц",
      vultr: "Нидерланды, Германия, США · от 5 $ в месяц",
      timeweb: "Оплата СБП и «Мир» · от 180 ₽ в месяц",
    },
  },
  key: {
    title: "ВПН Заставы",
    text: "Только трафик ИИ пойдёт через выделенный IP. Банки, рабочие сайты и загрузки — напрямую, на полной скорости.",
    fieldLabel: "Ключ или адрес прокси",
    placeholder: "zastava://… или host:port:user:pass",
    caption:
      "Поддерживаются zastava://, socks5://host:port:user:pass, host:port:user:pass, user:pass@host:port, https://, http://.",
    invalidKeyFormat:
      "Неверный формат ключа или порт. Пример: zastava://… или host:port:user:pass",
    scopeLabel: "Куда применить ключ",
    scopeOptions: {
      all: "Все профили / По умолчанию",
      save_only: "Только сохранить для привязки",
    },
    connect: "Добавить ключ",
    connecting: "Подключаем…",
    get: "Получить ВПН",
    renew: "Продлить",
    refreshSub: "Обновить статус",
    refreshingSub: "Обновляем…",
    graceExtendedBadge: "Активен на сервере",
    graceExtendedHint:
      "Ключ продлён на сервере и работает. При необходимости получите свежий ключ для точной даты.",
    expiringSoon: (remaining: string) => `Истекает (${remaining})`,
    empty: "Введите ключ или адрес прокси.",
    defaultLabel: "Выделенный шлюз Заставы",
    switchLabel: "Маршрут активен",
    switchOn: "Маршрут включён",
    switchOff: "Маршрут отключён",
    exit: "Выходной адрес",
    exitUnknown: "Определяем адрес…",
    disconnect: "Отключить ключ",
    addedTitle: "Сохранённые маршруты",
    test: "Проверить",
    testing: "Проверяем…",
    remove: "Удалить",
    makeDefault: "Сделать основным",
    defaultBadge: "По умолчанию",
    profileBadge: "Профиль Claude",
    expires: (date: string) => `Действует до ${date}`,
    expired: "Срок действия истёк",
    unreachable: "Недоступен",
    ipMismatch: "IP не совпадает",
    latency: (ms: number) => `${ms} мс`,
    toast: {
      connected: "Ключ добавлен",
      connectedText: "Маршрут установлен по умолчанию для всех провайдеров без отдельной привязки.",
      savedOnlyText: "Маршрут сохранён. Привяжите его к профилю Claude или сервису ниже.",
      connectError: "Не удалось подключить ключ",
      on: "Маршрут включён",
      onText: "Трафик снова может идти через этот маршрут.",
      off: "Маршрут отключён",
      offText: "Маршрут временно отключён.",
      toggleError: "Не удалось переключить маршрут",
      disconnected: "Маршрут удалён",
      disconnectedText: "Настройки шлюза очищены, маршрут удалён.",
      disconnectError: "Не удалось удалить маршрут",
      testSuccess: "Маршрут доступен",
      testSuccessText: (ip: string, latency?: number | null) =>
        `Выходной IP: ${ip}${latency !== undefined && latency !== null ? ` (${latency} мс)` : ""}`,
      graceExtendedText: (ip: string, latency?: number | null) =>
        `Ключ активен на сервере, блокировка снята. Выходной IP: ${ip}${latency !== undefined && latency !== null ? ` (${latency} мс)` : ""}`,
      testError: "Ошибка проверки маршрута",
      refreshSubSuccess: "Срок действия обновлён",
      refreshSubSuccessText: (date?: string | null) =>
        date ? `Ключ действителен до ${date}.` : "Метаданные подписки обновлены.",
      refreshSubError: "Не удалось обновить статус подписки",
    },
  },
  routes: {
    title: "Маршруты по сервисам",
    text: "Выберите, через какой маршрут отправлять запросы каждого сервиса ИИ.",
    direct: "Через текущий VPN",
    default: "Ключ по умолчанию",
    services: {
      anthropic: "Claude (Anthropic)",
      openai: "ChatGPT (OpenAI)",
      gemini: "Google Gemini",
    },
    danglingTitle: "Маршрут недоступен",
    danglingText: "Привязанный к сервису ключ был удалён. Сервис удерживается шлюзом для безопасности.",
    profileErrorTitle: "Ошибка ключа профиля Claude",
    profileErrorText: "Ключ активного профиля Claude не прошёл проверку. Запросы удерживаются.",
    blockedCountryTitle: (service: string, country: string) =>
      `Страна ${country} заблокирована в ${service}`,
    blockedCountryText:
      "Выбранный маршрут или VPN выходит в неподдерживаемом регионе — переключите сервис на другой ключ или страну VPN.",
    resetToDirect: "Сбросить на текущий VPN",
    switchToDirect: "Переключиться на ваш VPN",
    openConnect: "Открыть подключение",
    bannerTitle: (provider: string) => `Маршрут для ${provider.toUpperCase()} недоступен`,
    disableModal: {
      title: (label: string) => `Отключить маршрут «${label}»?`,
      text: (targets: string) =>
        `Сейчас через этот маршрут работают: ${targets}. Если просто остановить маршрут, запросы к ИИ будут заблокированы до включения защиты.`,
      profileNote:
        "Маршрут также привязан к активному профилю Claude. Для перехода на ваш VPN потребуется отдельное подтверждение защиты от смешивания аккаунтов.",
      switchToDirect: "Отключить и перейти на ваш VPN",
      stopAndBlock: "Остановить маршрут",
      stopAndBlockHint: "ИИ-сервисы будут заблокированы без маршрута",
      cancel: "Отмена",
      busy: "Применяем…",
      toastDirectTitle: "Переключено на ваш VPN",
      toastDirectText: "Маршрут отключён, привязки переведены на текущее подключение устройства.",
    },
    profileResetModal: {
      title: "Сбросить ключ профиля Claude на свой VPN?",
      text: "Этот маршрут привязан к активному профилю Claude. При переходе на ваш VPN запросы Claude пойдут через общий IP устройства. Убедитесь, что не смешиваете разные аккаунты на одном IP, чтобы не спровоцировать цепочку блокировок.",
      confirm: "Сбросить на свой VPN",
      cancel: "Оставить ключ профиля",
      busy: "Сбрасываем…",
    },
    toast: {
      boundSuccess: "Маршрут привязан",
      boundSuccessText: (service: string) => `Для сервиса ${service} обновлён рабочий маршрут.`,
      boundError: "Не удалось изменить привязку",
      resetSuccess: "Привязка сброшена",
      resetSuccessText: "Сервис переключён на текущий VPN.",
    },
  },
} as const;
