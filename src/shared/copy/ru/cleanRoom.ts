/** Строки раздела «Чистая комната» (v3.0.0): Pre-Flight детектор, браузерная песочница, 4-шаговый Launchpad и «Оплата и прогрев». */
export const cleanRoom = {
  screenTitle: "Чистая комната",
  hint: {
    id: "clean_room_intro",
    title: "Безопасный старт нового аккаунта без следов старого бана",
    body: "Сначала пройдите проверку среды (Детектор хвостов), затем создайте изолированное окно браузера и двигайтесь по 4 шагам. Если аккаунт уже создан — откройте вкладку «Оплата и прогрев».",
  },
  tabsLabel: "Режим Чистой комнаты",
  tabs: {
    launchpad: "Новый аккаунт (4 шага)",
    payment: "Оплата и прогрев",
  },
  paymentQuickNote:
    "Быстрый доступ для уже созданных аккаунтов: проверка BIN карты (IP ≈ страна карты), безналоговый адрес США (DE/OR/NH/MT/AK) и таймер прогрева 96 часов без прохождения шагов 1–3.",

  audit: {
    title: "Детектор хвостов и утечек",
    aside: "Только метаданные (read-only)",
    scanBtn: "Проверить среду",
    scanningBtn: "Проверяем…",
    gate: {
      ready: "READY · Можно запускать",
      blockedKillswitch: "БЛОК · Kill-Switch активен",
      blockedCritical: (n: number) => `БЛОК · Крит. замечаний: ${n}`,
      pending: "Ожидание проверки",
    },
    gateHint:
      "Hard Readiness Gate: запуск изолированного окна заблокирован, пока есть критические замечания или включён ручной Kill-Switch.",
    meta: {
      exitIp: "IP выхода",
      country: "Страна",
      timezone: "Таймзона выхода",
      osTz: "TZ ОС",
      tzMatch: "Совпадает",
      tzMismatch: "Не совпадает",
      ipClean: "IP чистый",
      ipTainted: "IP помечен (бан/Persona)",
      unknown: "Не определён",
    },
    taintedBannerTitle: "Текущий IP выхода помечен как скомпрометированный",
    taintedBannerText:
      "На этом IP ранее был зафиксирован бан или запрос Persona. Смените ключ Заставы или сервер VPN перед запуском нового аккаунта.",
    severity: {
      critical: "Критично",
      warning: "Внимание",
      ok: "Чисто",
    },
    fix: {
      cleanCache: (provider: string) => `Очистить кэш (${provider})`,
      syncTz: (tz: string) => `Синхронизировать TZ (${tz})`,
      switchRoute: "Сменить ключ / VPN",
      closeApp: (name: string) => `Закрыть ${name}`,
      ackIsolation: "Использовать песочницу",
      fixing: "Выполняем…",
    },
    toast: {
      cacheCleaned: "Кэш очищен",
      cacheCleanEmpty: "Следы не найдены — каталог уже чист.",
      cacheLocked: (targets: string[]) => `Закройте приложение вручную, заблокированы: ${targets.join(", ")}`,
      tzSynced: "Часовой пояс ОС синхронизирован",
      tzSyncedText: (tz: string) => `Установлен пояс ${tz} с авто-восстановлением при выходе.`,
      closeAppHint: (name: string) => `Закройте «${name}» и нажмите «Проверить среду» снова.`,
      isolationAck: "Выбрана браузерная песочница",
      isolationAckText: "Личный браузер останется нетронутым; работайте в изолированном окне Заставы.",
      error: "Не удалось выполнить действие",
    },
    tips: {
      readiness: {
        title: "Hard Readiness Gate",
        text: "Защита от случайного запуска нового аккаунта поверх старых cookies, tainted IP или активного Kill-Switch.",
      },
      tainted: {
        title: "Скомпрометированный IP (tainted)",
        text: "Адрес, на котором ранее фиксировался бан или запрос Persona. Повторная регистрация на том же IP резко повышает риск цепной блокировки.",
      },
      osTz: {
        title: "Часовой пояс ОС и песочница",
        text: "На macOS песочница получает TZ выхода автоматически через переменную среды. На Windows Chromium читает часовой пояс из ОС, поэтому нужна синхронизация.",
      },
    },
    emptyTitle: "Запустите проверку среды",
    emptyText: "Детектор проверит следы прошлых банов, утечки DNS/IPv6/STUN, часовой пояс и чистоту IP без чтения паролей и cookies.",
  },

  sandbox: {
    title: "Браузерная песочница (для веба)",
    subtitle: "Изолированное окно Chromium — отдельно от профилей Claude Desktop и CLI.",
    tipTitle: "Веб-песочница vs Claude Desktop",
    tipText:
      "Здесь создаются изолированные окна браузера (Chrome / Edge / Brave) для регистрации и веб-версий Claude / ChatGPT / Gemini. Профили локального Claude Desktop и CLI настраиваются отдельно в «Аккаунты, Бункер и SOS».",
    createBtn: "Создать профиль",
    cancelBtn: "Отмена",
    noBrowsers: {
      title: "Поддерживаемые браузеры не найдены",
      text: "Для изолированной песочницы нужен Google Chrome, Microsoft Edge или Brave. Установите один из них с официального сайта и обновите список.",
      refresh: "Проверить снова",
      downloads: [
        { id: "chrome", label: "Скачать Chrome", url: "https://www.google.com/chrome/" },
        { id: "edge", label: "Скачать Edge", url: "https://www.microsoft.com/edge" },
        { id: "brave", label: "Скачать Brave", url: "https://brave.com/download/" },
      ],
    },
    emptyProfiles: {
      title: "Нет профилей песочницы",
      text: "Создайте чистый профиль и привяжите к нему отдельный ключ/маршрут, чтобы личный браузер и другие аккаунты не пересекались.",
      cta: "Создать профиль",
    },
    form: {
      title: "Новый профиль песочницы",
      labelField: "Название профиля",
      labelPlaceholder: "Claude · Работа US",
      providerField: "Сервис ИИ",
      browserField: "Движок браузера",
      routeField: "Привязка маршрута",
      routeTipTitle: "Ключ Заставы vs Direct (Свой VPN)",
      routeTipText:
        "Привязанный ключ направляет весь трафик окна (включая Stripe и Persona) через свой выделенный порт-алиас. В режиме Direct окно пойдёт через системный VPN/интернет.",
      directOption: "Direct — через свой VPN / системную сеть",
      directWarning:
        "В режиме Direct все окна используют общий системный выход. Для параллельной работы с несколькими аккаунтами привяжите отдельный ключ.",
      submit: "Создать и выбрать",
      creating: "Создаём…",
    },
    providers: {
      anthropic: "Claude (Anthropic)",
      openai: "ChatGPT (OpenAI)",
      gemini: "Gemini (Google)",
      custom: "Другой сервис",
    },
    status: {
      active: "Активен",
      warming_up: "Прогрев",
      ready: "Готов",
      tainted: "Скомпрометирован",
    },
    profileCard: {
      selected: "Выбран",
      select: "Выбрать",
      routeDirect: "Direct (свой VPN)",
      routeMissing: "Маршрут удалён",
      lastIp: "Последний выход:",
      neverOpened: "Ещё не запускался",
      launchBtn: "Открыть песочницу",
      launching: "Запуск…",
      blockedReasonKillswitch: "Запуск заблокирован: включён ручной Kill-Switch.",
      blockedReasonAudit: "Запуск заблокирован: устраните критические замечания в «Детекторе хвостов».",
      blockedReasonTainted: "Профиль скомпрометирован — создайте новый чистый профиль.",
      taintBtn: "Отметить как скомпрометированный",
      deleteBtn: "Удалить",
      deleteTitle: "Удалить профиль песочницы?",
      deleteText: (label: string) =>
        `Профиль «${label}» и его изолированный каталог браузера будут удалены с диска без возможности восстановления.`,
      deleteConfirm: "Удалить профиль",
    },
    toast: {
      created: "Профиль создан",
      launched: "Песочница запущена",
      launchedText: (engine: string, port: number) => `${engine} запущен через изолированный алиас :${port}.`,
      tainted: "Профиль и IP помечены",
      taintedText: "Выходной IP добавлен в чёрный список Чистой комнаты.",
      deleted: "Профиль удалён",
      error: "Ошибка профиля песочницы",
    },
  },

  launchpad: {
    title: "Launchpad нового аккаунта (4 шага)",
    activeProfile: (label: string) => `Активный профиль: ${label}`,
    noProfileNote: "Выберите или создайте профиль выше, чтобы сохранять прогресс шагов и чеклиста.",
    stepLabels: [
      { step: 1, short: "1. Чистая среда" },
      { step: 2, short: "2. Регистрация" },
      { step: 3, short: "3. Прогрев 96ч" },
      { step: 4, short: "4. Оплата" },
    ],
    step1: {
      title: "Шаг 1: Чистая среда, профиль и маршрут",
      text: "Убедитесь, что Детектор хвостов горит зелёным (READY), а профиль песочницы привязан к чистому маршруту.",
      checkAuditOk: "Детектор хвостов: готов к запуску (READY)",
      checkAuditFail: "Детектор хвостов: есть блокирующие замечания",
      checkProfileOk: (label: string) => `Профиль выбран: ${label}`,
      checkProfileFail: "Профиль песочницы ещё не создан",
      checkRouteOk: "Выделенный маршрут привязан",
      checkRouteDirect: "Используется Direct (свой VPN) — проверьте уникальность IP",
      nextBtn: "Перейти к шагу 2: Регистрация",
    },
    step2: {
      title: "Шаг 2: Регистрация в изолированном окне",
      text: "Откройте целевой сервис прямо в изолированной песочнице. Не используйте личный браузер, где уже были баны.",
      launchBtn: "Открыть песочницу на регистрации",
      customUrlLabel: "Адрес регистрации",
      customUrlPlaceholder: "https://claude.ai",
      checklistTitle: "Чеклист гигиены регистрации",
      checklist: [
        {
          id: "clean_email",
          title: "Только зарубежная почта",
          detail: "Используйте gmail.com, proton.me, icloud.com или личный домен. Домены .ru / .by (mail.ru, yandex.ru) резко повышают риск флага.",
        },
        {
          id: "physical_sim",
          title: "Физическая SIM или eSIM для SMS",
          detail: "Не используйте дешёвые одноразовые VoIP/SMS-активаторы — номера из их пулов массово помечены и ведут к мгновенной проверке Persona.",
        },
        {
          id: "isolated_window",
          title: "Вход только в окне песочницы",
          detail: "Не открывайте новый аккаунт в личном Chrome/Safari и не смешивайте его cookies с другими учётными записями.",
        },
      ],
      nextBtn: "Перейти к шагу 3: Прогрев 96ч",
    },
    step3: {
      title: "Шаг 3: Прогрев аккаунта (96 часов)",
      text: "Дайте новому аккаунту естественную историю на Free tier с одного стабильного IP перед привязкой карты.",
      disclaimer:
        "96 часов — это дисциплинарный буфер, снижающий эвристический риск, а не гарантия нулевого KYC/Persona. Главные причины банов — грязный общий IP (смена ASN/страны) и проблемный биллинг/перекупщик.",
      checklistTitle: "Активность во время прогрева",
      checklist: [
        {
          id: "warmup_free_chats",
          title: "Естественные диалоги на Free tier",
          detail: "Не запускайте массовую автоматизацию и API-парсинг в первые сутки после регистрации.",
        },
        {
          id: "warmup_single_ip",
          title: "Один и тот же маршрут без скачков страны",
          detail: "Оставайтесь на привязанном ключе/IP на всём протяжении прогрева.",
        },
      ],
      nextBtn: "Перейти к шагу 4: Шлюз оплаты",
    },
    step4: {
      title: "Шаг 4: Шлюз оплаты и проверка BIN",
      text: "Перед вводом карты проверьте совпадение страны BIN и выходного IP, а для карт США используйте безналоговый адрес Stripe AVS.",
      resellerWarningTitle: "Категорически не покупайте подписки у перекупщиков",
      resellerWarningText:
        "Серые продавцы на Playerok, FunPay, Telegram-ботах «подписка за полцены» и чужие Apple Pay / Google Pay аккаунты — главная причина волн банов и вечных запросов Persona без возврата средств.",
      openGuideBtn: "Открыть полный гайд по оплате",
    },
  },
} as const;
