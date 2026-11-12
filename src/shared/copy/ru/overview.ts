export const providers = {
  anthropic: { name: "Claude", domains: "claude.ai · api.anthropic.com" },
  openai: { name: "ChatGPT", domains: "chatgpt.com · openai.com" },
  gemini: { name: "Gemini", domains: "gemini.google.com · aistudio" },
} as const;

export const overview = {
  sectionServices: "Сервисы ИИ",
  sectionProtected: "Под защитой",
  sectionToday: "Сегодня",
  verdict: {
    ok: "Вы защищены",
    attention: "Есть замечания",
    stopped: "Доступ к ИИ остановлен",
    frozen: "Сеть ИИ остановлена",
    off: "Защита выключена",
    partial: "Проверено частично",
  },
  facts: {
    checks: (passed: number, total: number, word: string) => `${passed} из ${total} ${word}`,
    /** Часть проверок не выполнена: «9 из 13 · 3 не удалось проверить». */
    checksPartial: (passed: number, total: number, unknown: number) =>
      `${passed} из ${total} · ${unknown} не удалось проверить`,
    pinned: "IP закреплён",
    pinChanged: "IP сменился",
    key: "Ключ Заставы",
  },
  guard: {
    title: "Защита",
    onText: "Запросы к ИИ идут только через чистый IP",
    offText: "Запросы к ИИ идут напрямую, без защиты",
    label: "Защита",
  },
  ipMenu: {
    label: "Действия с IP",
    copy: "Скопировать IP",
    pin: "Закрепить IP",
    unpin: "Открепить IP",
    strictOn: "Включить строгий режим",
    strictOff: "Выключить строгий режим",
  },
  service: {
    session: "Блок снят на эту сессию",
    review: "Подробности — в «Проверках»",
    blocked: "Запросы удерживаются шлюзом",
    unblock: "Снять блок",
    allow: "Разрешить на сессию",
    missing: "Данных пока нет",
    checking: "Проверяем",
  },
  browsers: { title: "Браузеры", sub: "Chrome, Safari, Arc, Edge, Яндекс" },
  desktopApps: { title: "Десктопные приложения", sub: "Claude Desktop, ChatGPT Desktop" },
  editors: { title: "IDE и терминал", sub: "Antigravity, Cursor, VS Code, Windsurf, Claude Code, Gemini CLI" },
  stats: {
    requests: "запросов к ИИ проверено",
    leaks: "утечек остановлено",
    direct: "обычных — напрямую",
  },
  events: {
    open: "Открыть ленту событий",
    title: "Лента событий шлюза",
    tunnels: (n: number) => `Активных туннелей ИИ: ${n}`,
    last: "Последний запрос",
    waiting: "Ждём первых запросов к Claude, ChatGPT и Gemini.",
    close: "Закрыть",
  },
  actions: {
    crashTest: "Тест обрыва VPN",
    stopNetwork: "Остановить сеть",
    resumeNetwork: "Возобновить сеть",
  },
  banner: {
    openChecks: "Открыть проверки",
    stopped: {
      title: "Запросы к ИИ удерживаются",
      text: "Найден небезопасный адрес или утечка. Подробности — во вкладке «Проверки».",
    },
    frozen: {
      title: "Сеть ИИ остановлена",
      text: "Все запросы к Claude, ChatGPT и Gemini заморожены, пока вы не возобновите сеть.",
    },
    leak: {
      title: "Возможна утечка адреса",
      text: "Часть трафика может идти мимо защиты. Подробности — во вкладке «Проверки».",
    },
    timezone: {
      title: "Часовой пояс не совпадает со страной IP",
      text: "Это повышает риск дополнительных проверок у ИИ-сервисов.",
      action: "Настроить часовой пояс",
    },
    review: {
      title: "У адреса есть замечания",
      text: "ИИ-сервис может запросить дополнительную проверку. Подробности — во вкладке «Проверки».",
    },
    incomplete: {
      title: "Проверено частично",
      text: "Часть проверок не удалось выполнить. Это не значит, что всё хорошо: повторите проверку.",
      action: "Повторить проверку",
    },
    update: {
      title: (version: string) => `Доступно обновление v${version}`,
      text: "Новая версия Заставы готова к установке.",
      action: "Что нового",
    },
  },
  error: {
    title: "Нет связи с сетью",
    text: "Не удалось проверить соединение. Проверьте интернет и VPN, затем повторите.",
    action: "Перепроверить",
  },
} as const;
