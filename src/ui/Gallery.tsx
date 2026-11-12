import { useState } from "react";
import type { ReactNode } from "react";
import "../App.css";
import "./Gallery.css";
import {
  AppHeader,
  Badge,
  Banner,
  Button,
  Card,
  ConfirmModal,
  CopyBlock,
  Dialog,
  EmptyState,
  ExpandRow,
  Field,
  ICON_NAMES,
  Icon,
  Link,
  Menu,
  Modal,
  Mono,
  Progress,
  Row,
  Rows,
  Section,
  Segmented,
  Skeleton,
  Stat,
  Stats,
  StatusHero,
  Steps,
  Switch,
  TabPanel,
  Tabs,
  Toast,
  ToastViewport,
  TrustRing,
} from "./index";
import type { MenuEntry, TabItem, ToastTone } from "./index";

const TAB_ITEMS: TabItem[] = [
  { id: "overview", label: "Обзор" },
  { id: "connect", label: "Подключение" },
  { id: "checks", label: "Проверки" },
  { id: "backup", label: "Бэкап" },
  { id: "guides", label: "Гайды" },
];

const COLOR_TOKENS = [
  "bg-0", "bg-1", "bg-2", "bg-3", "line", "line-strong", "ink", "ink-2", "ink-3",
  "brand", "brand-text", "brand-soft", "on-brand", "danger", "danger-text", "danger-soft", "on-danger",
  "warn", "warn-text", "warn-soft", "on-warn", "info-text", "info-soft", "focus",
];

const MENU_ITEMS: MenuEntry[] = [
  { id: "sub", label: "Подписка", icon: "key", onSelect: () => {} },
  { id: "upd", label: "Проверить обновления", icon: "refresh", onSelect: () => {} },
  { id: "diag", label: "Скопировать диагностику", icon: "copy", onSelect: () => {} },
  { id: "dir", label: "Открыть папку данных", icon: "folder", onSelect: () => {} },
  { id: "dis", label: "Недоступный пункт", icon: "lock", disabled: true, onSelect: () => {} },
  { id: "s1", type: "separator" },
  { id: "quit", label: "Выйти из Заставы", icon: "power", tone: "danger", onSelect: () => {} },
];

function Sec({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="gl__sec">
      <h2 className="gl__h">{title}</h2>
      {children}
    </section>
  );
}

/* ---------- Три эталонных экрана ---------- */

function AiServices() {
  return (
    <Section title="Сервисы ИИ">
      <Card>
        <Rows>
          <Row icon="shield" tone="ok" title="Claude" sub="claude.ai · api.anthropic.com" trail={<Badge tone="ok">Доступен</Badge>} />
          <Row icon="shield" tone="ok" title="ChatGPT" sub="chatgpt.com · openai.com" trail={<Badge tone="ok">Доступен</Badge>} />
          <Row icon="shield" tone="ok" title="Gemini" sub="gemini.google.com · aistudio" trail={<Badge tone="ok">Доступен</Badge>} />
        </Rows>
      </Card>
    </Section>
  );
}

const noop = () => {};

function ScreenOverview() {
  const [guard, setGuard] = useState(true);
  const [browsers, setBrowsers] = useState(true);
  const [editors, setEditors] = useState(true);
  return (
    <div className="zs-app">
      <AppHeader ping="41 мс" menuItems={MENU_ITEMS} />
      <Tabs items={TAB_ITEMS} value="overview" onChange={noop} idPrefix="ov" aria-label="Разделы" />
      <StatusHero
        score={100}
        title="Вы защищены"
        ip="145.241.193.245"
        country="Великобритания"
        facts={
          <>
            <Badge tone="ok" icon="check">13 из 13 проверок</Badge>
            <Badge>Oracle Cloud</Badge>
            <Badge icon="lock">IP закреплён</Badge>
          </>
        }
      >
        <Row
          as="div"
          className="zs-hero__switch"
          title="Защита"
          sub="Запросы к ИИ идут только через чистый IP"
          trail={<Switch checked={guard} onChange={setGuard} aria-label="Защита" />}
        />
      </StatusHero>
      <AiServices />
      <Section title="Под защитой">
        <Card>
          <Rows>
            <Row icon="globe" title="Браузеры" sub="Chrome, Safari, Arc, Edge, Яндекс" trail={<Switch checked={browsers} onChange={setBrowsers} aria-label="Браузеры" />} />
            <Row icon="term" title="Редакторы кода и CLI" sub="VS Code, Cursor, Windsurf, терминал" trail={<Switch checked={editors} onChange={setEditors} aria-label="Редакторы кода и CLI" />} />
          </Rows>
        </Card>
      </Section>
      <Section title="Сегодня">
        <Stats>
          <Stat layer={1} value="970" label="запросов к ИИ проверено" />
          <Stat layer={1} value="0" label="утечек остановлено" />
          <Stat layer={1} value={"5 262"} label="обычных — напрямую" />
        </Stats>
      </Section>
      <div className="zs-app__actions">
        <Button icon="pulse">Тест обрыва VPN</Button>
        <Button variant="danger" icon="power">Остановить сеть</Button>
      </div>
      <footer className="zs-app__foot">
        <span>Работает локально · чаты не читаются</span>
        <Mono>v1.3.1</Mono>
      </footer>
    </div>
  );
}

function ScreenConnect() {
  return (
    <div className="zs-app">
      <AppHeader ping="41 мс" menuItems={MENU_ITEMS} />
      <Tabs items={TAB_ITEMS} value="connect" onChange={noop} idPrefix="cn" aria-label="Разделы" />
      <Banner tone="warn" title="«Чистый IP» появится в следующем обновлении">
        Автоматическая выдача адресов ещё в разработке. Пока подключите свой VPN.
      </Banner>
      <Card title="Свой VPN за 15 минут" aside={<Badge tone="ok">Бесплатно</Badge>}>
        <p className="gl__lead" style={{ margin: "0 0 var(--space-3)" }}>
          Личный сервер с IP, которым никто больше не пользуется. Оплата картой РФ или СБП.
        </p>
        <Rows>
          <Row icon="globe" title="HostVDS" sub="Нидерланды · от 190 ₽ в месяц" onClick={noop} />
          <Row icon="globe" title="is*hosting" sub="Нидерланды, IPv4 и IPv6 · от 5 $ в месяц" onClick={noop} />
          <Row icon="globe" title="Timeweb Cloud" sub="Оплата СБП и «Мир» · от 180 ₽ в месяц" onClick={noop} />
        </Rows>
        <Button variant="primary" block style={{ marginTop: "var(--space-3)" }}>Открыть инструкцию</Button>
      </Card>
      <Card title="Ключ Заставы" aside={<Badge>Скоро</Badge>}>
        <p className="gl__lead" style={{ margin: "0 0 var(--space-3)" }}>
          Только трафик ИИ пойдёт через выделенный IP. Банки, рабочие сайты и загрузки — напрямую, на полной скорости.
        </p>
        <Field
          label="Ключ или адрес прокси"
          placeholder="zastava://…"
          disabled
          help="Поле заработает после обновления."
          action={<Button disabled>Подключить</Button>}
        />
      </Card>
      <footer className="zs-app__foot">
        <span>Работает локально · чаты не читаются</span>
        <Mono>v1.3.1</Mono>
      </footer>
    </div>
  );
}

function ScreenAlert() {
  const [log, setLog] = useState("Решение не принято");
  return (
    <div className="gl__frame">
      <Dialog
        title="Запрос к ИИ приостановлен"
        text="VPN отключился, и запрос ушёл бы с небезопасного адреса. Застава держит его, пока вы не решите."
        service="Claude"
        ip="185.220.101.5"
        country="Турция"
        seconds={59}
        onTimeout={() => setLog("Время вышло — запрос заблокирован")}
        actions={[
          { label: "Включить VPN", icon: "zap", onSelect: () => setLog("Выбрано 1: Включить VPN") },
          { label: "Блокировать", onSelect: () => setLog("Выбрано 2: Блокировать") },
          { label: "Пропустить раз", onSelect: () => setLog("Выбрано 3: Пропустить раз") },
        ]}
      />
      <p className="gl__label" role="status">Клавиши 1, 2, 3 работают. {log}</p>
    </div>
  );
}

/* ---------- Компоненты по состояниям ---------- */

function TabsDemo() {
  const [tab, setTab] = useState("overview");
  return (
    <div className="gl__col">
      <Tabs items={TAB_ITEMS} value={tab} onChange={setTab} idPrefix="demo" aria-label="Разделы демо" />
      <TabPanel idPrefix="demo" id={tab} selected>
        <p className="gl__label">Панель: {TAB_ITEMS.find((t) => t.id === tab)?.label}. Стрелки, Home и End переключают вкладки.</p>
      </TabPanel>
    </div>
  );
}

function SwitchDemo() {
  const [a, setA] = useState(true);
  const [b, setB] = useState(false);
  return (
    <div className="gl__col">
      <Switch checked={a} onChange={setA}>{a ? "Защита включена" : "Защита выключена"}</Switch>
      <Switch checked={b} onChange={setB}>{b ? "Защита включена" : "Защита выключена"}</Switch>
      <Switch checked disabled aria-label="Включено, недоступно" />
      <Switch checked={false} disabled aria-label="Выключено, недоступно" />
    </div>
  );
}

function SegmentedDemo() {
  const [two, setTwo] = useState("auto");
  const [three, setThree] = useState("strict");
  const [four, setFour] = useState("day");
  return (
    <div className="gl__col">
      <Segmented
        aria-label="Режим из двух"
        value={two}
        onChange={setTwo}
        options={[{ value: "auto", label: "Авто" }, { value: "manual", label: "Вручную" }]}
      />
      <Segmented
        aria-label="Режим из трёх"
        value={three}
        onChange={setThree}
        options={[
          { value: "soft", label: "Мягкий" },
          { value: "strict", label: "Строгий" },
          { value: "paranoid", label: "Параноидальный режим" },
        ]}
      />
      <Segmented
        aria-label="Период"
        value={four}
        onChange={setFour}
        options={[
          { value: "hour", label: "Час" },
          { value: "day", label: "Сутки" },
          { value: "week", label: "Неделя" },
          { value: "all", label: "Всё время", disabled: true },
        ]}
      />
    </div>
  );
}

function ToastDemo() {
  const [items, setItems] = useState<Array<{ id: number; tone: ToastTone }>>([]);
  const [seq, setSeq] = useState(0);
  const add = (tone: ToastTone) => {
    setItems((v) => [...v, { id: seq, tone }]);
    setSeq((n) => n + 1);
  };
  const remove = (id: number) => setItems((v) => v.filter((i) => i.id !== id));
  return (
    <>
      <div className="gl__wrap">
        <Button size="sm" onClick={() => add("ok")}>Показать «Готово»</Button>
        <Button size="sm" onClick={() => add("danger")}>Показать «Ошибка»</Button>
      </div>
      <ToastViewport>
        {items.map((t) => (
          <Toast key={t.id} tone={t.tone} duration={5000} onClose={() => remove(t.id)} title={t.tone === "ok" ? "Настройки сохранены" : "Не удалось применить"}>
            {t.tone === "ok" ? "Изменения вступили в силу." : "Попробуйте ещё раз или откройте «Проверки»."}
          </Toast>
        ))}
      </ToastViewport>
    </>
  );
}

function ExpandRowDemo() {
  const [open, setOpen] = useState<string | null>("tz");
  const toggle = (id: string) => setOpen((cur) => (cur === id ? null : id));
  return (
    <Card>
      <Rows>
        <ExpandRow icon="check" tone="ok" title="Спам-базы" sub="Spamhaus, SORBS, Barracuda, DroneBL" trail={<Badge tone="ok">Чисто</Badge>} open={open === "dnsbl"} onToggle={() => toggle("dnsbl")} detailLabel="Спам-базы">
          <p style={{ margin: 0 }}>Адрес не найден ни в одной из четырёх баз.</p>
        </ExpandRow>
        <ExpandRow icon="alert" tone="warn" title="Часовой пояс" sub="Система: Москва. Выход: Лондон." trail={<Badge tone="warn" icon="alert">Нужна проверка</Badge>} open={open === "tz"} onToggle={() => toggle("tz")} detailLabel="Часовой пояс">
          <p style={{ margin: 0 }}>Часовой пояс компьютера не совпадает со страной IP.</p>
          <div><Button size="sm" icon="refresh">Синхронизировать</Button></div>
        </ExpandRow>
      </Rows>
    </Card>
  );
}

function CopyBlockDemo() {
  const [copied, setCopied] = useState(false);
  return (
    <Card>
      <CopyBlock label="Команда подключения по SSH" lines={["ssh root@45.142.214.88"]} copied={copied} onCopy={() => { setCopied(true); window.setTimeout(() => setCopied(false), 2500); }} />
    </Card>
  );
}

function ConfirmDemo() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant="danger" onClick={() => setOpen(true)}>Сбросить системный прокси</Button>
      <ConfirmModal open={open} title="Сбросить системный прокси?" confirmLabel="Сбросить прокси" onConfirm={() => setOpen(false)} onCancel={() => setOpen(false)}>
        Прокси браузеров вернётся к состоянию до Заставы. Действие нельзя отменить.
      </ConfirmModal>
    </>
  );
}

function ModalDemo() {
  const [open, setOpen] = useState(false);
  const [lang, setLang] = useState("ru");
  const [auto, setAuto] = useState(true);
  return (
    <>
      <Button onClick={() => setOpen(true)}>Открыть настройки</Button>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Настройки"
        footer={
          <>
            <Button variant="quiet" onClick={() => setOpen(false)}>Отмена</Button>
            <Button variant="primary" onClick={() => setOpen(false)}>Сохранить</Button>
          </>
        }
      >
        <div className="gl__col" style={{ paddingBottom: "var(--space-3)" }}>
          <Segmented
            aria-label="Язык"
            value={lang}
            onChange={setLang}
            options={[{ value: "ru", label: "Русский" }, { value: "en", label: "English" }]}
          />
          <Rows>
            <Row title="Автозапуск" sub="Открывать Заставу при входе в систему" trail={<Switch checked={auto} onChange={setAuto} aria-label="Автозапуск" />} />
            <Row title="Проверять обновления" sub="Раз в сутки, только номер версии" trail={<Switch checked={false} onChange={noop} aria-label="Проверять обновления" />} />
          </Rows>
          <Field label="Папка данных" defaultValue="/Users/me/Library/Zastava" help="Здесь лежат профили и резервные копии." />
          {Array.from({ length: 6 }, (_, i) => (
            <Banner key={i} tone="info" title={`Пояснение ${i + 1}`}>Тело окна прокручивается, а заголовок и кнопки остаются на месте.</Banner>
          ))}
        </div>
      </Modal>
    </>
  );
}

export default function Gallery() {
  return (
    <div className="zs-root">
      <main className="gl">
        <header>
          <h1 className="gl__title">Галерея примитивов «Застава»</h1>
          <p className="gl__lead">src/ui — токены, шрифты и компоненты. Страница только для dev (?gallery=1).</p>
        </header>

        <Sec title="Токены: цвет">
          <div className="gl__swatches">
            {COLOR_TOKENS.map((n) => (
              <div key={n} className="gl__sw">
                <div className={n === "bg-0" ? "gl__chip gl__chip--line" : "gl__chip"} style={{ background: `var(--${n})` }} />
                <p className="gl__label"><Mono style={{ fontSize: 12 }}>{n}</Mono></p>
              </div>
            ))}
          </div>
        </Sec>

        <Sec title="Токены: типографика">
          <div className="gl__panel gl__col">
            <span className="zs-t-title">title — Вы защищены</span>
            <span className="zs-t-heading">heading — Сервисы ИИ</span>
            <span className="zs-t-body">body — Обычные сайты идут напрямую, без задержки.</span>
            <span className="zs-t-caption">caption — Chrome, Safari, Arc, Edge, Яндекс</span>
            <span className="zs-t-overline">overline — Под защитой</span>
            <span className="zs-t-metric">metric — 5 262</span>
            <span className="zs-t-data">data — 145.241.193.245</span>
          </div>
        </Sec>

        <Sec title="Icon (19 иконок ДС → lucide)">
          <div className="gl__icons">
            {ICON_NAMES.map((n) => (
              <div key={n} className="gl__icon"><Icon name={n} />{n}</div>
            ))}
          </div>
          <div className="gl__wrap"><Icon name="shield" size={24} /><Icon name="shield" size={16} /><Icon name="shield" label="Щит" /></div>
        </Sec>

        <Sec title="Button">
          <div className="gl__wrap">
            <Button variant="primary" icon="zap">Включить VPN</Button>
            <Button>Проверить обрыв VPN</Button>
            <Button variant="quiet">Подробнее</Button>
            <Button variant="danger" icon="power">Остановить сеть</Button>
            <Button variant="danger-solid">Сбросить всё</Button>
            <Button disabled>Недоступно</Button>
            <Button size="sm">Сбросить</Button>
            <Button variant="primary" size="lg" kbd="1">Включить VPN</Button>
            <Button variant="quiet" iconOnly icon="refresh" aria-label="Обновить" />
            <Button variant="primary" disabled>Основная недоступна</Button>
          </div>
          <div className="gl__grid">
            <Button block>Кнопка на всю ширину</Button>
            <Button variant="primary" block>Открыть инструкцию</Button>
          </div>
        </Sec>

        <Sec title="Badge">
          <div className="gl__wrap">
            <Badge tone="ok" icon="check">Защищено</Badge>
            <Badge tone="ok">Доступен</Badge>
            <Badge tone="warn" icon="alert">Нужна проверка</Badge>
            <Badge tone="danger" icon="alert">Утечка</Badge>
            <Badge tone="info">Демо</Badge>
            <Badge>Выключено</Badge>
            <Badge mono>AS31898</Badge>
          </div>
        </Sec>

        <Sec title="Switch">
          <SwitchDemo />
        </Sec>

        <Sec title="Tabs">
          <TabsDemo />
        </Sec>

        <Sec title="Segmented">
          <SegmentedDemo />
        </Sec>

        <Sec title="Banner">
          <div className="gl__grid">
            <Banner tone="ok" title="Вход в Claude и ChatGPT безопасен">IP чистый, регион совпадает, утечек нет.</Banner>
            <Banner tone="warn" title="«Чистый IP» появится в следующем обновлении" action={<Link href="https://example.com" chevron>Открыть инструкцию</Link>}>
              Пока используйте свой VPN — настройка займёт 15 минут.
            </Banner>
            <Banner tone="danger" role="alert" title="Обнаружена утечка IPv6">Запросы к ИИ остановлены, пока туннель не восстановится.</Banner>
            <Banner tone="info" title="Демонстрация">В реальной ситуации шлюз остановил бы трафик до включения VPN.</Banner>
            <Banner title="Нейтральное сообщение">Без тона: справка без статуса.</Banner>
          </div>
        </Sec>

        <Sec title="Card, Row">
          <div className="gl__grid">
            <Card title="Сервисы ИИ" aside="3 доступны">
              <Rows>
                <Row icon="shield" tone="ok" title="Claude" sub="claude.ai · api.anthropic.com" trail={<Badge tone="ok">Доступен</Badge>} />
                <Row icon="alert" tone="danger" title="Gemini" sub="Нет ответа от gemini.google.com. Проверьте подключение к сети." trail={<Badge tone="danger" icon="alert">Утечка</Badge>} />
              </Rows>
            </Card>
            <Card>
              <Rows>
                <Row icon="globe" title="Браузеры" sub="Chrome, Safari, Arc, Edge, Яндекс" trail={<Switch checked onChange={noop} aria-label="Браузеры" />} />
                <Row icon="check" tone="ok" title="Спам-базы" sub="Spamhaus, SORBS, Barracuda, DroneBL" trail={<><Mono>0 из 4</Mono><Badge tone="ok">Чисто</Badge></>} />
                <Row icon="alert" tone="warn" title="Часовой пояс" sub="Система: Москва. Выход: Лондон." trail={<Button size="sm">Исправить</Button>} />
                <Row icon="folder" title="Бэкап памяти и аккаунты" onClick={noop} />
                <Row icon="key" title="Ссылка на инструкцию" sub="Откроется в браузере" href="https://example.com" />
              </Rows>
            </Card>
          </div>
        </Sec>

        <Sec title="Stat">
          <div className="gl__grid">
            <Card>
              <Stats>
                <Stat value="970" label="запросов к ИИ проверено" />
                <Stat value="0" label="утечек остановлено" />
                <Stat value={"5 262"} label="обычных — напрямую" />
              </Stats>
            </Card>
            <Card>
              <Stats>
                <Stat tone="ok" value="13" label="проверок пройдено" />
                <Stat tone="danger" value="3" label="утечки остановлены" />
                <Stat value="41 мс" label="отклик шлюза" />
              </Stats>
            </Card>
          </div>
        </Sec>

        <Sec title="StatusHero, TrustRing">
          <div className="gl__grid">
            <StatusHero
              score={100}
              title="Вы защищены"
              ip="145.241.193.245"
              country="Великобритания"
              facts={<><Badge tone="ok" icon="check">13 из 13 проверок</Badge><Badge>Oracle Cloud</Badge><Badge icon="lock">IP закреплён</Badge></>}
            />
            <StatusHero
              score={64}
              tone="warn"
              title="Нужна проверка"
              ip="145.241.193.245"
              country="Великобритания"
              facts={<Badge tone="warn" icon="alert">Часовой пояс не совпадает</Badge>}
            />
            <StatusHero
              score={42}
              tone="danger"
              title="Доступ к ИИ остановлен"
              ip="185.220.101.5"
              country="Турция"
              facts={<Badge tone="danger" icon="alert">3 проверки не пройдены</Badge>}
            />
          </div>
          <div className="gl__wrap"><TrustRing score={0} /><TrustRing score={35} /><TrustRing score={85} /><TrustRing score={100} /></div>
        </Sec>

        <Sec title="Field">
          <div className="gl__grid">
            <Field label="Ключ Заставы или свой прокси" placeholder="zastava://… или socks5://…" help="Через этот адрес пойдёт только трафик ИИ-сервисов." action={<Button variant="primary">Подключить</Button>} />
            <Field label="IP сервера" defaultValue="45.142.214" error="Адрес неполный — нужны четыре числа через точку." />
            <Field label="Недоступное поле" placeholder="zastava://…" disabled help="Поле заработает после обновления." />
          </div>
        </Sec>

        <Sec title="Steps">
          <Steps
            items={[
              { status: "done", title: "Арендуйте сервер", text: <>HostVDS · <Mono>45.142.214.88</Mono></> },
              { status: "current", title: "Настройте Amnezia VPN", text: "Выберите «Настроить свой сервер» и введите IP, логин и пароль из письма хостинга.", action: <Button variant="primary" style={{ marginTop: "var(--space-2)" }}>Скачать Amnezia</Button> },
              { status: "todo", title: "Закрепите IP в Заставе", text: "Застава запомнит адрес и остановит запросы, если он сменится." },
            ]}
          />
        </Sec>

        <Sec title="ExpandRow">
          <ExpandRowDemo />
        </Sec>

        <Sec title="Steps (collapsible)">
          <Card>
            <Steps
              collapsible
              items={[
                { title: "Подключитесь к серверу", text: "Откройте терминал и вставьте команду.", body: <CopyBlock label="Команда подключения" lines={["ssh root@45.142.214.88"]} onCopy={noop} /> },
                { title: "Установите VPN", body: <p style={{ margin: 0 }}>Запустите установку и дождитесь ключа.</p> },
                { title: "Закрепите IP в Заставе", text: "Застава запомнит адрес и остановит запросы, если он сменится.", body: <Button size="sm" icon="lock">Закрепить IP</Button> },
              ]}
            />
          </Card>
        </Sec>

        <Sec title="CopyBlock">
          <CopyBlockDemo />
        </Sec>

        <Sec title="Menu (кнопка «Ещё»: стрелки, Esc, клик вне)">
          <div className="gl__wrap" style={{ justifyContent: "space-between" }}><Menu items={MENU_ITEMS} align="start" label="Ещё слева" /><Menu items={MENU_ITEMS} /></div>
          <div style={{ minHeight: 280 }} />
        </Sec>

        <Sec title="Toast">
          <div className="gl__toasts">
            <Toast tone="ok" title="Настройки сохранены">Изменения вступили в силу.</Toast>
            <Toast tone="warn" title="Часовой пояс не совпадает" action={<Button size="sm">Исправить</Button>}>Система: Москва. Выход: Лондон.</Toast>
            <Toast tone="danger" title="Не удалось применить" onClose={noop}>Попробуйте ещё раз или откройте «Проверки».</Toast>
            <Toast tone="info" title="Доступно обновление">Версия 1.3.2 появится после перезапуска.</Toast>
          </div>
          <ToastDemo />
        </Sec>

        <Sec title="Modal, ConfirmModal">
          <div className="gl__wrap"><ModalDemo /><ConfirmDemo /></div>
        </Sec>

        <Sec title="Progress">
          <div className="gl__grid">
            <Progress label="Упаковка архива" value={0} />
            <Progress label="Упаковка архива" value={45} />
            <Progress label="Упаковка архива" value={100} />
            <Progress label="Проверяем сеть" />
            <Progress label="Осталось мало места" value={82} tone="warn" />
            <Progress label="Ошибка передачи" value={30} tone="danger" />
          </div>
        </Sec>

        <Sec title="Skeleton">
          <div className="gl__grid">
            <Card>
              <div className="gl__wrap" style={{ flexWrap: "nowrap" }}>
                <Skeleton variant="circle" width={32} />
                <div style={{ flex: 1 }}><Skeleton lines={2} /></div>
              </div>
            </Card>
            <Card><Skeleton variant="block" height={96} /></Card>
          </div>
        </Sec>

        <Sec title="EmptyState">
          <div className="gl__grid">
            <Card>
              <EmptyState icon="folder" title="Резервных копий пока нет" action={<Button variant="primary">Создать копию</Button>}>
                Копия сохранит профили и память Claude. Создайте первую — это займёт минуту.
              </EmptyState>
            </Card>
            <Card>
              <EmptyState icon="shield" title="Проверок ещё не было">Запустите проверку, и результаты появятся здесь.</EmptyState>
            </Card>
          </div>
        </Sec>

        <Sec title="AppHeader, Section">
          <div className="gl__grid">
            <div className="gl__panel"><AppHeader ping="41 мс" menuItems={MENU_ITEMS} /></div>
            <div className="gl__panel"><Section title="Сегодня"><Card><p style={{ margin: 0 }}>Содержимое раздела</p></Card></Section></div>
          </div>
        </Sec>

        <Sec title="Dialog (клавиши 1, 2, 3 включены только на эталонном экране ниже)">
          <div className="gl__grid">
            <Dialog
              hotkeys={false}
              title="Запрос к ИИ приостановлен"
              text="VPN отключился, и запрос ушёл бы с небезопасного адреса. Застава держит его, пока вы не решите."
              service="Claude"
              ip="185.220.101.5"
              country="Турция"
              demo
              seconds={30}
              actions={[
                { label: "Включить VPN", icon: "zap", onSelect: noop },
                { label: "Блокировать", onSelect: noop },
                { label: "Пропустить раз", onSelect: noop },
              ]}
            />
          </div>
        </Sec>

        <Sec title="Эталонные экраны">
          <div className="gl__screens">
            <div className="gl__shot"><p className="gl__label">Обзор</p><ScreenOverview /></div>
            <div className="gl__shot"><p className="gl__label">Подключение</p><ScreenConnect /></div>
            <div className="gl__shot"><p className="gl__label">Диалог обрыва</p><ScreenAlert /></div>
          </div>
        </Sec>
      </main>
    </div>
  );
}
