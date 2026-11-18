import { useState } from "react";
import {
  AppHeader,
  Badge,
  Banner,
  Button,
  Card,
  Dialog,
  Field,
  Mono,
  Row,
  Rows,
  Section,
  Stat,
  Stats,
  StatusHero,
  Switch,
  Tabs,
} from "../index";
import type { MenuEntry, TabItem } from "../index";

export const GALLERY_TAB_ITEMS: TabItem[] = [
  { id: "overview", label: "Обзор" },
  { id: "connect", label: "Подключение" },
  { id: "checks", label: "Проверки" },
  { id: "backup", label: "Бэкап" },
  { id: "guides", label: "Гайды" },
];

export const GALLERY_MENU_ITEMS: MenuEntry[] = [
  { id: "sub", label: "Подписка", icon: "key", onSelect: () => {} },
  { id: "upd", label: "Проверить обновления", icon: "refresh", onSelect: () => {} },
  { id: "diag", label: "Скопировать диагностику", icon: "copy", onSelect: () => {} },
  { id: "dir", label: "Открыть папку данных", icon: "folder", onSelect: () => {} },
  { id: "dis", label: "Недоступный пункт", icon: "lock", disabled: true, onSelect: () => {} },
  { id: "s1", type: "separator" },
  { id: "quit", label: "Выйти из Заставы", icon: "power", tone: "danger", onSelect: () => {} },
];

export const galleryNoop = () => {};

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

export function ScreenOverview() {
  const [guard, setGuard] = useState(true);
  const [browsers, setBrowsers] = useState(true);
  const [editors, setEditors] = useState(true);
  return (
    <div className="zs-app">
      <AppHeader ping="41 мс" menuItems={GALLERY_MENU_ITEMS} />
      <Tabs items={GALLERY_TAB_ITEMS} value="overview" onChange={galleryNoop} idPrefix="ov" aria-label="Разделы" />
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
          <Stat layer={1} value={"5\u00a0262"} label="обычных — напрямую" />
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

export function ScreenConnect() {
  return (
    <div className="zs-app">
      <AppHeader ping="41 мс" menuItems={GALLERY_MENU_ITEMS} />
      <Tabs items={GALLERY_TAB_ITEMS} value="connect" onChange={galleryNoop} idPrefix="cn" aria-label="Разделы" />
      <Banner tone="warn" title="«Чистый IP» появится в следующем обновлении">
        Автоматическая выдача адресов ещё в разработке. Пока подключите свой VPN.
      </Banner>
      <Card title="Свой VPN за 15 минут" aside={<Badge tone="ok">Бесплатно</Badge>}>
        <p className="gl__lead" style={{ margin: "0 0 var(--space-3)" }}>
          Личный сервер с IP, которым никто больше не пользуется. Оплата картой РФ или СБП.
        </p>
        <Rows>
          <Row icon="globe" title="HostVDS" sub="Нидерланды · от 190 ₽ в месяц" onClick={galleryNoop} />
          <Row icon="globe" title="Vultr" sub="Нидерланды, IPv4 и IPv6 · от 5 $ в месяц" onClick={galleryNoop} />
          <Row icon="globe" title="Timeweb Cloud" sub="Оплата СБП и «Мир» · от 180 ₽ в месяц" onClick={galleryNoop} />
        </Rows>
        <Button variant="primary" block style={{ marginTop: "var(--space-3)" }}>Открыть инструкцию</Button>
      </Card>
      <Card title="ВПН Заставы" aside={<Badge>Скоро</Badge>}>
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

export function ScreenAlert() {
  const [log, setLog] = useState("Решение не принято");
  return (
    <div className="gl__frame">
      <Dialog
        title="Запрос к ИИ приостановлен"
        text="VPN отключился, и запрос ушёл бы с небезопасного адреса. Застава держит его, пока вы не решите."
        service="Claude"
        ip="185.220.101.5"
        country="Турция (TR)"
        previous={{ ip: "185.212.102.40", country: "Нидерланды (NL)", label: "Было" }}
        seconds={59}
        onTimeout={() => setLog("Время вышло — запрос на паузе")}
        actions={[
          { label: "Держать на паузе", onSelect: () => setLog("Выбрано 1: Держать на паузе") },
          { label: "Разрешить принудительно", variant: "danger", onSelect: () => setLog("Выбрано 2: Разрешить принудительно") },
        ]}
      />
      <p className="gl__label" role="status">Клавиши 1, 2 работают. {log}</p>
    </div>
  );
}
