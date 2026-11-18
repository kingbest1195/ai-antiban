import type { ReactNode } from "react";
import "../App.css";
import "./Gallery.css";
import {
  AppHeader,
  Badge,
  Banner,
  Button,
  Card,
  CopyBlock,
  Dialog,
  EmptyState,
  Field,
  ICON_NAMES,
  Icon,
  Link,
  Menu,
  Mono,
  Progress,
  Row,
  Rows,
  Section,
  Skeleton,
  Stat,
  Stats,
  StatusHero,
  Steps,
  Switch,
  Toast,
  TrustRing,
} from "./index";
import {
  ConfirmDemo,
  CopyBlockDemo,
  ExpandRowDemo,
  ModalDemo,
  SegmentedDemo,
  SwitchDemo,
  TabsDemo,
  ToastDemo,
} from "./gallery/GalleryDemos";
import {
  GALLERY_MENU_ITEMS,
  ScreenAlert,
  ScreenConnect,
  ScreenOverview,
  galleryNoop,
} from "./gallery/GalleryScreens";

const COLOR_TOKENS = [
  "bg-0", "bg-1", "bg-2", "bg-3", "line", "line-strong", "ink", "ink-2", "ink-3",
  "brand", "brand-text", "brand-soft", "on-brand", "danger", "danger-text", "danger-soft", "on-danger",
  "warn", "warn-text", "warn-soft", "on-warn", "info-text", "info-soft", "focus",
];

function Sec({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="gl__sec">
      <h2 className="gl__h">{title}</h2>
      {children}
    </section>
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

        <Sec title="Switch"><SwitchDemo /></Sec>
        <Sec title="Tabs"><TabsDemo /></Sec>
        <Sec title="Segmented"><SegmentedDemo /></Sec>

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
                <Row icon="globe" title="Браузеры" sub="Chrome, Safari, Arc, Edge, Яндекс" trail={<Switch checked onChange={galleryNoop} aria-label="Браузеры" />} />
                <Row icon="check" tone="ok" title="Спам-базы" sub="Spamhaus, SORBS, Barracuda, DroneBL" trail={<><Mono>0 из 4</Mono><Badge tone="ok">Чисто</Badge></>} />
                <Row icon="alert" tone="warn" title="Часовой пояс" sub="Система: Москва. Выход: Лондон." trail={<Button size="sm">Исправить</Button>} />
                <Row icon="folder" title="Бэкап памяти и аккаунты" onClick={galleryNoop} />
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
                <Stat value={"5\u00a0262"} label="обычных — напрямую" />
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
            <Field label="ВПН Заставы или свой прокси" placeholder="zastava://… или socks5://…" help="Через этот адрес пойдёт только трафик ИИ-сервисов." action={<Button variant="primary">Подключить</Button>} />
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

        <Sec title="ExpandRow"><ExpandRowDemo /></Sec>

        <Sec title="Steps (collapsible)">
          <Card>
            <Steps
              collapsible
              items={[
                { title: "Подключитесь к серверу", text: "Откройте терминал и вставьте команду.", body: <CopyBlock label="Команда подключения" lines={["ssh root@45.142.214.88"]} onCopy={galleryNoop} /> },
                { title: "Установите VPN", body: <p style={{ margin: 0 }}>Запустите установку и дождитесь ключа.</p> },
                { title: "Закрепите IP в Заставе", text: "Застава запомнит адрес и остановит запросы, если он сменится.", body: <Button size="sm" icon="lock">Закрепить IP</Button> },
              ]}
            />
          </Card>
        </Sec>

        <Sec title="CopyBlock"><CopyBlockDemo /></Sec>

        <Sec title="Menu (кнопка «Ещё»: стрелки, Esc, клик вне)">
          <div className="gl__wrap" style={{ justifyContent: "space-between" }}><Menu items={GALLERY_MENU_ITEMS} align="start" label="Ещё слева" /><Menu items={GALLERY_MENU_ITEMS} /></div>
          <div style={{ minHeight: 280 }} />
        </Sec>

        <Sec title="Toast">
          <div className="gl__toasts">
            <Toast tone="ok" title="Настройки сохранены">Изменения вступили в силу.</Toast>
            <Toast tone="warn" title="Часовой пояс не совпадает" action={<Button size="sm">Исправить</Button>}>Система: Москва. Выход: Лондон.</Toast>
            <Toast tone="danger" title="Не удалось применить" onClose={galleryNoop}>Попробуйте ещё раз или откройте «Проверки».</Toast>
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
            <div className="gl__panel"><AppHeader ping="41 мс" menuItems={GALLERY_MENU_ITEMS} /></div>
            <div className="gl__panel"><Section title="Сегодня"><Card><p style={{ margin: 0 }}>Содержимое раздела</p></Card></Section></div>
          </div>
        </Sec>

        <Sec title="Dialog (клавиши 1, 2 включены только на эталонном экране ниже)">
          <div className="gl__grid">
            <Dialog
              hotkeys={false}
              title="Запрос к ИИ приостановлен"
              text="VPN отключился, и запрос ушёл бы с небезопасного адреса. Застава держит его, пока вы не решите."
              service="Claude"
              ip="185.220.101.5"
              country="Турция (TR)"
              previous={{ ip: "185.212.102.40", country: "Нидерланды (NL)", label: "Было" }}
              demo
              seconds={30}
              actions={[
                { label: "Держать на паузе", onSelect: galleryNoop },
                { label: "Разрешить принудительно", variant: "danger", onSelect: galleryNoop },
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
