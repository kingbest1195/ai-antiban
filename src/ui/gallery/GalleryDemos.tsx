import { useState } from "react";
import {
  Badge,
  Banner,
  Button,
  Card,
  ConfirmModal,
  CopyBlock,
  ExpandRow,
  Field,
  Modal,
  Row,
  Rows,
  Segmented,
  Switch,
  TabPanel,
  Tabs,
  Toast,
  ToastViewport,
} from "../index";
import type { ToastTone } from "../index";
import { GALLERY_TAB_ITEMS, galleryNoop } from "./GalleryScreens";

export function TabsDemo() {
  const [tab, setTab] = useState("overview");
  return (
    <div className="gl__col">
      <Tabs items={GALLERY_TAB_ITEMS} value={tab} onChange={setTab} idPrefix="demo" aria-label="Разделы демо" />
      <TabPanel idPrefix="demo" id={tab} selected>
        <p className="gl__label">Панель: {GALLERY_TAB_ITEMS.find((t) => t.id === tab)?.label}. Стрелки, Home и End переключают вкладки.</p>
      </TabPanel>
    </div>
  );
}

export function SwitchDemo() {
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

export function SegmentedDemo() {
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

export function ToastDemo() {
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

export function ExpandRowDemo() {
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

export function CopyBlockDemo() {
  const [copied, setCopied] = useState(false);
  return (
    <Card>
      <CopyBlock label="Команда подключения по SSH" lines={["ssh root@45.142.214.88"]} copied={copied} onCopy={() => { setCopied(true); window.setTimeout(() => setCopied(false), 2500); }} />
    </Card>
  );
}

export function ConfirmDemo() {
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

export function ModalDemo() {
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
            <Row title="Проверять обновления" sub="Раз в сутки, только номер версии" trail={<Switch checked={false} onChange={galleryNoop} aria-label="Проверять обновления" />} />
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
