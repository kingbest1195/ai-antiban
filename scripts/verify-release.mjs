#!/usr/bin/env node
// Проверка ассетов релиза Zastava перед публикацией: набор файлов, latest.json,
// minisign-подписи (Ed25519, на node:crypto — без внешних зависимостей).
//
// Использование:
//   node scripts/verify-release.mjs --repo OWNER/REPO --tag v2.1.0 [--dl-dir DIR] [--version 2.1.0[,2.1.0-1]] [--head]
//   node scripts/verify-release.mjs --dir ./assets --repo OWNER/REPO --tag v2.1.0     (без gh, каталог уже скачан)
// --version: допустимые значения version (через запятую); по умолчанию — тег без «v».
//            Нужен для запасного варианта, когда версия в конфиге отличается от тега
//            (например MSI не принимает pre-release «rc.1»: тег v2.1.0-rc.1, версия 2.1.0-1).
// --head:    дополнительно делать HEAD по url из latest.json (для опубликованных релизов;
//            у черновика ассеты по публичному url недоступны, поэтому в CI не используется).
// --pubkey:  base64-pubkey (по умолчанию plugins.updater.pubkey из src-tauri/tauri.conf.json).
// Скачанные файлы — недоверенные данные: скрипт только читает их как байты и JSON.
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const REQUIRED_PLATFORMS = ['darwin-aarch64', 'darwin-x86_64', 'windows-x86_64'];
const OPTIONAL_PLATFORMS = [
  'darwin-aarch64-app', 'darwin-x86_64-app', 'windows-x86_64-nsis', 'windows-x86_64-msi',
];

// ---------- minisign ----------
function b64(s) { return Buffer.from(s.trim(), 'base64'); }

/** Текст minisign-файла: допускаем и «сырой» текст, и base64 от всего файла (формат Tauri). */
function minisignText(content) {
  const t = content.toString('utf8').trim();
  if (t.startsWith('untrusted comment:')) return t;
  return b64(t).toString('utf8').trim();
}

export function parsePubkey(pubkeyB64) {
  const lines = minisignText(Buffer.from(pubkeyB64)).split(/\r?\n/);
  if (lines.length < 2) throw new Error('pubkey: ожидалось 2 строки minisign');
  const raw = b64(lines[1]);
  if (raw.length !== 42 || raw.subarray(0, 2).toString() !== 'Ed') throw new Error('pubkey: неверный формат (ожидалось Ed + keyid + 32 байта)');
  return { keyId: raw.subarray(2, 10), key: raw.subarray(10) };
}

export function parseSignature(sigContent) {
  const lines = minisignText(Buffer.from(sigContent)).split(/\r?\n/);
  if (lines.length < 4) throw new Error('sig: ожидалось 4 строки minisign');
  const raw = b64(lines[1]);
  if (raw.length !== 74) throw new Error('sig: неверная длина подписи');
  const prefix = 'trusted comment: ';
  if (!lines[2].startsWith(prefix)) throw new Error('sig: нет trusted comment');
  return {
    alg: raw.subarray(0, 2).toString(), keyId: raw.subarray(2, 10), sig: raw.subarray(10),
    trusted: Buffer.from(lines[2].slice(prefix.length)), globalSig: b64(lines[3]),
  };
}

function edCheck(pk, data, sig) {
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, pk.key]), format: 'der', type: 'spki' });
  return edVerify(null, data, key, sig);
}

/** Возвращает null, если подпись верна, иначе строку с причиной. */
export function verifyMinisign(pubkeyB64, sigContent, data) {
  let pk, s;
  try { pk = parsePubkey(pubkeyB64); s = parseSignature(sigContent); } catch (e) { return e.message; }
  if (!pk.keyId.equals(s.keyId)) return 'key id подписи не совпадает с pubkey';
  let msg;
  if (s.alg === 'Ed') msg = data;
  else if (s.alg === 'ED') msg = createHash('blake2b512').update(data).digest();
  else return `неизвестный алгоритм подписи ${s.alg}`;
  if (!edCheck(pk, msg, s.sig)) return 'подпись файла неверна';
  if (!edCheck(pk, Buffer.concat([s.sig, s.trusted]), s.globalSig)) return 'глобальная подпись (trusted comment) неверна';
  return null;
}

// ---------- проверка набора ----------
export async function verifyDir({ dir, repo, tag, versions, pubkeyB64, head = false, fetchImpl = fetch }) {
  const res = [];
  const ok = (name, detail = '') => res.push({ ok: true, name, detail });
  const bad = (name, detail) => res.push({ ok: false, name, detail });
  const accepted = versions && versions.length ? versions : [tag.replace(/^v/, '')];

  const files = readdirSync(dir).sort();
  const dmg = files.find((f) => /^Zastava_.+_universal\.dmg$/.test(f));
  const fileVersion = dmg ? dmg.match(/^Zastava_(.+)_universal\.dmg$/)[1] : null;
  if (!fileVersion) bad('имена ассетов', 'нет Zastava_<v>_universal.dmg');
  else if (!accepted.includes(fileVersion)) bad('версия в именах', `${fileVersion} не из допустимых ${accepted.join(', ')}`);

  const expected = fileVersion ? [
    'latest.json', `Zastava_${fileVersion}_universal.dmg`,
    'Zastava_universal.app.tar.gz', 'Zastava_universal.app.tar.gz.sig',
    `Zastava_${fileVersion}_x64-setup.exe`, `Zastava_${fileVersion}_x64-setup.exe.sig`,
    `Zastava_${fileVersion}_x64_en-US.msi`, `Zastava_${fileVersion}_x64_en-US.msi.sig`,
  ].sort() : [];
  const missing = expected.filter((f) => !files.includes(f));
  const extra = files.filter((f) => !expected.includes(f));
  if (fileVersion) {
    if (missing.length) bad('обязательные файлы', `отсутствуют: ${missing.join(', ')}`);
    if (extra.length) bad('посторонние файлы', `лишние: ${extra.join(', ')}`);
    if (!missing.length && !extra.length) ok('набор ассетов', `ровно ${expected.length} файлов`);
  }
  const extraBinaries = files.filter((f) => /\.(exe|msi)$|\.app\.tar\.gz$/.test(f) && !expected.includes(f));
  if (extraBinaries.length) bad('клиенты 1.3.x берут первый подходящий ассет', `лишние: ${extraBinaries.join(', ')}`);

  // latest.json
  let lj = null;
  if (files.includes('latest.json')) {
    try { lj = JSON.parse(readFileSync(join(dir, 'latest.json'), 'utf8')); } catch (e) { bad('latest.json', `не JSON: ${e.message}`); }
  }
  if (lj) {
    if (accepted.includes(lj.version)) ok('latest.version', lj.version); else bad('latest.version', `${JSON.stringify(lj.version)} не из допустимых ${accepted.join(', ')}`);
    if (fileVersion && lj.version !== fileVersion) bad('latest.version vs имена файлов', `${lj.version} != ${fileVersion}`);
    if (typeof lj.pub_date === 'string' && RFC3339.test(lj.pub_date) && !Number.isNaN(Date.parse(lj.pub_date))) ok('pub_date', lj.pub_date); else bad('pub_date', `не RFC3339: ${JSON.stringify(lj.pub_date)}`);
    if (typeof lj.notes === 'string' && lj.notes.trim()) ok('notes', `${lj.notes.length} симв.`); else bad('notes', 'пусто');
    const platforms = lj.platforms && typeof lj.platforms === 'object' ? lj.platforms : {};
    for (const p of REQUIRED_PLATFORMS) if (!platforms[p]) bad(`platform ${p}`, 'отсутствует');
    const prefix = `https://github.com/${repo}/releases/download/${tag}/`;
    for (const [name, p] of Object.entries(platforms)) {
      if (!REQUIRED_PLATFORMS.includes(name) && !OPTIONAL_PLATFORMS.includes(name)) { bad(`platform ${name}`, 'неизвестный ключ платформы'); continue; }
      const sigInJson = typeof p.signature === 'string' ? p.signature.trim() : '';
      if (!sigInJson) { bad(`${name}: signature`, 'пусто'); continue; }
      const url = String(p.url || '');
      if (!url.startsWith(prefix)) { bad(`${name}: url`, `не ${prefix}…: ${url}`); continue; }
      const asset = decodeURIComponent(url.slice(prefix.length));
      const kindOk = name.startsWith('darwin') ? asset === 'Zastava_universal.app.tar.gz'
        : name.endsWith('-nsis') ? asset.endsWith('_x64-setup.exe')
        : name.endsWith('-msi') ? asset.endsWith('_x64_en-US.msi')
        : /_x64-setup\.exe$|_x64_en-US\.msi$/.test(asset);
      if (!kindOk) { bad(`${name}: url`, `неожиданный тип ассета ${asset}`); continue; }
      if (!files.includes(asset)) { bad(`${name}: url`, `ассета ${asset} нет в релизе`); continue; }
      if (!files.includes(`${asset}.sig`)) { bad(`${name}: .sig`, `нет ${asset}.sig`); continue; }
      const sigFile = readFileSync(join(dir, `${asset}.sig`), 'utf8').trim();
      if (sigFile !== sigInJson) { bad(`${name}: signature`, `не совпадает с ${asset}.sig`); continue; }
      ok(`${name}: url+signature`, asset);
      if (head) {
        try {
          const r = await fetchImpl(url, { method: 'HEAD', redirect: 'follow' });
          if (r.status === 200) ok(`${name}: HEAD`, '200'); else bad(`${name}: HEAD`, `статус ${r.status}`);
        } catch (e) { bad(`${name}: HEAD`, e.message); }
      }
    }
  }

  // криптопроверка каждого ассета с .sig
  for (const f of files.filter((x) => x.endsWith('.sig'))) {
    const target = f.slice(0, -4);
    if (!files.includes(target)) { bad(`minisign ${f}`, 'нет файла, к которому относится .sig'); continue; }
    const why = verifyMinisign(pubkeyB64, readFileSync(join(dir, f)), readFileSync(join(dir, target)));
    if (why) bad(`minisign ${target}`, why); else ok(`minisign ${target}`, 'подпись верна');
  }
  return { ok: res.every((r) => r.ok), results: res };
}

// ---------- CLI ----------
function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === '--head') a.head = true;
    else if (k.startsWith('--')) a[k.slice(2)] = argv[++i];
    else throw new Error(`неизвестный аргумент ${k}`);
  }
  return a;
}

async function main() {
  const a = parseArgs(process.argv.slice(2));
  if (!a.repo || !a.tag) { console.error('нужны --repo и --tag'); process.exit(2); }
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const pubkeyB64 = a.pubkey || JSON.parse(readFileSync(join(root, 'src-tauri/tauri.conf.json'), 'utf8')).plugins.updater.pubkey;
  let dir = a.dir;
  if (!dir) {
    dir = a['dl-dir'] || mkdtempSync(join(tmpdir(), 'zastava-verify-'));
    mkdirSync(dir, { recursive: true });
    if (readdirSync(dir).length) { console.error(`каталог ${dir} не пуст`); process.exit(2); }
    execFileSync('gh', ['release', 'download', a.tag, '--repo', a.repo, '--dir', dir], { stdio: 'inherit' });
  } else if (!existsSync(dir)) { console.error(`нет каталога ${dir}`); process.exit(2); }
  const versions = a.version ? a.version.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
  const { ok, results } = await verifyDir({ dir, repo: a.repo, tag: a.tag, versions, pubkeyB64, head: !!a.head });
  for (const r of results) console.log(`${r.ok ? 'OK  ' : 'FAIL'} ${r.name}${r.detail ? ' — ' + r.detail : ''}`);
  console.log(ok ? `\nVERIFY: ЗЕЛЁНЫЙ (${basename(dir)})` : '\nVERIFY: КРАСНЫЙ');
  process.exit(ok ? 0 : 1);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error(e.message); process.exit(2); });
}
