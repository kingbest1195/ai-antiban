import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { cpSync, mkdtempSync, rmSync, unlinkSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyDir } from './verify-release.mjs';

const REPO = 'o/r';
const b64 = (b) => Buffer.from(b).toString('base64');

function makeKey(id = Buffer.from('0102030405060708', 'hex')) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  const pub = b64(`untrusted comment: minisign public key\n${b64(Buffer.concat([Buffer.from('Ed'), id, raw]))}\n`);
  return { privateKey, id, pub };
}

/** minisign-подпись в формате Tauri (base64 всего файла), prehashed=ED. */
function minisign(k, data) {
  const sig = sign(null, createHash('blake2b512').update(data).digest(), k.privateKey);
  const trusted = 'timestamp:1\tfile:x';
  const gsig = sign(null, Buffer.concat([sig, Buffer.from(trusted)]), k.privateKey);
  const text = `untrusted comment: signature\n${b64(Buffer.concat([Buffer.from('ED'), k.id, sig]))}\ntrusted comment: ${trusted}\n${b64(gsig)}\n`;
  return b64(text);
}

function makeRelease(k, v = '2.1.0', tag = 'v2.1.0') {
  const dir = mkdtempSync(join(tmpdir(), 'vr-'));
  const assets = [`Zastava_${v}_universal.dmg`, 'Zastava_universal.app.tar.gz', `Zastava_${v}_x64-setup.exe`, `Zastava_${v}_x64_en-US.msi`];
  const sigs = {};
  for (const a of assets) {
    const data = Buffer.from(`data-of-${a}`);
    writeFileSync(join(dir, a), data);
    if (!a.endsWith('.dmg')) { sigs[a] = minisign(k, data); writeFileSync(join(dir, `${a}.sig`), sigs[a]); }
  }
  const base = `https://github.com/${REPO}/releases/download/${tag}/`;
  const p = (a) => ({ url: base + a, signature: sigs[a] });
  const app = p('Zastava_universal.app.tar.gz'), msi = p(`Zastava_${v}_x64_en-US.msi`), nsis = p(`Zastava_${v}_x64-setup.exe`);
  writeFileSync(join(dir, 'latest.json'), JSON.stringify({
    version: v, notes: 'notes', pub_date: '2026-01-01T00:00:00Z',
    platforms: { 'darwin-aarch64': app, 'darwin-x86_64': app, 'windows-x86_64': msi, 'windows-x86_64-msi': msi, 'windows-x86_64-nsis': nsis },
  }));
  return dir;
}

const run = (dir, k, extra = {}) => verifyDir({ dir, repo: REPO, tag: 'v2.1.0', pubkeyB64: k.pub, ...extra });
const failed = (r) => r.results.filter((x) => !x.ok).map((x) => x.name).join(' | ');

test('валидный релиз — зелёный', async () => {
  const k = makeKey(); const d = makeRelease(k);
  const r = await run(d, k); assert.equal(r.ok, true, failed(r)); rmSync(d, { recursive: true });
});

test('запасной вариант версии: тег v2.1.0-rc.1, версия 2.1.0-1 через параметр', async () => {
  const k = makeKey(); const d = makeRelease(k, '2.1.0-1', 'v2.1.0-rc.1');
  const strict = await verifyDir({ dir: d, repo: REPO, tag: 'v2.1.0-rc.1', pubkeyB64: k.pub });
  assert.equal(strict.ok, false);
  const r = await verifyDir({ dir: d, repo: REPO, tag: 'v2.1.0-rc.1', pubkeyB64: k.pub, versions: ['2.1.0-rc.1', '2.1.0-1'] });
  assert.equal(r.ok, true, failed(r)); rmSync(d, { recursive: true });
});

test('негатив 1: удалён .sig', async () => {
  const k = makeKey(); const d = makeRelease(k); unlinkSync(join(d, 'Zastava_2.1.0_x64-setup.exe.sig'));
  const r = await run(d, k); assert.equal(r.ok, false); assert.match(failed(r), /отсутствуют|\.sig/); rmSync(d, { recursive: true });
});

test('негатив 2: подменён version в latest.json', async () => {
  const k = makeKey(); const d = makeRelease(k);
  const lj = JSON.parse(readFileSync(join(d, 'latest.json'), 'utf8')); lj.version = '2.0.0';
  writeFileSync(join(d, 'latest.json'), JSON.stringify(lj));
  const r = await run(d, k); assert.equal(r.ok, false); assert.match(failed(r), /latest\.version/); rmSync(d, { recursive: true });
});

test('негатив 3: лишний .exe', async () => {
  const k = makeKey(); const d = makeRelease(k); writeFileSync(join(d, 'Zastava_extra.exe'), 'x');
  const r = await run(d, k); assert.equal(r.ok, false); assert.match(failed(r), /посторонние|1\.3\.x/); rmSync(d, { recursive: true });
});

test('негатив 4: пустой signature в latest.json', async () => {
  const k = makeKey(); const d = makeRelease(k);
  const lj = JSON.parse(readFileSync(join(d, 'latest.json'), 'utf8')); lj.platforms['darwin-aarch64'].signature = '';
  writeFileSync(join(d, 'latest.json'), JSON.stringify(lj));
  const r = await run(d, k); assert.equal(r.ok, false); assert.match(failed(r), /darwin-aarch64: signature/); rmSync(d, { recursive: true });
});

test('негатив 5a: подпись другим ключом (pubkey не соответствует)', async () => {
  const k = makeKey(); const other = makeKey(); const d = makeRelease(k);
  const r = await run(d, other); assert.equal(r.ok, false); assert.match(failed(r), /minisign/); rmSync(d, { recursive: true });
});

test('негатив 5b: тот же key id, но испорчено содержимое ассета', async () => {
  const k = makeKey(); const d = makeRelease(k); writeFileSync(join(d, 'Zastava_universal.app.tar.gz'), 'tampered');
  const r = await run(d, k); assert.equal(r.ok, false); assert.match(failed(r), /minisign Zastava_universal\.app\.tar\.gz/); rmSync(d, { recursive: true });
});

test('негатив: url ведёт на ассет вне релиза / не тот тег', async () => {
  const k = makeKey(); const d = makeRelease(k);
  const lj = JSON.parse(readFileSync(join(d, 'latest.json'), 'utf8'));
  lj.platforms['windows-x86_64'].url = lj.platforms['windows-x86_64'].url.replace('v2.1.0', 'v9.9.9');
  writeFileSync(join(d, 'latest.json'), JSON.stringify(lj));
  const r = await run(d, k); assert.equal(r.ok, false); assert.match(failed(r), /windows-x86_64: url/); rmSync(d, { recursive: true });
});
