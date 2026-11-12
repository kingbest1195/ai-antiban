#!/usr/bin/env node
// CI guard: direct TrayIcon access must live only in src-tauri/src/tray/ (main-thread entry point).
// Usage: node scripts/check-tray-main-thread.mjs        (scan repo)
//        node scripts/check-tray-main-thread.mjs --self-test
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const PATTERN = /tray_by_id|\.set_icon\(|\.set_title\(|\.set_tooltip\(/;

export function findViolations(files) {
  // files: [{ path (posix, relative to src-tauri/src), text }]
  const out = [];
  for (const { path, text } of files) {
    if (path.startsWith("tray/")) continue;
    text.split("\n").forEach((line, i) => {
      if (PATTERN.test(line)) out.push(`${path}:${i + 1}: ${line.trim()}`);
    });
  }
  return out;
}

function walk(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, acc);
    else if (name.endsWith(".rs")) acc.push(p);
  }
  return acc;
}

function selfTest() {
  const bad = findViolations([{ path: "commands/x.rs", text: "let t = app.tray_by_id(\"a\");\nt.set_icon(None);" }]);
  const good = findViolations([
    { path: "tray/mod.rs", text: "app.tray_by_id(ID); t.set_tooltip(x);" },
    { path: "commands/y.rs", text: "crate::tray::update_tray_status(&app, \"red\", None);" },
  ]);
  if (bad.length !== 2) throw new Error(`negative fixture must yield 2 violations, got ${bad.length}`);
  if (good.length !== 0) throw new Error(`positive fixture must be clean, got ${good.length}`);
  console.log("self-test ok");
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "src-tauri", "src");
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--self-test")) {
    try { selfTest(); } catch (e) { console.error(e.message); process.exit(1); }
  }
  if (process.argv.includes("--fixture-bad")) {
    // Demonstrates a red result on a negative fixture.
    const v = findViolations([{ path: "commands/x.rs", text: "app.tray_by_id(\"a\")" }]);
    console.error("violations:\n" + v.join("\n"));
    process.exit(v.length ? 1 : 0);
  }
  const files = walk(root).map((p) => ({ path: relative(root, p).split(sep).join("/"), text: readFileSync(p, "utf8") }));
  const v = findViolations(files);
  if (v.length) {
    console.error("Tray access outside src/tray/ (use crate::tray::update_* / with_tray_on_main):\n" + v.join("\n"));
    process.exit(1);
  }
  console.log("tray main-thread guard ok");
}
