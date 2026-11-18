#!/usr/bin/env node
// Architecture & Constitution guard (see CONSTITUTION.md).
// Scope: Desktop app only (src-tauri/src/, src-tauri/tests/, src/). Does NOT enforce on site/.
//
// Usage:
//   node scripts/check-architecture.mjs             (scan repo)
//   node scripts/check-architecture.mjs --self-test (run unit self-tests + scan repo)

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const BUDGETS = {
  PROD_SOFT_LIMIT: 350,
  PROD_HARD_LIMIT: 500,
  TEST_HARD_LIMIT: 700,
  INLINE_TEST_TOTAL_LIMIT: 400,
};

/**
 * Legacy allowlist cleared in Wave 7 — zero exemptions remain.
 * Kept as an empty structure so `analyzeArchitecture` signature stays compatible.
 */
export const LEGACY_ALLOWLIST = {
  // Rust production lines (> 500L) in src-tauri/src/
  rustProd: {},

  // Rust test / fakes lines (> 700L), keyed by path relative to src-tauri/src/ or "tests/<name>"
  rustTest: {},

  // Rust files with inline `#[cfg(test)] mod ... { ... }` where total lines > 400
  rustInlineOver400: {},

  // Rust production files that still contain inline `Fake*` / `mod fakes` definitions
  inlineFakes: new Set(),

  // Layer 0-2 Rust files with legacy upward imports (commands/app/tray/popup/startup/update_tray_*)
  // or Layer-2 bidirectional sysproxy <-> proxy::coverage imports (max line matches per file)
  forbiddenRustImports: {},

  // Frontend production files (> 500L) relative to repo root
  frontendProd: {},

  // Frontend files outside src/utils/api/ calling `invoke(` (max call-site matches per file)
  frontendInvoke: {},
};

const FRONTEND_EXTS = new Set([".ts", ".tsx", ".css"]);

export function countLines(text) {
  if (!text) return 0;
  const lines = text.split("\n");
  return lines[lines.length - 1] === "" ? lines.length - 1 : lines.length;
}

export function isDedicatedRustTest(relPath) {
  return (
    relPath === "tests.rs" ||
    relPath.endsWith("/tests.rs") ||
    relPath.endsWith("_tests.rs") ||
    relPath.includes("/tests/")
  );
}

export function isRustFakesFile(relPath) {
  return relPath === "fakes.rs" || relPath.endsWith("/fakes.rs") || relPath.includes("/fakes/");
}

/**
 * Splits a Rust source file into production lines and test lines at the first
 * `#[cfg(test)] mod <name>` boundary (skipping individual `#[cfg(test)] fn ...` helpers
 * earlier in the file). External `#[cfg(test)] mod tests;` declarations without a `{`
 * inline test block do not mark `hasInlineTestMod = true`.
 */
export function splitRustFile(relPath, text) {
  const lines = text.split("\n");
  const totalLines = lines.length > 0 && lines[lines.length - 1] === "" ? lines.length - 1 : lines.length;

  if (isDedicatedRustTest(relPath)) {
    return { totalLines, prodLines: 0, testLines: totalLines, prodEndIdx: 0, hasInlineTestMod: false };
  }
  if (isRustFakesFile(relPath)) {
    return { totalLines, prodLines: 0, testLines: totalLines, prodEndIdx: 0, hasInlineTestMod: false };
  }

  let splitIdx = -1;
  for (let i = 0; i < totalLines; i++) {
    const trimmed = lines[i].trim();
    if (/^#\[cfg\(test\)\]\s*(?:pub(?:\([^)]+\))?\s+)?mod\s+\w+/.test(trimmed)) {
      splitIdx = i;
      break;
    }
    if (/^#\[cfg\(test\)\]$/.test(trimmed)) {
      for (let j = i + 1; j < Math.min(totalLines, i + 5); j++) {
        const next = lines[j].trim();
        if (next === "" || next.startsWith("//") || next.startsWith("#[")) continue;
        if (/^(?:pub(?:\([^)]+\))?\s+)?mod\s+\w+/.test(next)) {
          splitIdx = i;
        }
        break;
      }
      if (splitIdx !== -1) break;
    }
  }

  if (splitIdx === -1) {
    return { totalLines, prodLines: totalLines, testLines: 0, prodEndIdx: totalLines, hasInlineTestMod: false };
  }

  let hasInlineTestMod = false;
  for (let i = splitIdx; i < totalLines; i++) {
    const trimmed = lines[i].trim();
    if (/^(?:#\[cfg\(test\)\]\s*)?(?:pub(?:\([^)]+\))?\s+)?mod\s+\w+\s*\{/.test(trimmed)) {
      hasInlineTestMod = true;
      break;
    }
  }

  return {
    totalLines,
    prodLines: splitIdx,
    testLines: totalLines - splitIdx,
    prodEndIdx: splitIdx,
    hasInlineTestMod,
  };
}

export function getRustLayer(relPath) {
  if (
    relPath === "main.rs" ||
    relPath === "lib.rs" ||
    relPath === "app.rs" ||
    relPath.startsWith("app/") ||
    relPath.startsWith("commands/") ||
    relPath.startsWith("tray/") ||
    relPath === "popup.rs" ||
    relPath.startsWith("popup/") ||
    relPath === "startup.rs" ||
    relPath.startsWith("startup/") ||
    relPath === "autostart.rs" ||
    relPath.startsWith("autostart/")
  ) {
    return 3;
  }
  if (relPath.startsWith("core/") || relPath === "sanctions.rs") {
    return 0;
  }
  if (relPath.startsWith("state/") || relPath.startsWith("routing/")) {
    return 1;
  }
  return 2;
}

function stripLineComment(line) {
  const idx = line.indexOf("//");
  return idx === -1 ? line : line.slice(0, idx);
}

/**
 * Pure analyzer over in-memory file records so both CLI runs and `--self-test`
 * exercise the exact same enforcement logic.
 */
export function analyzeArchitecture({ rustSrcFiles, rustIntegrationFiles, frontendFiles }, allowlist = LEGACY_ALLOWLIST) {
  const violations = [];
  const softLimitWarnings = [];

  const checkBudget = (kind, key, actual, hardLimit, capMap) => {
    if (actual <= hardLimit) return;
    const cap = capMap?.[key];
    if (cap === undefined) {
      violations.push(`[${kind}] ${key}: ${actual} lines exceeds hard limit ${hardLimit}`);
    } else if (actual > cap) {
      violations.push(`[${kind}] ${key}: ${actual} lines grew beyond legacy allowlist cap ${cap}`);
    }
  };

  // Build lookup map of rustSrcFiles for parent module gating checks of `fakes.rs`
  const rustMap = new Map(rustSrcFiles.map((f) => [f.path, f.text]));

  for (const { path: relPath, text } of rustSrcFiles) {
    const split = splitRustFile(relPath, text);
    const lines = text.split("\n");
    const layer = getRustLayer(relPath);

    // 1. Line budgets
    if (split.prodLines > BUDGETS.PROD_SOFT_LIMIT && split.prodLines <= BUDGETS.PROD_HARD_LIMIT) {
      softLimitWarnings.push(`src-tauri/src/${relPath}: ${split.prodLines} prod lines (soft limit ${BUDGETS.PROD_SOFT_LIMIT})`);
    }
    checkBudget("rust-prod-limit", `src-tauri/src/${relPath}`, split.prodLines, BUDGETS.PROD_HARD_LIMIT, prefixKeys(allowlist.rustProd, "src-tauri/src/"));
    checkBudget("rust-test-limit", `src-tauri/src/${relPath}`, split.testLines, BUDGETS.TEST_HARD_LIMIT, prefixKeys(allowlist.rustTest, "src-tauri/src/"));

    if (split.hasInlineTestMod && split.totalLines > BUDGETS.INLINE_TEST_TOTAL_LIMIT) {
      checkBudget(
        "rust-inline-test-split",
        `src-tauri/src/${relPath}`,
        split.totalLines,
        BUDGETS.INLINE_TEST_TOTAL_LIMIT,
        prefixKeys(allowlist.rustInlineOver400, "src-tauri/src/"),
      );
    }

    // 2. Test doubles isolation
    if (!isRustFakesFile(relPath) && !isDedicatedRustTest(relPath)) {
      const fakeDefs = [];
      for (let i = 0; i < split.prodEndIdx; i++) {
        const clean = stripLineComment(lines[i]);
        if (/^\s*(?:pub(?:\([^)]+\))?\s+)?(?:struct|enum|mod)\s+(Fake\w+|fakes\b)/.test(clean)) {
          fakeDefs.push(`${i + 1}: ${clean.trim()}`);
        }
      }
      if (fakeDefs.length > 0 && !allowlist.inlineFakes.has(relPath)) {
        violations.push(
          `[fakes-in-prod] src-tauri/src/${relPath}: test doubles must live in fakes.rs (${fakeDefs[0]})`,
        );
      }
    } else if (isRustFakesFile(relPath)) {
      const hasSelfGate = /#\[!?cfg\(any\(test,\s*feature\s*=\s*"test-support"\)\)\]|#\[!?cfg\(test\)\]/.test(text);
      const parentPath = relPath.endsWith("/fakes.rs")
        ? relPath.replace(/\/fakes\.rs$/, "/mod.rs")
        : relPath === "fakes.rs"
          ? "lib.rs"
          : null;
      const parentText = parentPath ? rustMap.get(parentPath) ?? "" : "";
      const hasParentGate = /#\[cfg\(any\(test,\s*feature\s*=\s*"test-support"\)\)\]\s*(?:pub(?:\([^)]+\))?\s+)?mod\s+fakes\b/.test(parentText);
      if (!hasSelfGate && !hasParentGate) {
        violations.push(
          `[fakes-gate] src-tauri/src/${relPath}: fakes.rs must be gated by #[cfg(any(test, feature = "test-support"))]`,
        );
      }
    }

    // 3. Acyclic 4-layer dependency rules (scan prod code only)
    if (!isDedicatedRustTest(relPath) && !isRustFakesFile(relPath)) {
      const forbiddenHits = [];
      for (let i = 0; i < split.prodEndIdx; i++) {
        const clean = stripLineComment(lines[i]);
        if (layer === 0) {
          if (/\btauri::/.test(clean) || /\bcrate::(commands|app|tray|popup|startup|autostart|proxy|auditor|sysproxy|updater|cowork_guard|os_tz|diagnostics|bin_checker|win_reg|state|routing)\b/.test(clean)) {
            forbiddenHits.push(`${i + 1}: ${clean.trim()}`);
          }
        } else if (layer <= 2) {
          if (/\bcrate::(commands|app|tray|popup|startup|update_tray_\w+)\b/.test(clean)) {
            forbiddenHits.push(`${i + 1}: ${clean.trim()}`);
          }
          if (relPath.startsWith("sysproxy/") && /\bcrate::proxy::coverage\b/.test(clean)) {
            forbiddenHits.push(`${i + 1}: ${clean.trim()}`);
          }
        }
      }

      if (forbiddenHits.length > 0) {
        const cap = allowlist.forbiddenRustImports[relPath];
        if (layer === 0) {
          violations.push(`[layer0-purity] src-tauri/src/${relPath}: Layer 0 must not depend on Tauri or higher layers (${forbiddenHits[0]})`);
        } else if (cap === undefined) {
          violations.push(`[layer-violation] src-tauri/src/${relPath}: forbidden upward/bidirectional import (${forbiddenHits[0]})`);
        } else if (forbiddenHits.length > cap) {
          violations.push(
            `[layer-violation] src-tauri/src/${relPath}: ${forbiddenHits.length} forbidden imports exceed legacy cap ${cap} (e.g. ${forbiddenHits[0]})`,
          );
        }
      }
    }
  }

  // 4. Integration tests in src-tauri/tests/
  for (const { path: relPath, text } of rustIntegrationFiles) {
    const linesCount = countLines(text);
    checkBudget("rust-integration-test-limit", `src-tauri/${relPath}`, linesCount, BUDGETS.TEST_HARD_LIMIT, prefixKeys(allowlist.rustTest, "src-tauri/"));
  }

  // 5. Frontend files in src/
  for (const { path: relPath, text } of frontendFiles) {
    const linesCount = countLines(text);
    const isTest = /\.test\.[jt]sx?$|\.spec\.[jt]sx?$/.test(relPath);
    if (isTest) {
      checkBudget("frontend-test-limit", relPath, linesCount, BUDGETS.TEST_HARD_LIMIT, null);
    } else {
      if (linesCount > BUDGETS.PROD_SOFT_LIMIT && linesCount <= BUDGETS.PROD_HARD_LIMIT) {
        softLimitWarnings.push(`${relPath}: ${linesCount} lines (soft limit ${BUDGETS.PROD_SOFT_LIMIT})`);
      }
      checkBudget("frontend-prod-limit", relPath, linesCount, BUDGETS.PROD_HARD_LIMIT, allowlist.frontendProd);
    }

    // `invoke(` isolation: only allowed inside src/utils/api/ (and legacy barrel src/utils/api.ts)
    if ((relPath.endsWith(".ts") || relPath.endsWith(".tsx")) && relPath !== "src/utils/api.ts" && !relPath.startsWith("src/utils/api/")) {
      const invokeLines = [];
      text.split("\n").forEach((line, idx) => {
        const clean = stripLineComment(line);
        if (/\binvoke\s*[<(]/.test(clean)) {
          invokeLines.push(`${idx + 1}: ${clean.trim()}`);
        }
      });
      if (invokeLines.length > 0) {
        const cap = allowlist.frontendInvoke[relPath];
        if (cap === undefined) {
          violations.push(`[frontend-invoke] ${relPath}: invoke() only allowed in src/utils/api/ (${invokeLines[0]})`);
        } else if (invokeLines.length > cap) {
          violations.push(`[frontend-invoke] ${relPath}: ${invokeLines.length} invoke() calls exceed legacy cap ${cap}`);
        }
      }
    }
  }

  return {
    violations,
    softLimitWarnings,
    counts: {
      rustSrc: rustSrcFiles.length,
      rustIntegration: rustIntegrationFiles.length,
      frontend: frontendFiles.length,
    },
  };
}

function prefixKeys(obj, prefix) {
  if (!obj) return {};
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[`${prefix}${k}`] = v;
  return out;
}

function walkFiles(dir, exts, acc = []) {
  if (!existsSync(dir)) return acc;
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) walkFiles(full, exts, acc);
    else if (exts.has(extname(full))) acc.push(full);
  }
  return acc;
}

function toPosix(base, full) {
  return relative(base, full).split(sep).join("/");
}

function selfTest() {
  const emptyAllowlist = {
    rustProd: {},
    rustTest: {},
    rustInlineOver400: {},
    inlineFakes: new Set(),
    forbiddenRustImports: {},
    frontendProd: {},
    frontendInvoke: {},
  };

  // 1. Rust split skips #[cfg(test)] helper fn before #[cfg(test)] mod tests {
  const sampleWithHelper = [
    ...Array(10).fill("fn prod() {}"),
    "#[cfg(test)]",
    "fn helper_for_tests() {}",
    ...Array(10).fill("fn more_prod() {}"),
    "#[cfg(test)]",
    "mod tests {",
    ...Array(20).fill("    fn t() {}"),
    "}",
  ].join("\n");
  const split = splitRustFile("proxy/sample.rs", sampleWithHelper);
  if (split.prodLines !== 22 || split.testLines !== 23 || !split.hasInlineTestMod) {
    throw new Error(`unexpected splitRustFile result: ${JSON.stringify(split)}`);
  }

  // 2. External `#[cfg(test)] mod tests;` does NOT trigger inline-test > 400L violation
  const externalMod = [
    ...Array(420).fill("fn prod() {}"),
    "#[cfg(test)]",
    "mod tests;",
  ].join("\n");
  const resExt = analyzeArchitecture(
    {
      rustSrcFiles: [{ path: "proxy/ok.rs", text: externalMod }],
      rustIntegrationFiles: [],
      frontendFiles: [],
    },
    emptyAllowlist,
  );
  if (resExt.violations.length !== 0) {
    throw new Error(`external mod tests; should pass: ${resExt.violations.join("; ")}`);
  }

  // 3. Rejects new >500L prod, >700L test, >400L inline test, Fake* in prod, upward import, Layer 0 leak, frontend invoke
  const badRes = analyzeArchitecture(
    {
      rustSrcFiles: [
        { path: "proxy/big.rs", text: Array(501).fill("fn x() {}").join("\n") },
        { path: "proxy/inline_big.rs", text: [...Array(250).fill("fn x() {}"), "#[cfg(test)]", "mod tests {", ...Array(155).fill("  fn t() {}"), "}"].join("\n") },
        { path: "proxy/bad_fake.rs", text: "pub struct FakeClock;" },
        { path: "proxy/upward.rs", text: "use crate::commands::audit::foo;" },
        { path: "core/bad.rs", text: "use crate::proxy::server;" },
        { path: "proxy/tests.rs", text: Array(701).fill("#[test] fn t() {}").join("\n") },
      ],
      rustIntegrationFiles: [],
      frontendFiles: [
        { path: "src/features/a/Bad.tsx", text: "import { invoke } from '@tauri-apps/api/core';\ninvoke('ping');" },
        { path: "src/utils/api/client.ts", text: "import { invoke } from '@tauri-apps/api/core';\nexport const ping = () => invoke('ping');" },
        { path: "src/features/a/Big.tsx", text: Array(501).fill("export const a = 1;").join("\n") },
        { path: "src/features/a/Big.test.ts", text: Array(701).fill("it('x', () => {});").join("\n") },
      ],
    },
    emptyAllowlist,
  );
  if (badRes.violations.length !== 9) {
    throw new Error(`expected 9 negative fixture violations, got ${badRes.violations.length}: ${badRes.violations.join(" | ")}`);
  }

  // 4. Allowlist blocks growth beyond cap (+1 line fails)
  const capRes = analyzeArchitecture(
    {
      rustSrcFiles: [{ path: "proxy/big.rs", text: Array(502).fill("fn x() {}").join("\n") }],
      rustIntegrationFiles: [],
      frontendFiles: [],
    },
    { ...emptyAllowlist, rustProd: { "proxy/big.rs": 501 } },
  );
  if (capRes.violations.length !== 1) {
    throw new Error(`expected allowlist cap growth failure, got ${capRes.violations.length}`);
  }

  console.log("self-test ok");
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--self-test")) {
    try {
      selfTest();
    } catch (err) {
      console.error("architecture check self-test failed:", err.message);
      process.exit(1);
    }
  }

  const rustSrcRoot = join(repoRoot, "src-tauri", "src");
  const rustTestsRoot = join(repoRoot, "src-tauri", "tests");
  const frontendRoot = join(repoRoot, "src");

  const rustSrcFiles = walkFiles(rustSrcRoot, new Set([".rs"])).map((p) => ({
    path: toPosix(rustSrcRoot, p),
    text: readFileSync(p, "utf8"),
  }));
  const rustIntegrationFiles = walkFiles(rustTestsRoot, new Set([".rs"])).map((p) => ({
    path: `tests/${toPosix(rustTestsRoot, p)}`,
    text: readFileSync(p, "utf8"),
  }));
  const frontendFiles = walkFiles(frontendRoot, FRONTEND_EXTS).map((p) => ({
    path: toPosix(repoRoot, p),
    text: readFileSync(p, "utf8"),
  }));

  const result = analyzeArchitecture({ rustSrcFiles, rustIntegrationFiles, frontendFiles });
  if (result.violations.length > 0) {
    console.error("Architecture constitution check FAILED:\n" + result.violations.map((v) => `  - ${v}`).join("\n"));
    process.exit(1);
  }

  console.log(
    `architecture check ok — checked ${result.counts.rustSrc} rust src, ${result.counts.rustIntegration} rust integration tests, ${result.counts.frontend} frontend files (${result.softLimitWarnings.length} soft-limit notices >${BUDGETS.PROD_SOFT_LIMIT}L)`,
  );
}
