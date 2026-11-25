#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
'use strict';

/**
 * Guard against log injection regressions.
 *
 * The full scan locks the specific class that kept reopening CodeQL alerts:
 * console calls that carry message identifiers.  The diff scan is broader and
 * only looks at lines added by the current branch, so legacy logging does not
 * have to be rewritten before the gate can be useful.
 *
 * Usage:
 *   node scripts/check-log-injection.cjs
 *   node scripts/check-log-injection.cjs --diff-base origin/main
 *   node scripts/check-log-injection.cjs --self-test
 *
 * Exit codes: 0 clean, 1 finding, 2 usage/git error, 3 self-test failure.
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const CONSOLE_RE = /\bconsole\s*\.\s*(?:log|debug|info|warn|error)\s*\(/;
const ID_RE = /\b(?:_?mid|messageId|msg\.messageId|msg\.id)\b/;
const DIFF_TAINT_RE = /\b(?:msg\.|e\.|err\.|error\.|data\.|mid\b|messageId\b|peerId\b|senderUserId\b)/;

function isComment(line) {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('*') || t.startsWith('/*');
}

function codeOnly(line) {
  // Remove quoted strings, but keep interpolations from template literals:
  // console.log('[X] messageId') is a literal, console.log(`${messageId}`) is not.
  return line
    .replace(/`(?:\\.|[^`\\])*`/g, (m) => (m.match(/\$\{[^}]*\}/g) || []).join(' '))
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/"(?:\\.|[^"\\])*"/g, '""');
}

function hasConsole(line) {
  return CONSOLE_RE.test(codeOnly(line)) && !isComment(line);
}

function parenDelta(text) {
  let d = 0;
  for (const ch of text) {
    if (ch === '(') d += 1;
    else if (ch === ')') d -= 1;
  }
  return d;
}

function collectFiles(root) {
  const out = [];
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ent.name === 'node_modules' || ent.name === '.git') continue;
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (/\.(?:js|cjs)$/.test(ent.name)) out.push(p);
    }
  };
  walk(root);
  return out;
}

function scanFull() {
  const files = collectFiles(path.resolve('src'));
  const findings = [];
  let scanned = 0;
  for (const file of files) {
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    scanned += lines.length;
    lines.forEach((line, idx) => {
      if (hasConsole(line) && ID_RE.test(codeOnly(line)) && !isComment(line)) {
        findings.push({ file: path.relative(process.cwd(), file), line: idx + 1, text: line.trim() });
      }
    });
  }
  return { findings, scanned, mode: 'full' };
}

function scanDiff(base) {
  const diff = execFileSync('git', ['diff', '--unified=0', `${base}...HEAD`, '--', 'src'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  const findings = [];
  let file = null;
  let newLine = 0;
  let pending = null;
  const finish = () => {
    if (!pending) return;
    if (DIFF_TAINT_RE.test(codeOnly(pending.text))) {
      findings.push({ file, line: pending.line, text: pending.text.replace(/\s+/g, ' ').trim() });
    }
    pending = null;
  };
  for (const raw of diff.split(/\r?\n/)) {
    if (raw.startsWith('+++ b/')) {
      file = raw.slice(6);
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) {
      newLine = Number(hunk[1]);
      continue;
    }
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      const text = raw.slice(1);
      if (pending) {
        pending.text += '\n' + text;
        pending.depth += parenDelta(text);
        if (pending.depth <= 0) finish();
      } else if (hasConsole(text)) {
        pending = { line: newLine, text, depth: parenDelta(text) };
        if (pending.depth <= 0) finish();
      }
      newLine += 1;
    } else if (raw.startsWith(' ')) {
      newLine += 1;
    }
  }
  finish();
  return { findings, scanned: null, mode: `diff:${base}` };
}

function selfTest() {
  const cases = [
    { name: 'msg.from is tainted', text: "console.log('[WS] from', msg.from)", want: true },
    { name: 'message id is tainted', text: "console.log('[WS] duplicate', mid)", want: true },
    { name: 'error message is tainted', text: "console.warn('[X] failed:', e.message)", want: true },
    { name: 'literal plus loop index is safe', text: "console.log('[X] item', i)", want: false },
    { name: 'comment is ignored', text: "// console.log(msg.from)", want: false },
  ];
  let ok = true;
  for (const c of cases) {
    const got = hasConsole(c.text) && DIFF_TAINT_RE.test(codeOnly(c.text));
    if (got !== c.want) {
      ok = false;
      console.error(`SELFTEST FAIL ${c.name}: got ${got}, want ${c.want}`);
    }
  }
  console.log(ok ? `self-test: pass (${cases.length} cases)` : 'self-test: FAIL');
  return ok ? 0 : 3;
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) {
    process.exitCode = selfTest();
    return;
  }
  const baseIdx = args.indexOf('--diff-base');
  try {
    const result = baseIdx >= 0
      ? scanDiff(args[baseIdx + 1] || 'origin/main')
      : scanFull();
    const { findings } = result;
    const evidence = result.scanned == null ? result.mode : `${result.mode} lines=${result.scanned}`;
    if (findings.length) {
      console.error(`FAIL ${findings.length} console call(s) carry user-controlled values (${evidence})`);
      for (const f of findings) console.error(`  ${f.file}:${f.line} ${f.text}`);
      process.exitCode = 1;
      return;
    }
    console.log(`OK no user-controlled values in console calls (${evidence})`);
    process.exitCode = 0;
  } catch (err) {
    console.error(`ERROR ${err && err.message ? err.message : err}`);
    process.exitCode = 2;
  }
}

main();
