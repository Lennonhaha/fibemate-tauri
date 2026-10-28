#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
//
// Gate: the production CSP must let the app's own inline styles work while
// keeping scripts locked down.
//
// Why this is not obvious from tauri.conf.json alone: Tauri rewrites the CSP at
// build time (tauri/src/manager/mod.rs, replace_csp_nonce) and appends a nonce
// to style-src. Under CSP3, a nonce in the source list makes 'unsafe-inline' be
// ignored, so `style-src 'self' 'unsafe-inline'` in the config does NOT mean
// inline styles work: every `style="..."` attribute the app ships gets blocked,
// silently, with only a console entry to show for it. Issue #53 measured 58
// blocked attribute styles and 7 blocked injected <style> elements per load in
// this app, including four panels that were left visible on first paint.
//
// The fix is `dangerousDisableAssetCspModification: ["style-src"]`: Tauri stops
// touching style-src, 'unsafe-inline' keeps its meaning, and script-src keeps
// its nonce. The two settings are coupled: dropping either one breaks the app,
// and the breakage is invisible unless someone watches the console. Hence a
// gate.
//
// Exit codes: 0 pass, 1 a check failed, 2 usage/IO, 3 self-test found a
// mutation the gate cannot see.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const args = process.argv.slice(2);
const selfTest = args.includes('--self-test');
const confArg = args.find((a) => a.startsWith('--conf='));
const confPath = path.resolve(confArg ? confArg.slice('--conf='.length) : path.join(__dirname, '..', 'src-tauri', 'tauri.conf.json'));

// Exact token membership, not substring: a source list is a set of tokens, and
// "http://ipc.localhost" as a substring would also accept
// "http://ipc.localhost.attacker.test". CodeQL flagged the substring form in the
// first version of this gate, correctly: it is the same bug class the gate exists
// to prevent, one level up.
const has = (list, value) => list.some((item) => item === value);

function directives(csp) {
  const map = {};
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    map[tokens[0]] = tokens.slice(1);
  }
  return map;
}

function runChecks(raw) {
  const results = [];
  const add = (ok, id, detail) => results.push({ ok, id, detail });

  let conf;
  try { conf = JSON.parse(raw); } catch (e) {
    add(false, 'tauri.conf.json parses', e.message);
    return results;
  }
  const security = (conf.app && conf.app.security) || {};
  if (typeof security.csp !== 'string') {
    add(typeof security.csp === 'string', 'CSP is a single policy string', `got ${typeof security.csp}`);
    return results;
  }

  const d = directives(security.csp);
  add(!!d['default-src'] && has(d['default-src'], "'self'"), "default-src 'self'", JSON.stringify(d['default-src']));

  const script = d['script-src'] || [];
  add(script.length > 0, 'script-src is explicit', script.length ? script.join(' ') : 'missing');
  add(
    !has(script, "'unsafe-inline'") && !has(script, "'unsafe-eval'"),
    'script-src allows no inline script and no eval',
    script.join(' '),
  );

  const style = d['style-src'] || [];
  add(has(style, "'unsafe-inline'"), "style-src keeps 'unsafe-inline'", style.join(' '));
  add(has(style, "'self'"), "style-src keeps 'self'", style.join(' '));

  const disabled = security.dangerousDisableAssetCspModification;
  const disabledList = Array.isArray(disabled) ? disabled : [];
  add(
    has(disabledList, 'style-src'),
    'Tauri is told not to rewrite style-src',
    Array.isArray(disabled) ? JSON.stringify(disabled) : `${JSON.stringify(disabled)} (must be a list containing "style-src")`,
  );
  add(
    disabled !== true && !has(disabledList, 'script-src'),
    'Tauri still rewrites script-src (nonce preserved)',
    disabled === true ? 'true disables all rewriting, which drops the script nonce' : JSON.stringify(disabled),
  );

  const connect = d['connect-src'] || [];
  add(has(connect, 'ipc:'), 'connect-src allows the ipc: scheme', connect.join(' '));
  add(has(connect, 'http://ipc.localhost'), 'connect-src allows http://ipc.localhost', connect.join(' '));

  for (const [directive, source] of [['object-src', "'none'"], ['frame-src', "'none'"], ['base-uri', "'self'"]]) {
    const list = d[directive] || [];
    add(has(list, source), `${directive} ${source}`, list.length ? list.join(' ') : 'missing');
  }

  return results;
}

function loadConf() {
  return fs.readFileSync(confPath, 'utf8');
}

function main() {
  let raw;
  try { raw = loadConf(); } catch (e) { console.error(`cannot read ${confPath}: ${e.message}`); process.exit(2); }

  const base = runChecks(raw);
  const baseFailures = base.filter((r) => !r.ok).length;

  if (selfTest) {
    const mutateJson = (fn) => {
      const conf = JSON.parse(raw);
      fn(conf.app.security);
      return JSON.stringify(conf, null, 2);
    };
    const mutations = [
      ['M1 the style-src rewrite opt-out is dropped', () => mutateJson((s) => { delete s.dangerousDisableAssetCspModification; })],
      ['M2 the opt-out covers script-src too', () => mutateJson((s) => { s.dangerousDisableAssetCspModification = ['script-src', 'style-src']; })],
      ['M3 the opt-out disables every rewrite', () => mutateJson((s) => { s.dangerousDisableAssetCspModification = true; })],
      ["M4 'unsafe-inline' is removed from style-src", () => mutateJson((s) => { s.csp = s.csp.replace("style-src 'self' 'unsafe-inline'", "style-src 'self'"); })],
      ["M5 'unsafe-inline' is added to script-src", () => mutateJson((s) => { s.csp = s.csp.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'"); })],
      ['M6 the IPC host is dropped from connect-src', () => mutateJson((s) => { s.csp = s.csp.replace('ipc: http://ipc.localhost ', ''); })],
      ["M7 object-src stops being 'none'", () => mutateJson((s) => { s.csp = s.csp.replace("object-src 'none'", "object-src 'self'"); })],
      ["M8 default-src stops being 'self'", () => mutateJson((s) => { s.csp = s.csp.replace("default-src 'self'", 'default-src *'); })],
      // Substring matching would accept this: 'http://ipc.localhost' is contained in
      // 'http://ipc.localhost.attacker.test'. Exact token matching must reject it.
      ['M9 the IPC host is swapped for a lookalike domain', () => mutateJson((s) => { s.csp = s.csp.replace('http://ipc.localhost', 'http://ipc.localhost.attacker.test'); })],
    ];

    console.log(`=== self-test against ${mutations.length} mutations ===`);
    let survivors = 0;
    for (const [label, fn] of mutations) {
      let mutated;
      try { mutated = fn(); } catch (e) { console.log(`FAIL ${label} -- mutation threw: ${e.message}`); survivors++; continue; }
      if (mutated === raw) { console.log(`FAIL ${label} -- mutation changed nothing`); survivors++; continue; }
      const failures = runChecks(mutated).filter((r) => !r.ok).length;
      if (failures === 0) { console.log(`FAIL ${label} -- SURVIVED`); survivors++; }
      else console.log(`PASS ${label} -- ${failures} check(s) went red`);
    }
    console.log(`self-test: ${mutations.length - survivors}/${mutations.length} mutations killed`);
    if (baseFailures > 0) console.log('note: the config under test does not pass on its own; a red mutation is not meaningful until it does');
    if (survivors > 0) process.exit(3);
    process.exit(baseFailures > 0 ? 1 : 0);
  }

  for (const r of base) console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.id}${r.ok ? '' : ` -- ${r.detail}`}`);
  console.log(`${path.relative(process.cwd(), confPath) || confPath}: ${base.length - baseFailures}/${base.length} checks passed`);
  process.exit(baseFailures === 0 ? 0 : 1);
}

main();
