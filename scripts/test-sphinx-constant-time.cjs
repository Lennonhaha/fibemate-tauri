#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
/**
 * scripts/test-sphinx-constant-time.cjs — the identicon check must use the real
 * constant-time primitive, and must fail closed when it cannot.
 *
 * Why this exists (2026-10-28): src/privacy-layers/sphinx-packet.js asked for
 * `./constant-time.js`, which never existed in that directory. A try/catch turned
 * the failure into `constantTimeEqual = null`, and the identicon comparison then
 * fell back to `===`. Nothing crashed, no test looked, and the timing-variable
 * path was the one that ran. "It still works" was the whole disguise.
 *
 * Checks:
 *   1. resolveConstantTimeEqual() returns a function (not null).
 *   2. It is the very function exported by src/crypto/crypto/constant-time.js.
 *   3. Equal inputs compare true, differing inputs false, length mismatch false.
 *   4. verifyPacketIdenticon routes through it (behavioural, not textual).
 *   5. The source contains no `===` identicon fallback and no swallowing catch.
 *
 * --self-test mutates a temporary copy and expects each mutation to be caught:
 *   M1 break the require path        -> the resolver must throw (never return null)
 *   M2 restore the `===` fallback    -> check 5 red
 *   M3 restore the swallowing catch  -> check 5 red
 *
 * Exit codes: 0 pass, 1 check failed, 2 IO/usage, 3 self-test found a survivor.
 */
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.join(__dirname, '..');
const MODULE = path.join(REPO, 'src', 'privacy-layers', 'sphinx-packet.js');
const CT_MODULE = path.join(REPO, 'src', 'crypto', 'crypto', 'constant-time.js');

const failures = [];
async function check(name, fn) {
  try {
    const r = await fn();
    if (r === true) console.log('PASS ' + name);
    else { console.log('FAIL ' + name + (typeof r === 'string' ? ' — ' + r : '')); failures.push(name); }
  } catch (err) {
    console.log('FAIL ' + name + ' — threw: ' + err.message);
    failures.push(name);
  }
}

function loadSource(file = MODULE) {
  return fs.readFileSync(file, 'utf8');
}

function staticChecks(src) {
  const problems = [];
  if (/packet\.identicon\s*===\s*expectedIdenticon/.test(src)) problems.push('identicon === fallback present');
  if (/catch\s*\([^)]*\)\s*\{\s*constantTimeEqual\s*=\s*null/.test(src)) problems.push('swallowing catch present');
  if (!/resolveConstantTimeEqual\(\)\(packet\.identicon,\s*expectedIdenticon\)/.test(src)) {
    problems.push('verifyPacketIdenticon does not call the resolver');
  }
  return problems;
}

async function runChecks(src) {
  const mod = require(MODULE);
  const ct = require(CT_MODULE);

  await check('resolver returns a function', () => typeof mod.resolveConstantTimeEqual === 'function' || 'exported resolver missing');
  await check('resolver yields the shipped primitive', () => {
    const got = mod.resolveConstantTimeEqual();
    if (typeof got !== 'function') return 'resolver returned ' + String(got);
    return got === ct.constantTimeEqual || 'resolver returned a different function';
  });
  await check('comparison semantics (equal / differ / length)', () => {
    const f = mod.resolveConstantTimeEqual();
    if (f('abcd', 'abcd') !== true) return 'equal inputs not true';
    if (f('abcd', 'abce') !== false) return 'differing inputs not false';
    if (f('abc', 'abcd') !== false) return 'length mismatch not false';
    return true;
  });
  await check('verifyPacketIdenticon uses the primitive (behavioural)', async () => {
    const { SphinxHandler } = mod;
    const p = new SphinxHandler({});
    p.sphinx = { generateIdenticon: async () => 'abcdefghijklmnop' };
    const ok = await p.verifyPacketIdenticon({ identicon: 'abcdefghijklmnop' }, 'me');
    const bad = await p.verifyPacketIdenticon({ identicon: 'abcdefghijklmnoX' }, 'me');
    if (ok !== true) return 'matching identicon rejected';
    if (bad !== false) return 'non-matching identicon accepted';
    return true;
  });
  await check('no === fallback, no swallowing catch', () => {
    const problems = staticChecks(src);
    return problems.length === 0 || problems.join('; ');
  });
}

function runChild(file) {
  const script = [
    'try {',
    '  const m = require(process.argv[1]);',
    '  const f = m.resolveConstantTimeEqual();',
    '  if (typeof f !== "function") { console.error("not a function"); process.exit(7); }',
    '  console.log("OK");',
    '} catch (e) {',
    '  console.error(e.message);',
    '  process.exit(9);',
    '}',
  ].join('\n');
  return spawnSync(process.execPath, ['-e', script, file], { encoding: 'utf8' });
}

function selfTest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sphinx-ct-'));
  const src = loadSource();
  let survivors = 0;

  // M1: break the require path. The resolver must refuse (throw), never return null.
  const m1 = path.join(dir, 'm1.js');
  fs.writeFileSync(m1, src.replace("require('../crypto/crypto/constant-time.js')", "require('./does-not-exist.js')"), 'utf8');
  {
    const r = runChild(m1);
    const killed = r.status !== 0;
    console.log((killed ? 'KILLED ' : 'SURVIVED ') + 'M1 broken require path (exit ' + r.status + ')');
    if (!killed) survivors++;
  }

  // M2: put the timing-variable fallback back.
  {
    const mutated = src.replace(
      'return resolveConstantTimeEqual()(packet.identicon, expectedIdenticon);',
      'if (typeof constantTimeEqual === "function") { return constantTimeEqual(packet.identicon, expectedIdenticon); }\n        return packet.identicon === expectedIdenticon;',
    );
    const problems = staticChecks(mutated);
    const killed = problems.length > 0;
    console.log((killed ? 'KILLED ' : 'SURVIVED ') + 'M2 === fallback restored' + (killed ? ' (' + problems.join('; ') + ')' : ''));
    if (!killed) survivors++;
  }

  // M3: put the swallowing catch back.
  {
    const mutated = src.replace(
      "const mod = require('../crypto/crypto/constant-time.js');",
      "let mod; try { mod = require('../crypto/crypto/constant-time.js'); } catch (e) { constantTimeEqual = null; }",
    );
    const problems = staticChecks(mutated);
    const killed = problems.length > 0;
    console.log((killed ? 'KILLED ' : 'SURVIVED ') + 'M3 swallowing catch restored' + (killed ? ' (' + problems.join('; ') + ')' : ''));
    if (!killed) survivors++;
  }

  fs.rmSync(dir, { recursive: true, force: true });
  if (survivors > 0) {
    console.log('\nSELF-TEST FAILED: ' + survivors + ' mutation(s) survived');
    process.exit(3);
  }
  console.log('\nSELF-TEST OK: all mutations killed');
}

let src;
try { src = loadSource(); } catch (err) { console.error('cannot read ' + MODULE + ': ' + err.message); process.exit(2); }

runChecks(src).then(() => {
  if (process.argv.includes('--self-test')) selfTest();
  if (failures.length) {
    console.log('\n' + failures.length + ' check(s) failed');
    process.exit(1);
  }
  console.log('\nall checks passed');
  process.exit(0);
});
