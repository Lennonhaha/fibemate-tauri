#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 FIBEMATE Contributors
//
// Refuse to promote a draft whose build predates main (#118).
//
// A draft release is a snapshot: `targetCommitish` is the commit it was built from.
// main keeps moving, so a draft that was correct when it was created becomes stale
// without anything turning red -- the artifacts still verify, because they verify
// against the commit they were built from. Promoting it publishes code that does not
// contain the fixes main has since received.
//
// This gate compares the draft's target with the current main head. Not "is the
// target an ancestor of main" -- a stale draft is always an ancestor. Equality is
// the only condition under which the artifact set matches the reviewed tree.
//
// Usage:
//   node scripts/check-draft-baseline.cjs --tag v3.3.16
//   node scripts/check-draft-baseline.cjs --release-id 458946642
//   node scripts/check-draft-baseline.cjs --tag v3.3.16 --main-sha <sha>   # test override
//   node scripts/check-draft-baseline.cjs --self-test
//
// Exit codes: 0 aligned, 1 gate failure (named), 2 usage or API error.
'use strict';

const { execFileSync } = require('child_process');

const EXIT_OK = 0;
const EXIT_GATE = 1;
const EXIT_USAGE = 2;

const CODES = {
  OK: 'ALIGNED',
  NO_TARGET: 'NO_TARGET',
  NOT_DRAFT: 'NOT_DRAFT',
  TARGET_UNRESOLVED: 'TARGET_UNRESOLVED',
  STALE: 'STALE_DRAFT',
  MAIN_UNRESOLVED: 'MAIN_UNRESOLVED',
};

function isSha(s) {
  return typeof s === 'string' && /^[0-9a-f]{7,40}$/i.test(s);
}

function shasMatch(a, b) {
  const x = String(a || '').toLowerCase();
  const y = String(b || '').toLowerCase();
  if (!x || !y) return false;
  if (!isSha(x) || !isSha(y)) return false;
  const n = Math.min(x.length, y.length);
  return x.slice(0, n) === y.slice(0, n);
}

/**
 * Pure decision function. All I/O happens before this is called.
 *
 * @param {object} input
 * @param {boolean} input.isDraft
 * @param {string|null} input.target        targetCommitish from the release
 * @param {string} input.mainSha            current head of main
 * @param {string|null} [input.resolvedTargetSha] target resolved to a sha (branch names)
 * @returns {{ok: boolean, code: string, detail: string}}
 */
function classify(input) {
  const { isDraft, target, mainSha, resolvedTargetSha } = input;
  if (isDraft !== true) {
    return { ok: false, code: CODES.NOT_DRAFT, detail: 'release is not a draft' };
  }
  if (!target || typeof target !== 'string') {
    return { ok: false, code: CODES.NO_TARGET, detail: 'release has no targetCommitish' };
  }
  if (!mainSha) {
    return { ok: false, code: CODES.MAIN_UNRESOLVED, detail: 'main head could not be resolved' };
  }

  const targetSha = isSha(target) ? target : resolvedTargetSha;
  if (!targetSha) {
    return {
      ok: false,
      code: CODES.TARGET_UNRESOLVED,
      detail: `targetCommitish=${target} is not a sha and did not resolve`,
    };
  }
  if (shasMatch(targetSha, mainSha)) {
    return { ok: true, code: CODES.OK, detail: `target=${target} main=${mainSha}` };
  }
  return {
    ok: false,
    code: CODES.STALE,
    detail: `target=${target} (${String(targetSha).slice(0, 12)}) main=${mainSha}. ` +
      'Rebuild the draft from the current main before promoting.',
  };
}

function gh(args) {
  return execFileSync('gh', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function resolveMain(repo, override) {
  if (override) return override;
  return gh(['api', `repos/${repo}/commits/main`, '--jq', '.sha']);
}

function resolveRef(repo, ref) {
  try {
    return gh(['api', `repos/${repo}/commits/${encodeURIComponent(ref)}`, '--jq', '.sha']);
  } catch (e) {
    return null;
  }
}

function readRelease(repo, { tag, releaseId }) {
  const endpoint = releaseId
    ? `repos/${repo}/releases/${releaseId}`
    : `repos/${repo}/releases/tags/${encodeURIComponent(tag)}`;
  let j;
  try {
    j = JSON.parse(gh(['api', endpoint]));
  } catch (e) {
    // A draft created without a tag has tag_name "untagged-..."; users still type the
    // version they meant. Fall back to matching a draft by name, and say which one matched.
    if (releaseId || !tag) throw e;
    const list = JSON.parse(gh(['api', `repos/${repo}/releases?per_page=100`]));
    const drafts = list.filter((r) => r.draft === true);
    const matches = drafts.filter((r) =>
      r.tag_name === tag || r.name === tag ||
      String(r.name || '').includes(tag) || String(r.tag_name || '').includes(tag));
    if (matches.length !== 1) {
      const seen = drafts.map((r) => `${r.id} tag_name=${r.tag_name} name=${JSON.stringify(r.name)} target=${r.target_commitish}`);
      throw new Error(
        `no unique draft matches ${tag} (matches=${matches.length}). Drafts: ${seen.join(' | ') || 'none'}`);
    }
    j = matches[0];
    console.error(`note: matched draft by name (id=${j.id} tag_name=${j.tag_name} name=${JSON.stringify(j.name)})`);
  }
  return { isDraft: j.draft === true, target: j.target_commitish || null, name: j.tag_name || j.name, tagName: j.tag_name || '', releaseId: j.id };
}

function selfTest() {
  const MAIN = 'bb7c788054040d662fd2335d4032e0e61e0f4943';
  const OLD = 'ec4546f110b457c8edcdb6c83a6c6c087cbacbb0';
  const cases = [
    { name: 'aligned sha passes', input: { isDraft: true, target: MAIN, mainSha: MAIN }, want: CODES.OK },
    { name: 'stale sha fails (ancestor of main)', input: { isDraft: true, target: OLD, mainSha: MAIN }, want: CODES.STALE },
    { name: 'short sha prefix of main passes', input: { isDraft: true, target: 'bb7c788', mainSha: MAIN }, want: CODES.OK },
    { name: 'branch main resolving to main passes', input: { isDraft: true, target: 'main', mainSha: MAIN, resolvedTargetSha: MAIN }, want: CODES.OK },
    { name: 'branch main resolving elsewhere fails', input: { isDraft: true, target: 'main', mainSha: MAIN, resolvedTargetSha: OLD }, want: CODES.STALE },
    { name: 'unresolvable branch fails', input: { isDraft: true, target: 'release/3.3', mainSha: MAIN }, want: CODES.TARGET_UNRESOLVED },
    { name: 'missing target fails', input: { isDraft: true, target: null, mainSha: MAIN }, want: CODES.NO_TARGET },
    { name: 'non-draft fails', input: { isDraft: false, target: MAIN, mainSha: MAIN }, want: CODES.NOT_DRAFT },
  ];
  let fails = 0;
  for (const c of cases) {
    const got = classify(c.input);
    const ok = got.ok === (c.want === CODES.OK) && got.code === c.want;
    if (!ok) fails += 1;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${c.name} -> ${got.code}${got.ok ? '' : ' :: ' + got.detail}`);
  }
  console.log(fails === 0 ? `SELF-TEST OK (${cases.length}/${cases.length})` : `SELF-TEST FAILED (${fails}/${cases.length})`);
  process.exit(fails === 0 ? EXIT_OK : EXIT_GATE);
}

function parseArgs(argv) {
  const out = { repo: process.env.GITHUB_REPOSITORY || 'Lennonhaha/fibemate-tauri' };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--self-test') out.selfTest = true;
    else if (a === '--tag') out.tag = argv[++i];
    else if (a === '--release-id') out.releaseId = argv[++i];
    else if (a === '--main-sha') out.mainSha = argv[++i];
    else if (a === '--repo') out.repo = argv[++i];
    else if (a === '--json') out.json = true;
    else if (a === '--help' || a === '-h') out.help = true;
    else { console.error(`unknown argument: ${a}`); out.bad = true; }
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log('usage: check-draft-baseline.cjs (--tag <tag> | --release-id <id>) [--main-sha <sha>] [--repo o/r] [--json] | --self-test');
    process.exit(EXIT_OK);
  }
  if (args.selfTest) return selfTest();
  if (args.bad || (!args.tag && !args.releaseId)) {
    console.error('usage: --tag <tag> or --release-id <id> required (or --self-test)');
    process.exit(EXIT_USAGE);
  }

  let release;
  let mainSha;
  try {
    release = readRelease(args.repo, args);
    mainSha = resolveMain(args.repo, args.mainSha);
  } catch (e) {
    console.error(`API ERROR: ${e.message}`);
    process.exit(EXIT_USAGE);
  }

  const resolvedTargetSha = isSha(release.target) ? null : resolveRef(args.repo, release.target);
  const verdict = classify({
    isDraft: release.isDraft,
    target: release.target,
    mainSha,
    resolvedTargetSha,
  });

  if (args.json) {
    console.log(JSON.stringify({ ...verdict, release: release.name, target: release.target, main: mainSha }));
  } else {
    console.log(`${verdict.code} ${verdict.detail}`);
  }
  // Let the workflow publish the tag that actually exists, not the label the operator typed.
  if (process.env.GITHUB_OUTPUT && release.tagName) {
    require('fs').appendFileSync(
      process.env.GITHUB_OUTPUT,
      `tag=${release.tagName}\nrelease_id=${release.releaseId}\n`,
      'utf8'
    );
  }
  process.exit(verdict.ok ? EXIT_OK : EXIT_GATE);
}

if (require.main === module) main();

module.exports = { classify, CODES, isSha, shasMatch };
