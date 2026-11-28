#!/usr/bin/env node
// Regression test for the 2FA login hand-off.
//
// The server answers a 2FA account with 200 { twoFARequired: true, ticket }
// and no token. doLogin() used to treat that as a failure, so an account that
// had just enabled 2FA could never sign in again. These cases pin the hand-off
// to TwoFactorAuth.showLogin2FA() and the cancelled / missing-module paths.
'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const SRC = path.join(__dirname, '..', 'src', 'fibemate-zk-polyfill.js');
const source = fs.readFileSync(SRC, 'utf8');

let passed = 0;
const results = [];

function makeEnv(opts) {
  const store = new Map([['fk_api_url', 'https://example.test/api']]);
  const calls = { twofa: [], remembered: [], fetches: [] };
  const env = {
    console,
    URL,
    Promise,
    setTimeout,
    localStorage: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k)
    },
    crypto: require('crypto').webcrypto,
    fetch: async (url, init) => {
      calls.fetches.push({ url, body: init && init.body ? JSON.parse(init.body) : null });
      const r = opts.responses.shift();
      if (!r) throw new Error('unexpected fetch');
      return { status: r.status || 200, ok: (r.status || 200) < 400, json: async () => r.body };
    },
    FIBEMATE_DEVICE_ID: {
      getOrCreate: () => 'device-from-helper',
      remember: (u, id) => { calls.remembered.push([u, id]); return id; },
      reset: () => 'device-after-reset'
    }
  };
  if (opts.withTwoFA) {
    env.TwoFactorAuth = {
      showLogin2FA: (username, ticket, onVerified, onCancelled) => {
        calls.twofa.push({ username, ticket, hasOnVerified: typeof onVerified === 'function', hasOnCancelled: typeof onCancelled === 'function' });
        if (opts.cancel) onCancelled();
        else onVerified(opts.verifiedPayload);
      }
    };
  }
  env.window = env;
  env.globalThis = env;
  return { env, calls };
}

function run(env) {
  const vm = require('vm');
  const ctx = vm.createContext(env);
  vm.runInContext(source, ctx, { filename: 'fibemate-zk-polyfill.js' });
  return ctx.FIBEMATE_ZK;
}

async function check(name, fn) {
  try {
    await fn();
    passed++;
    results.push('PASS  ' + name);
  } catch (e) {
    results.push('FAIL  ' + name + ' :: ' + e.message);
  }
}

(async () => {
  await check('2FA login hands the ticket to showLogin2FA and returns its session', async () => {
    const { env, calls } = makeEnv({
      withTwoFA: true,
      responses: [{ status: 200, body: { twoFARequired: true, ticket: 'ticket-abc' } }],
      verifiedPayload: { token: 'tok', refreshToken: 'ref', userId: 'u-1', displayName: 'Nine', deviceId: 'dev-9' }
    });
    const ZK = run(env);
    const res = await ZK.doLogin('009', 'pw');
    assert.deepStrictEqual(calls.twofa, [{ username: '009', ticket: 'ticket-abc', hasOnVerified: true, hasOnCancelled: true }]);
    assert.strictEqual(res.token, 'tok');
    assert.strictEqual(res.refreshToken, 'ref');
    assert.strictEqual(res.userId, 'u-1');
    assert.strictEqual(res.deviceId, 'dev-9');
    assert.deepStrictEqual(calls.remembered, [['009', 'dev-9']]);
    assert.strictEqual(calls.fetches.length, 1, 'must not retry the password call');
  });

  await check('cancelling the 2FA prompt rejects instead of hanging', async () => {
    const { env } = makeEnv({
      withTwoFA: true,
      cancel: true,
      responses: [{ status: 200, body: { twoFARequired: true, ticket: 't' } }]
    });
    const ZK = run(env);
    await assert.rejects(() => ZK.doLogin('009', 'pw'), /cancelled/i);
  });

  await check('a build without the 2FA module says so instead of "Login failed"', async () => {
    const { env } = makeEnv({
      withTwoFA: false,
      responses: [{ status: 200, body: { twoFARequired: true, ticket: 't' } }]
    });
    const ZK = run(env);
    await assert.rejects(() => ZK.doLogin('009', 'pw'), /two-factor/i);
  });

  await check('an ordinary login is untouched', async () => {
    const { env } = makeEnv({
      withTwoFA: true,
      responses: [{ status: 200, body: { success: true, token: 'plain', userId: 'u-2', deviceId: 'dev-2' } }]
    });
    const ZK = run(env);
    const res = await ZK.doLogin('007', 'pw');
    assert.strictEqual(res.token, 'plain');
    assert.strictEqual(res.userId, 'u-2');
  });

  await check('a wrong password still surfaces the server message', async () => {
    const { env } = makeEnv({
      withTwoFA: true,
      responses: [{ status: 401, body: { error: 'Invalid password' } }]
    });
    const ZK = run(env);
    await assert.rejects(() => ZK.doLogin('007', 'nope'), /Invalid password/);
  });

  console.log(results.join('\n'));
  console.log(passed === results.length ? `\nALL PASS (${passed}/${results.length})` : `\nFAILED (${passed}/${results.length})`);
  process.exit(passed === results.length ? 0 : 1);
})();
