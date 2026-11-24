#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
'use strict';

/**
 * Client-side device id: helper invariants + login payload.
 *
 * The second half boots the real fibemate-zk-polyfill.js in a vm with fake
 * fetch/localStorage, so the assertion is on the bytes that would go on the
 * wire, not on a reimplementation.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const helperPath = path.join(__dirname, '..', 'src', 'device-id-client.js');
const polyfillPath = path.join(__dirname, '..', 'src', 'fibemate-zk-polyfill.js');
const helper = require(helperPath);

class Store {
  constructor() { this.m = new Map(); }
  getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }
  setItem(k, v) { this.m.set(k, String(v)); }
  removeItem(k) { this.m.delete(k); }
}

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log('PASS ' + name);
}

test('isValid accepts UUIDs and rejects the legacy device-* shape', () => {
  assert.equal(helper.isValid(A), true);
  assert.equal(helper.isValid(A.toUpperCase()), true);
  assert.equal(helper.isValid('device-abc-123'), false);
  assert.equal(helper.isValid(''), false);
  assert.equal(helper.isValid(null), false);
});

test('getOrCreate persists per user and mirrors fk_device_id', () => {
  const s = new Store();
  const id = helper.getOrCreate('Alice', s);
  assert.equal(helper.isValid(id), true);
  assert.equal(s.getItem('fk_device_id:alice'), id);
  assert.equal(s.getItem('fk_device_id'), id);
  assert.equal(helper.getOrCreate('ALICE', s), id, 'username is case-insensitive');
});

test('two accounts on one machine get different ids', () => {
  const s = new Store();
  const a = helper.getOrCreate('alice', s);
  const b = helper.getOrCreate('bob', s);
  assert.notEqual(a, b);
  assert.equal(s.getItem('fk_device_id:alice'), a);
  assert.equal(s.getItem('fk_device_id:bob'), b);
  assert.equal(s.getItem('fk_device_id'), b, 'global mirror follows the latest account');
});

test('an invalid stored id is regenerated, not sent', () => {
  const s = new Store();
  s.setItem('fk_device_id:alice', 'device-old-format');
  const id = helper.getOrCreate('alice', s);
  assert.equal(helper.isValid(id), true);
  assert.notEqual(id, 'device-old-format');
});

test('a valid legacy fk_device_id is adopted once', () => {
  const s = new Store();
  s.setItem('fk_device_id', B);
  assert.equal(helper.getOrCreate('alice', s), B);
  assert.equal(s.getItem('fk_device_id:alice'), B);
});

test('an invalid legacy fk_device_id is ignored', () => {
  const s = new Store();
  s.setItem('fk_device_id', 'device-legacy');
  const id = helper.getOrCreate('alice', s);
  assert.equal(helper.isValid(id), true);
  assert.notEqual(id, 'device-legacy');
});

test('a global id owned by another account is not adopted', () => {
  const s = new Store();
  s.setItem('fk_device_id', B);
  s.setItem('fk_device_id_owner', 'bob');
  const id = helper.getOrCreate('alice', s);
  assert.notEqual(id, B);
  assert.equal(helper.isValid(id), true);
  assert.equal(s.getItem('fk_device_id:alice'), id);
});

test('remember normalises and rejects malformed ids', () => {
  const s = new Store();
  assert.equal(helper.remember('alice', A.toUpperCase(), s), A);
  assert.equal(helper.remember('alice', 'nope', s), '');
  assert.equal(s.getItem('fk_device_id:alice'), A);
});

test('reset moves the account to a new id', () => {
  const s = new Store();
  helper.remember('alice', A, s);
  const next = helper.reset('alice', s);
  assert.equal(helper.isValid(next), true);
  assert.notEqual(next, A);
  assert.equal(s.getItem('fk_device_id:alice'), next);
});

async function polyfillTests() {
  const source = fs.readFileSync(helperPath, 'utf8') + '\n' + fs.readFileSync(polyfillPath, 'utf8');
  const store = new Store();
  const calls = [];
  const responses = [
    { status: 400, body: { error: 'owned', code: 'E_DEVICE_OWNED' } },
    { status: 200, body: { token: 'tok', userId: 'u1', displayName: 'Alice', deviceId: C } }
  ];
  const context = {
    window: {},
    localStorage: store,
    crypto: webcrypto,
    console: { log() {}, warn() {} },
    Uint8Array,
    fetch: async (url, opts) => {
      calls.push({ url, body: JSON.parse(opts.body) });
      const next = responses.shift();
      return { status: next.status, json: async () => next.body };
    }
  };
  vm.createContext(context);
  vm.runInContext(source, context);

  const result = await context.window.FIBEMATE_ZK.doLogin('Alice', 'pw');
  assert.equal(calls.length, 2, 'E_DEVICE_OWNED must trigger exactly one retry');
  assert.equal(helper.isValid(calls[0].body.deviceId), true);
  assert.equal(helper.isValid(calls[1].body.deviceId), true);
  assert.notEqual(calls[0].body.deviceId, calls[1].body.deviceId, 'retry must mint a new id');
  assert.equal(result.deviceId, C, 'server-normalised id wins');
  assert.equal(store.getItem('fk_device_id:alice'), C);
  assert.equal(store.getItem('fk_device_id'), C);

  // Normal login sends the persisted id and does not retry.
  const store2 = new Store();
  const calls2 = [];
  const context2 = {
    window: {}, localStorage: store2, crypto: webcrypto, console: { log() {}, warn() {} }, Uint8Array,
    fetch: async (url, opts) => {
      calls2.push(JSON.parse(opts.body));
      return { status: 200, json: async () => ({ token: 't2', userId: 'u2', deviceId: calls2[0].deviceId }) };
    }
  };
  vm.createContext(context2);
  vm.runInContext(source, context2);
  const r2 = await context2.window.FIBEMATE_ZK.doLogin('Bob', 'pw');
  assert.equal(calls2.length, 1);
  assert.equal(helper.isValid(calls2[0].deviceId), true);
  assert.equal(r2.deviceId, calls2[0].deviceId);
  console.log('PASS login payload carries deviceId and retries once on E_DEVICE_OWNED');
  passed += 1;
}

polyfillTests().then(() => {
  console.log(`\nALL PASS (${passed})`);
}).catch((e) => {
  console.error('FAIL', e && e.message);
  process.exitCode = 1;
});
