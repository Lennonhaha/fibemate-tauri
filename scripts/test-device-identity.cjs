#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
/**
 * Covers fibemate-tauri#127: the device id must survive a wiped WebView2
 * profile by being restored from the Rust-side store (app data dir).
 *
 * Run: node scripts/test-device-identity.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = process.env.FK_DEVICE_ID_SRC || path.join(__dirname, '..', 'src', 'device-id-client.js');
const code = fs.readFileSync(SRC, 'utf8');

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log('PASS ' + name);
  } catch (e) {
    failures += 1;
    console.log('FAIL ' + name + ' :: ' + (e && e.message ? e.message : e));
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

function makeStorage(seed) {
  const m = new Map(Object.entries(seed || {}));
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    dump: () => Object.fromEntries(m),
  };
}

const ID_009 = '495cb9f8-e06b-414d-9fe9-6e803c386318';
const ID_007 = '339d70e5-187a-4abd-8e88-16750503be08';

function load(opts) {
  const calls = [];
  const storage = makeStorage(opts.storage || {});
  const sandbox = {
    module: { exports: {} },
    console: { warn() {}, info() {}, log() {} },
    crypto: { randomUUID: () => ID_007 },
    localStorage: storage,
    setTimeout,
  };
  sandbox.window = sandbox;
  sandbox.document = { readyState: 'complete', addEventListener() {} };
  if (opts.tauri !== false) {
    sandbox.__TAURI_INTERNALS__ = {
      invoke: (cmd, args) => {
        calls.push({ cmd, args });
        if (cmd === 'device_identity_all') return Promise.resolve(opts.disk || {});
        if (cmd === 'device_identity_remember') {
          opts.disk = Object.assign({}, opts.disk, { [String(args.account).toLowerCase()]: args.deviceId });
          return Promise.resolve(null);
        }
        return Promise.resolve(null);
      },
    };
  }
  sandbox.module.exports = {};
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, { filename: SRC });
  return { api: sandbox.FIBEMATE_DEVICE_ID || sandbox.module.exports, storage, calls, sandbox };
}

(async () => {
  // 1. A wiped profile recovers the id from disk instead of minting a new one.
  {
    const { api, storage, calls } = load({ disk: { '009': ID_009 } });
    // The module hydrates itself on load; give that microtask a turn.
    await new Promise((r) => setTimeout(r, 0));
    check('a wiped profile recovers the id from disk instead of minting one', () => {
      assert(storage.getItem('fk_device_id:009') === ID_009, 'localStorage not repopulated');
      assert(api.getOrCreate('009') === ID_009, 'getOrCreate still minted a new id');
    });
    check('a second hydrate is a no-op', async () => {
      const again = await api.hydrate();
      assert(again === 0, 'expected idempotent hydrate, got ' + again);
    });
    check('hydrate reads the durable store, not localStorage', () => {
      assert(calls.some((c) => c.cmd === 'device_identity_all'), 'never asked the Rust side');
    });
  }

  // 2. A brand new install records the minted id on disk.
  {
    const { api, calls } = load({ disk: {} });
    await api.hydrate();
    const id = api.getOrCreatePersistent('007');
    check('a new id is written to the durable store', () => {
      assert(id === ID_007, 'unexpected id ' + id);
      const wrote = calls.filter((c) => c.cmd === 'device_identity_remember');
      assert(wrote.length === 1, 'expected exactly one remember call, got ' + wrote.length);
      assert(wrote[0].args.account === '007', 'account not normalised: ' + wrote[0].args.account);
      assert(wrote[0].args.deviceId === ID_007, 'wrong id persisted');
    });
  }

  // 3. Accounts stay separate: restoring 009 must not touch 007.
  {
    const { api, storage } = load({ disk: { '009': ID_009, '007': ID_007 } });
    await api.hydrate();
    check('per-account ids do not cross-contaminate', () => {
      assert(storage.getItem('fk_device_id:009') === ID_009, '009 wrong');
      assert(storage.getItem('fk_device_id:007') === ID_007, '007 wrong');
    });
  }

  // 4. Junk on disk is ignored, not trusted.
  {
    const { api, storage } = load({ disk: { '009': 'not-a-uuid' } });
    const restored = await api.hydrate();
    check('a malformed stored id is ignored', () => {
      assert(restored === 0, 'restored junk');
      assert(storage.getItem('fk_device_id:009') === null, 'junk written into localStorage');
    });
  }

  // 5. Outside Tauri (browser, node tests) nothing throws and nothing persists.
  {
    const { api, storage } = load({ tauri: false });
    const restored = await api.hydrate();
    check('hydrate is a no-op without the Tauri bridge', () => {
      assert(restored === 0, 'unexpected restore');
      assert(typeof api.getOrCreate('009') === 'string', 'getOrCreate broke');
      assert(storage.getItem('fk_device_id:009'), 'id not kept locally');
    });
  }

  await new Promise((r) => setTimeout(r, 10));
  console.log('');
  if (failures) {
    console.log('FAILED (' + failures + ')');
    process.exit(1);
  }
  console.log('ALL PASS (5 groups)');
})();
