/**
 * Minimal DOM harness for the client modules that run inside the Tauri webview.
 *
 * Why this exists: the v3.3.15 build shipped a setup flow that threw
 * "Cannot set properties of null (setting 'textContent')" on the very first click.
 * Nothing in CI renders these modules, and `tauri dev` only catches what a human
 * happens to click. This harness mounts the real modules, dispatches the real click,
 * and fails when the flow throws or renders nothing.
 *
 * It is deliberately a shim, not jsdom: only the surfaces these modules touch are
 * implemented (ids, classes, innerHTML parsing, listeners, canvas 2d no-ops). When a
 * module starts needing more, the shim should grow a node/attribute at a time rather
 * than the test becoming a browser.
 *
 * Usage: node scripts/test-client-dom.cjs
 * Exit: 0 all checks pass, 1 a check failed.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = path.join(__dirname, '..', 'src');

let failures = 0;
const checks = [];
function check(name, fn) { checks.push([name, fn]); }
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ─────────────────────────────────────────────────────────────── DOM shim ──
class ClassList {
  constructor(node) { this.node = node; }
  get set() { return new Set((this.node.className || '').split(/\s+/).filter(Boolean)); }
  _write(s) { this.node.className = Array.from(s).join(' '); }
  add(c) { const s = this.set; s.add(c); this._write(s); }
  remove(c) { const s = this.set; s.delete(c); this._write(s); }
  toggle(c, on) { const s = this.set; const want = on === undefined ? !s.has(c) : !!on; if (want) s.add(c); else s.delete(c); this._write(s); return want; }
  contains(c) { return this.set.has(c); }
}

class El {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.attrs = {};
    this.listeners = {};
    this.style = {};
    this.dataset = {};
    this._text = '';
    this._innerHTML = '';
    this.classList = new ClassList(this);
    this.className = '';
    this.id = '';
  }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); if (k === 'class') this.className = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  removeAttribute(k) { delete this.attrs[k]; }
  get textContent() { return this._text; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get innerHTML() { return this._innerHTML; }
  set innerHTML(html) {
    this._innerHTML = String(html);
    this.children = [];
    parseInto(this, this._innerHTML);
  }
  appendChild(node) { node.parentNode = this; this.children.push(node); return node; }
  remove() {
    if (this.parentNode) {
      const i = this.parentNode.children.indexOf(this);
      if (i >= 0) this.parentNode.children.splice(i, 1);
      this.parentNode = null;
    }
  }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn); }
  click() { (this.listeners.click || []).forEach((fn) => fn({ target: this, preventDefault() {} })); }
  focus() {}
  getContext() {
    const noop = () => {};
    return { fillStyle: '', fillRect: noop, fillText: noop, drawImage: noop, beginPath: noop, moveTo: noop, lineTo: noop, stroke: noop, clearRect: noop, scale: noop, save: noop, restore: noop, translate: noop, rotate: noop };
  }
  *walk() { for (const c of this.children) { yield c; yield* c.walk(); } }
  querySelectorAll(sel) {
    const m = /^([.#])([\w-]+)$/.exec(String(sel).trim());
    if (!m) throw new Error('shim: unsupported selector ' + sel);
    const [, kind, name] = m;
    const out = [];
    for (const el of this.walk()) {
      if (kind === '#' ? el.id === name : el.classList.contains(name)) out.push(el);
    }
    return out;
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

function parseInto(root, html) {
  const tagRe = /<(\/?)([a-zA-Z][\w-]*)((?:\s+[^\s/>=]+(?:\s*=\s*"[^"]*"|\s*=\s*'[^']*'|\s*=\s*[^\s>]+)?)*)\s*(\/?)>/g;
  const stack = [root];
  const voidTags = new Set(['input', 'img', 'br', 'hr', 'meta', 'link', 'source', 'path', 'circle', 'line', 'rect', 'polyline', 'polygon', 'use', 'stop']);
  let m;
  while ((m = tagRe.exec(html))) {
    const [, closing, tag, attrText, selfClose] = m;
    if (closing) { if (stack.length > 1) stack.pop(); continue; }
    const el = new El(tag);
    const attrRe = /([^\s=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
    let a;
    while ((a = attrRe.exec(attrText || ''))) {
      const key = a[1];
      const val = a[2] !== undefined ? a[2] : a[3] !== undefined ? a[3] : a[4] !== undefined ? a[4] : '';
      el.setAttribute(key, val);
      if (key.startsWith('data-')) el.dataset[key.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = val;
    }
    stack[stack.length - 1].appendChild(el);
    if (!selfClose && !voidTags.has(tag.toLowerCase())) stack.push(el);
  }
}

function makeDocument() {
  const html = new El('html');
  const head = new El('head');
  const body = new El('body');
  html.appendChild(head);
  html.appendChild(body);
  return {
    documentElement: html,
    head,
    body,
    createElement: (t) => new El(t),
    getElementById: (id) => { for (const el of html.walk()) if (el.id === id) return el; return null; },
    querySelector: (s) => html.querySelector(s),
    querySelectorAll: (s) => html.querySelectorAll(s),
    addEventListener() {},
    dispatchEvent() {},
  };
}

function makeSandbox(doc, extra = {}) {
  const sandbox = {
    console,
    setTimeout,
    clearTimeout,
    document: doc,
    localStorage: {
      _d: Object.create(null),
      getItem(k) { return k in this._d ? this._d[k] : null; },
      setItem(k, v) { this._d[k] = String(v); },
      removeItem(k) { delete this._d[k]; },
    },
    fetch: extra.fetch || (async () => ({ ok: false, status: 501, json: async () => ({}) })),
    AbortController,
    crypto: { getRandomValues: (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = (i * 37 + 11) & 0xff; return arr; } },
    navigator: { clipboard: { writeText: async () => {} } },
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    escape: (s) => s,
    CustomEvent: class { constructor(t, o) { this.type = t; Object.assign(this, o || {}); } },
    WebSocket: { OPEN: 1 },
    API_BASE: 'https://fibemate.net/api',
    escapeHtml: (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    formatTime: (t) => String(t),
    showToast: () => {},
    ...extra,
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  return sandbox;
}

function loadModule(sandbox, file, exportExpr) {
  const code = fs.readFileSync(path.join(SRC, file), 'utf8');
  const ctx = vm.createContext(sandbox);
  vm.runInContext(code, ctx, { filename: file });
  // Top-level `const` does not land on the context object the way a function
  // declaration does; ask the context for the binding explicitly.
  if (exportExpr) return vm.runInContext(exportExpr, ctx, { filename: file + '#export' });
  return undefined;
}

// ──────────────────────────────────────────────────────────────── checks ──
check('2FA setup flow opens without throwing and renders the secret', async () => {
  const doc = makeDocument();
  const sandbox = makeSandbox(doc);
  // main.html ships this container; _addSettingsSection returns early without it.
  const sections = doc.createElement('div');
  sections.id = 'settingsSections';
  doc.body.appendChild(sections);

  const TwoFactorAuth = loadModule(sandbox, 'modules/two-factor-auth.js', 'TwoFactorAuth');

  assert(TwoFactorAuth, 'TwoFactorAuth global missing');
  TwoFactorAuth.init();
  await wait(600); // _addSettingsSection mounts after 500ms

  assert(doc.getElementById('twofaSettingsSection'), 'settings section was not mounted by init()');
  const btn = doc.getElementById('btnToggle2FA');
  assert(btn, 'Enable 2FA button missing');

  btn.click(); // this threw "Cannot set properties of null" before the fix

  const secret = doc.getElementById('twofaSecretDisplay');
  assert(secret, 'secret display missing from the mounted modal');
  assert(secret.textContent && secret.textContent !== 'Loading...', 'secret was never written; textContent=' + JSON.stringify(secret.textContent));
  assert(/^[A-Z2-7]{4}( [A-Z2-7]{4})*$/.test(secret.textContent), 'secret does not look like a formatted base32 key: ' + secret.textContent);
});

check('one setup modal per click (no duplicate overlay)', async () => {
  const doc = makeDocument();
  const sandbox = makeSandbox(doc);
  const sections = doc.createElement('div');
  sections.id = 'settingsSections';
  doc.body.appendChild(sections);

  const TwoFactorAuth = loadModule(sandbox, 'modules/two-factor-auth.js', 'TwoFactorAuth');
  TwoFactorAuth.init();
  await wait(600);
  doc.getElementById('btnToggle2FA').click();
  const modals = doc.querySelectorAll('.modal-overlay');
  assert(modals.length === 1, 'expected exactly one modal, found ' + modals.length);
});

check('conversation row renders the unread badge from the API payload', async () => {
  const doc = makeDocument();
  const list = doc.createElement('div');
  list.id = 'conversationList';
  doc.body.appendChild(list);
  const empty = doc.createElement('div');
  empty.id = 'emptyState';
  doc.body.appendChild(empty);

  const payload = {
    conversations: [{
      id: 'c1',
      otherUser: { id: 'u1', username: 'alice', displayName: 'Alice' },
      lastMessage: { ciphertext: 'x' },
      lastMessageAt: 1700000000000,
      unreadCount: 3,
    }],
  };
  const sandbox = makeSandbox(doc, { fetch: async () => ({ ok: true, status: 200, json: async () => payload }) });
  const refreshConversations = loadModule(sandbox, 'modules/conversations.js', 'refreshConversations');
  assert(typeof refreshConversations === 'function', 'refreshConversations missing');
  refreshConversations();
  await wait(50);

  const html = doc.getElementById('conversationList').innerHTML;
  assert(html.includes('conv-badge'), 'badge markup missing from the row');
  assert(html.includes('>3<'), 'badge value missing; got: ' + html.slice(0, 200));
});

check('refreshConversations survives a missing list element instead of throwing', async () => {
  const doc = makeDocument();
  const sandbox = makeSandbox(doc, { fetch: async () => ({ ok: true, status: 200, json: async () => ({ conversations: [] }) }) });
  const refreshConversations = loadModule(sandbox, 'modules/conversations.js', 'refreshConversations');
  refreshConversations(); // no #conversationList in this document
  await wait(20);
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log('PASS ' + name);
    } catch (e) {
      failures += 1;
      console.log('FAIL ' + name + ' :: ' + (e && e.message ? e.message : e));
    }
  }
  console.log(failures === 0 ? 'ALL PASS (' + checks.length + ' checks)' : failures + ' check(s) failed');
  process.exit(failures === 0 ? 0 : 1);
})();
