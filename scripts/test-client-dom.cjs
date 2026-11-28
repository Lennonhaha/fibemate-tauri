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
    const self = this;
    return { fillStyle: '', imageSmoothingEnabled: true,
      // Counted so a test can prove the QR was painted rather than merely mounted.
      fillRect: () => { self._fillRects = (self._fillRects || 0) + 1; },
      fillText: noop, drawImage: (img) => { self._drawImageCalls = (self._drawImageCalls || 0) + 1; },
      beginPath: noop, moveTo: noop, lineTo: noop, stroke: noop, clearRect: noop, scale: noop, save: noop, restore: noop, translate: noop, rotate: noop };
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

function parseAttributes(text) {
  // Linear scan. The obvious attribute regex nests a quantified group whose
  // branches can each match a quote run, which CodeQL flags as exponential
  // backtracking - and it only takes one hostile fixture to hang the gate.
  const out = [];
  let i = 0;
  const n = text.length;
  const isSpace = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r';
  while (i < n) {
    while (i < n && isSpace(text[i])) i++;
    if (i >= n) break;
    const nameStart = i;
    while (i < n && !isSpace(text[i]) && text[i] !== '=' && text[i] !== '>' && text[i] !== '/') i++;
    const name = text.slice(nameStart, i);
    if (!name) { i += 1; continue; }
    while (i < n && isSpace(text[i])) i++;
    let value = '';
    if (text[i] === '=') {
      i += 1;
      while (i < n && isSpace(text[i])) i++;
      const quote = text[i];
      if (quote === '"' || quote === "'") {
        i += 1;
        const valueStart = i;
        while (i < n && text[i] !== quote) i++;
        value = text.slice(valueStart, i);
        if (i < n) i += 1;
      } else {
        const valueStart = i;
        while (i < n && !isSpace(text[i]) && text[i] !== '>') i++;
        value = text.slice(valueStart, i);
      }
    }
    out.push([name, value]);
  }
  return out;
}

function parseInto(root, html) {
  const voidTags = new Set(['input', 'img', 'br', 'hr', 'meta', 'link', 'source', 'path', 'circle', 'line', 'rect', 'polyline', 'polygon', 'use', 'stop']);
  const stack = [root];
  const n = html.length;
  let i = 0;
  while (i < n) {
    const lt = html.indexOf('<', i);
    if (lt < 0) break;
    if (html.startsWith('<!--', lt)) {
      const close = html.indexOf('-->', lt + 4);
      i = close < 0 ? n : close + 3;
      continue;
    }
    let j = lt + 1;
    let closing = false;
    if (html[j] === '/') { closing = true; j += 1; }
    const nameStart = j;
    while (j < n && /[\w-]/.test(html[j])) j++;
    const tag = html.slice(nameStart, j);
    if (!tag) { i = lt + 1; continue; }
    // Find the end of this tag, ignoring ">" inside a quoted value.
    let k = j;
    let quote = null;
    let end = -1;
    while (k < n) {
      const c = html[k];
      if (quote) {
        if (c === quote) quote = null;
      } else if (c === '"' || c === "'") {
        quote = c;
      } else if (c === '>') {
        end = k;
        break;
      }
      k += 1;
    }
    if (end < 0) break;
    if (closing) {
      if (stack.length > 1) stack.pop();
      i = end + 1;
      continue;
    }
    const rawAttrs = html.slice(j, end);
    const selfClose = /\/\s*$/.test(rawAttrs);
    const attrText = selfClose ? rawAttrs.replace(/\/\s*$/, '') : rawAttrs;
    const el = new El(tag);
    for (const [key, val] of parseAttributes(attrText)) {
      el.setAttribute(key, val);
      if (key.indexOf('data-') === 0) el.dataset[key.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = val;
    }
    stack[stack.length - 1].appendChild(el);
    if (!selfClose && !voidTags.has(tag.toLowerCase())) stack.push(el);
    i = end + 1;
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
const TEST_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

function twoFaSandbox(doc, calls, confirmPayload = { enabled: true, recoveryCodes: ['AAAAAAAA'] }) {
  return makeSandbox(doc, {
    // Minimal stand-in for the vendored encoder. isDark is deterministic so the
    // test can assert a non-trivial number of modules was painted. The real bug
    // (2026-11-27) was createDataURL returning "[object Object]", which no test
    // that only checks "canvas exists" could catch.
    qrcode: () => ({
      addData() {}, make() {}, getModuleCount() { return 21; },
      isDark(r, c) { return (r * 7 + c * 3) % 4 < 2; },
      createDataURL() { throw new Error('createDataURL is broken in the vendored build; draw modules directly'); },
    }),
    fetch: async (url, opts = {}) => {
      const u = String(url);
      calls.push({ url: u, opts });
      if (u.endsWith('/auth/2fa/status')) {
        return { ok: true, status: 200, json: async () => ({ enabled: false }) };
      }
      if (u.endsWith('/auth/2fa/enable')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            secret: TEST_SECRET,
            uri: 'otpauth://totp/FIBEMATE:alice?secret=' + TEST_SECRET + '&issuer=FIBEMATE&algorithm=SHA1&digits=6&period=30',
          }),
        };
      }
      if (u.endsWith('/auth/2fa/confirm-enable')) {
        return { ok: true, status: 200, json: async () => confirmPayload };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    },
  });
}

check('2FA setup flow opens without throwing and renders the server secret', async () => {
  const doc = makeDocument();
  const calls = [];
  const sandbox = twoFaSandbox(doc, calls);
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
  await wait(50); // step 1 now waits for POST /auth/2fa/enable

  const secret = doc.getElementById('twofaSecretDisplay');
  assert(secret, 'secret display missing from the mounted modal');
  assert(secret.textContent && secret.textContent !== 'Loading...', 'secret was never written; textContent=' + JSON.stringify(secret.textContent));
  assert(secret.textContent.replace(/ /g, '') === TEST_SECRET, 'secret is not the value returned by the server: ' + secret.textContent);
  assert(calls.some((c) => c.url.endsWith('/auth/2fa/enable')), 'POST /auth/2fa/enable was not called');

  const canvas = doc.getElementById('twofaQRCanvas');
  assert(canvas, 'QR canvas missing from the modal');
  assert(canvas.dataset.qrDrawn === '21', 'QR was not drawn (dataset.qrDrawn=' + canvas.dataset.qrDrawn + ')');
  assert((canvas._fillRects || 0) > 200, 'QR canvas was never painted: fillRect calls=' + (canvas._fillRects || 0));
  assert(canvas.width === (21 + 8) * Math.max(3, Math.min(8, Math.floor(200 / (21 + 8)))), 'QR canvas size does not match integer modules: ' + canvas.width);
  assert(!canvas._drawImageCalls, 'QR still goes through an Image/data URL, the path that failed in WebView2');
});

check('2FA confirm posts the code to confirm-enable, never the secret', async () => {
  const doc = makeDocument();
  const calls = [];
  const sandbox = twoFaSandbox(doc, calls);
  const sections = doc.createElement('div');
  sections.id = 'settingsSections';
  doc.body.appendChild(sections);

  const TwoFactorAuth = loadModule(sandbox, 'modules/two-factor-auth.js', 'TwoFactorAuth');
  TwoFactorAuth.init();
  await wait(600);
  doc.getElementById('btnToggle2FA').click();
  await wait(50);

  doc.getElementById('btn2FANext').click();
  const digits = doc.querySelectorAll('.twofa-code-digit');
  '123456'.split('').forEach((d, i) => { if (digits[i]) digits[i].value = d; });
  doc.getElementById('btn2FAVerify').click();
  await wait(50);

  const confirm = calls.filter((c) => c.url.endsWith('/auth/2fa/confirm-enable'));
  assert(confirm.length === 1, 'expected exactly one confirm-enable call, got ' + confirm.length);
  const body = JSON.parse(confirm[0].opts.body);
  assert(body.code === '123456', 'code was not forwarded: ' + confirm[0].opts.body);
  assert(!('secret' in body), 'the secret must not be sent back in the confirm request');
  const setupPosts = calls.filter((c) => c.url.endsWith('/auth/2fa/enable') && c.opts.method === 'POST');
  assert(setupPosts.length === 1, 'expected one enable POST (step 1), got ' + setupPosts.length);
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

check('the Disable dialog can actually be cancelled and confirmed', async () => {
  const doc = makeDocument();
  const calls = [];
  const sandbox = makeSandbox(doc, {
    fetch: async (url, opts = {}) => {
      const u = String(url);
      calls.push({ url: u, opts });
      if (u.endsWith('/auth/2fa/status')) {
        return { ok: true, status: 200, json: async () => ({ enabled: true }) };
      }
      if (u.endsWith('/auth/2fa/disable')) {
        return { ok: true, status: 200, json: async () => ({ enabled: false }) };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    },
  });
  const sections = doc.createElement('div');
  sections.id = 'settingsSections';
  doc.body.appendChild(sections);
  doc.localStorage?.setItem?.('fk_token', 'tok');

  const TwoFactorAuth = loadModule(sandbox, 'modules/two-factor-auth.js', 'TwoFactorAuth');
  TwoFactorAuth.init();
  await wait(600);

  const btn = doc.getElementById('btnToggle2FA');
  assert(btn, 'Disable button missing (status should have been enabled)');
  assert(btn.classList.contains('twofa-btn-disable'), 'button did not switch to the disable label: ' + btn.className);

  // 3.3.18: this opened a modal whose Cancel and Disable buttons had no
  // handlers, because both were looked up with document.getElementById()
  // before the overlay was attached. The window looked frozen.
  btn.click();
  assert(doc.querySelectorAll('.modal-overlay').length === 1, 'disable modal did not open');

  const cancel = doc.getElementById('btn2FACancelDisable');
  assert(cancel, 'Cancel button missing from the disable modal');
  assert(cancel.listeners && cancel.listeners.click && cancel.listeners.click.length, 'Cancel has no click handler - the modal cannot be dismissed');
  cancel.click();
  assert(doc.querySelectorAll('.modal-overlay').length === 0, 'Cancel did not close the disable modal');

  btn.click();
  const confirm = doc.getElementById('btn2FAConfirmDisable');
  assert(confirm && confirm.listeners && confirm.listeners.click && confirm.listeners.click.length, 'Disable has no click handler - confirming does nothing');
  const digits = doc.querySelectorAll('.twofa-code-digit');
  '654321'.split('').forEach((d, i) => { if (digits[i]) digits[i].value = d; });
  confirm.click();
  await wait(50);

  const posts = calls.filter((c) => c.url.endsWith('/auth/2fa/disable'));
  assert(posts.length === 1, 'expected one disable request, got ' + posts.length);
  assert(JSON.parse(posts[0].opts.body).code === '654321', 'code was not forwarded: ' + posts[0].opts.body);
  await wait(20);
  assert(doc.querySelectorAll('.modal-overlay').length === 0, 'modal stayed open after a successful disable');
});

check('the 2FA login dialog is visible and wired on a page without .modal-overlay CSS', async () => {
  const doc = makeDocument();
  const calls = [];
  const sandbox = makeSandbox(doc, {
    fetch: async (url, opts = {}) => {
      const u = String(url);
      calls.push({ url: u, opts });
      if (u.endsWith('/auth/2fa/verify-login')) {
        return { ok: true, status: 200, json: async () => ({ token: 'tok', userId: 'u1' }) };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    },
  });

  const TwoFactorAuth = loadModule(sandbox, 'modules/two-factor-auth.js', 'TwoFactorAuth');
  let verified = null;
  let cancelled = 0;
  TwoFactorAuth.showLogin2FA('009', 'TICKET', (payload) => { verified = payload; }, () => { cancelled += 1; });

  // 3.3.19 shipped this dialog unwired and unstyled: index.html does not load the
  // stylesheet that defines .modal-overlay, so the overlay rendered as a
  // transparent block at the bottom of the document, and both buttons were looked
  // up with document.getElementById() before the subtree was attached. The user
  // only saw the login button frozen on "processing".
  const overlays = doc.querySelectorAll('.modal-overlay');
  assert(overlays.length === 1, 'login modal did not open, overlays=' + overlays.length);
  const overlay = overlays[0];
  assert(overlay.style.position === 'fixed', 'overlay is not fixed-position (would render off-screen): ' + overlay.style.position);
  assert(overlay.style.background && overlay.style.background !== '', 'overlay has no background: it would be invisible');

  const cancel = doc.getElementById('btn2FACancelLogin');
  assert(cancel, 'Cancel button missing from the login dialog');
  assert(cancel.listeners.click && cancel.listeners.click.length, 'Cancel has no click handler - the dialog cannot be dismissed');
  const verify = doc.getElementById('btn2FAVerifyLogin');
  assert(verify, 'Verify button missing from the login dialog');
  assert(verify.listeners.click && verify.listeners.click.length, 'Verify has no click handler - entering a code does nothing');

  const digits = doc.querySelectorAll('.twofa-code-digit');
  assert(digits.length === 6, 'expected 6 code inputs, got ' + digits.length);
  '123456'.split('').forEach((d, i) => { digits[i].value = d; });
  verify.click();
  await wait(60);

  const posts = calls.filter((c) => c.url.endsWith('/auth/2fa/verify-login'));
  assert(posts.length === 1, 'expected one verify-login request, got ' + posts.length);
  const body = JSON.parse(posts[0].opts.body);
  assert(body.ticket === 'TICKET', 'ticket was not forwarded: ' + posts[0].opts.body);
  assert(body.code === '123456', 'code was not forwarded: ' + posts[0].opts.body);
  assert(verified && verified.token === 'tok', 'onVerified was not called with the session');
  assert(doc.querySelectorAll('.modal-overlay').length === 0, 'dialog stayed open after a successful verification');
  assert(cancelled === 0, 'unexpected cancel callback');
});

check('a hostile username reaches the 2FA login prompt as text, not markup', async () => {
  // Alert #291 (js/xss-through-dom): showLogin2FA interpolated username straight
  // into body.innerHTML. The shim parses innerHTML for real, so an injected tag
  // becomes a node here - which is what makes this a gate and not a grep.
  const doc = makeDocument();
  const calls = [];
  const sandbox = twoFaSandbox(doc, calls);
  const TwoFactorAuth = loadModule(sandbox, 'modules/two-factor-auth.js', 'TwoFactorAuth');

  const hostile = '<img src=x onerror="globalThis.__pwned=1">';
  TwoFactorAuth.showLogin2FA(hostile, 'TICKET', () => {}, () => {});

  const nameEl = doc.getElementById('twofaLoginUsername');
  assert(nameEl, 'the login prompt has no username slot');
  assert(nameEl.textContent === hostile, 'username is not shown verbatim as text: ' + JSON.stringify(nameEl.textContent));

  const imgs = Array.from(doc.body.walk()).filter((el) => el.tagName === 'IMG');
  assert(imgs.length === 0, 'username created an <img> element: XSS through innerHTML (alert #291)');
  assert(!doc.body.innerHTML.includes('onerror'), 'the payload is still present in the markup');
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
