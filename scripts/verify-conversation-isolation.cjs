#!/usr/bin/env node
// 3.3.13 conversation isolation harness.
//
// Regression for the screenshot bug: switching from 007 to 刘秀 changed the
// header but left 007's messages in the list while find-or-create / handshake
// was pending. This test uses the real chat.js functions with a minimal DOM.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert');

const CHAT = path.join(__dirname, '..', 'src', 'modules', 'chat.js');
const UTILS = path.join(__dirname, '..', 'src', 'modules', 'utils.js');

function extract(src, name) {
  const re = new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\(`);
  const m = re.exec(src);
  if (!m) throw new Error(`function ${name} not found`);
  const startBrace = src.indexOf('{', m.index);
  let depth = 0;
  for (let j = startBrace; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}') {
      depth--;
      if (depth === 0) return src.slice(m.index, j + 1);
    }
  }
  throw new Error(`unbalanced braces in ${name}`);
}

class El {
  constructor(tag, id = '') {
    this.tag = tag;
    this.id = id;
    this.children = [];
    this.dataset = {};
    this.style = {};
    this._html = '';
    this._text = '';
    this.scrollTop = 0;
    this.classList = {
      _s: new Set(),
      add: (c) => { this.classList._s.add(c); },
      remove: (c) => { this.classList._s.delete(c); },
      contains: (c) => this.classList._s.has(c),
    };
  }
  get className() { return [...this.classList._s].join(' '); }
  set className(v) { this.classList._s = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get innerHTML() { return this._html; }
  set innerHTML(v) { this._html = String(v); this.children = []; }
  get textContent() { return this._text; }
  set textContent(v) { this._text = String(v); }
  get scrollHeight() { return this.children.length; }
  appendChild(n) { this.children.push(n); return n; }
  replaceChildren(n) { this.children = n && n.children ? [...n.children] : []; this._html = ''; }
  querySelectorAll(sel) {
    const cls = sel.replace(/^\./, '');
    return this.children.filter((c) => c.classList && c.classList.contains(cls));
  }
  querySelector() { return null; }
  focus() {}
}

const elements = {};
for (const id of [
  'messagesList', 'msgLoadingBar', 'messageInput', 'chatWindow', 'chatPeerName',
  'chatPeerAvatar', 'chatPeerStatus', 'e2eeStatusBar', 'e2eeStatusIcon',
  'e2eeStatusText', 'e2eeStatusDetail',
]) elements[id] = new El('div', id);

const documentStub = {
  getElementById: (id) => elements[id] || (elements[id] = new El('div', id)),
  createElement: (t) => new El(t),
  createDocumentFragment: () => new El('#fragment'),
  querySelectorAll: () => [],
  querySelector: () => null,
};

const store = new Map([['fk_token', 'test-token'], ['fk_uid', 'me']]);
for (const cid of ['cid-A', 'cid-B', 'cid-FAIL']) {
  for (let i = 1; i <= 3; i++) store.set(`fibemate_pt_${cid}-${i}`, `PT-${cid}-${i}`);
}
const localStorageStub = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};

const findDelays = { A: 150, B: 15, FAIL: 5 };
const findCalls = [];
const fetchStub = async (url, opts = {}) => {
  if (url.includes('/conversations/find-or-create')) {
    const uid = JSON.parse(opts.body || '{}').userId;
    findCalls.push(uid);
    await new Promise((r) => setTimeout(r, findDelays[uid] ?? 10));
    if (uid === 'FAIL') return { ok: false, status: 500, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => ({ conversationId: `cid-${uid}` }) };
  }
  const m = /conversations\/([^/]+)\/messages/.exec(url);
  if (!m) throw new Error(`unexpected fetch: ${url}`);
  const cid = m[1];
  await new Promise((r) => setTimeout(r, 5));
  return {
    ok: true,
    status: 200,
    json: async () => ({
      messages: Array.from({ length: 3 }, (_, i) => ({
        id: `${cid}-${i + 1}`,
        senderUserId: 'peer',
        createdAt: 1000 + i,
        ciphertext: `CT-${cid}-${i + 1}`,
      })),
    }),
  };
};

const STATE = { currentConversationId: null, currentPeerId: null, currentPeerName: null };
const sandbox = {
  STATE,
  API_BASE: 'http://test',
  localStorage: localStorageStub,
  document: documentStub,
  fetch: fetchStub,
  setTimeout,
  clearTimeout,
  performance,
  AbortController,
  hideAllMainViews() {},
  showToast() {},
  decodeCiphertext: (c) => c,
  console: { debug() {}, error() {}, log() {}, warn() {} },
  MessageCrypto: undefined,
  // Make status lookup a throwing best-effort path: openChat must still reach
  // ensureConversation and render B instead of hanging on the placeholder.
  MessageCryptoV2: {
    hasSession: async () => { throw new Error('session status unavailable'); },
    getSecurityStatus: async () => ({})
  },
  ReadReceipts: undefined,
  E2EEDisplay: undefined,
  escapeHtml: undefined,
};
vm.createContext(sandbox);
const chatSrc = fs.readFileSync(CHAT, 'utf8');
const utilsSrc = fs.readFileSync(UTILS, 'utf8');
const code = [
  extract(utilsSrc, 'escapeHtml'), extract(utilsSrc, 'formatTime'),
  extract(chatSrc, 'renderChatPlaceholder'), extract(chatSrc, 'showChatLoading'),
  extract(chatSrc, 'showChatUnavailable'), extract(chatSrc, 'openChat'),
  extract(chatSrc, 'ensureConversation'), extract(chatSrc, 'appendMessage'),
  extract(chatSrc, 'loadMessages'),
].join('\n\n');
vm.runInContext(`(function(){ ${code}
  this.openChat = openChat;
  this.ensureConversation = ensureConversation;
  this.loadMessages = loadMessages;
})()`, sandbox);

const { openChat } = sandbox;
const list = elements.messagesList;
const textOf = (n) => (n.textContent || '') + (n.innerHTML || '') + (n.children || []).map(textOf).join('');
const text = () => list.children.map(textOf).join('|');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
function check(name, fn) {
  try { fn(); results.push(['PASS', name]); }
  catch (e) { results.push(['FAIL', name, e.message]); }
}

(async () => {
  // Seed the panel as if 007 was already rendered.
  const old = new El('div');
  old.className = 'message received';
  old.innerHTML = 'PT-cid-A-OLD';
  list.appendChild(old);
  list.dataset.conversationId = 'cid-A';

  // S1: openChat(B) must remove A synchronously, before find-or-create resolves.
  const pB = openChat('B', '刘秀');
  check('S1 switch removes previous peer before await', () => {
    assert.ok(!text().includes('PT-cid-A-OLD'), `old content still visible: ${text()}`);
    assert.ok(text().includes('正在加载会话'), `loading placeholder missing: ${text()}`);
    assert.equal(list.dataset.conversationId, '');
  });
  await pB;
  check('S1b B renders only B', () => {
    assert.ok(text().includes('PT-cid-B-'), text());
    assert.ok(!text().includes('PT-cid-A-'), text());
    assert.equal(list.dataset.conversationId, 'cid-B');
  });

  // S2: A's late find-or-create must not overwrite B's conversation id.
  const pA = openChat('A', '007');
  await sleep(5);
  const pB2 = openChat('B', '刘秀');
  await pB2;
  await pA;
  check('S2 late A response cannot overwrite B', () => {
    assert.equal(STATE.currentPeerId, 'B');
    assert.equal(STATE.currentConversationId, 'cid-B');
    assert.ok(text().includes('PT-cid-B-'), text());
    assert.ok(!text().includes('PT-cid-A-'), text());
  });

  // S3: find-or-create failure leaves an explicit empty state, never old data.
  list.children = [];
  const stale = new El('div');
  stale.innerHTML = 'PT-cid-A-OLD';
  list.appendChild(stale);
  const pFail = openChat('FAIL', '刘秀');
  check('S3 failure removes previous peer synchronously', () => {
    assert.ok(!text().includes('PT-cid-A-OLD'), text());
  });
  await pFail;
  check('S3b failure shows unavailable, not old data', () => {
    assert.ok(text().includes('无法打开会话'), text());
    assert.ok(!text().includes('PT-cid-A-OLD'), text());
    assert.equal(list.dataset.conversationId, '');
  });

  for (const r of results) console.log(`${r[0]} ${r[1]}${r[2] ? ' :: ' + r[2] : ''}`);
  const failed = results.filter((r) => r[0] === 'FAIL');
  console.log(`\n${results.length - failed.length}/${results.length} PASS`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
