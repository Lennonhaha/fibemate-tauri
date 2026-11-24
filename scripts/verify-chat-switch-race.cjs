#!/usr/bin/env node
// 3.3.12/3.3.13 switch-race verification harness (no external deps)
//
// 用法:
//   node scripts/verify-chat-switch-race.cjs                # 新实现，应全绿
//   node scripts/verify-chat-switch-race.cjs --guards-only  # 只剥两处守卫（保留 abort + fragment）
//   node scripts/verify-chat-switch-race.cjs --legacy       # 剥守卫 + abort + fragment（≈修复前）
//
// 做法：从真实 chat.js / utils.js 抽出函数原文，配最小 DOM + 可控延迟 fetch，重放切会话时序。
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const MODE = process.argv.includes('--legacy') ? 'legacy'
  : process.argv.includes('--guards-only') ? 'guards-only'
    : 'fixed';
const LEGACY = MODE === 'legacy';

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

function buildSource() {
  const chatSrc = fs.readFileSync(CHAT, 'utf8');
  const utilsSrc = fs.readFileSync(UTILS, 'utf8');
  let code = [
    extract(utilsSrc, 'escapeHtml'),
    extract(utilsSrc, 'formatTime'),
    extract(chatSrc, 'renderChatPlaceholder'),
    extract(chatSrc, 'showChatLoading'),
    extract(chatSrc, 'showChatUnavailable'),
    extract(chatSrc, 'appendMessage'),
    extract(chatSrc, 'loadMessages'),
  ].join('\n\n');

  if (MODE !== 'fixed') {
    //   --guards-only : 只剥两处守卫，保留 abort 与 fragment → 测「守卫的独立贡献」
    //   --legacy      : 再剥 abort 与 fragment（≈修复前实现）→ 归因是合并的
    const guardRe = /^[ \t]*if \(STATE\._msgAbort !== ac \|\| STATE\.currentConversationId !== conversationId\)[^\r\n]*$/gm;
    const guardCount = (code.match(guardRe) || []).length;
    if (guardCount !== 2) throw new Error(`expected 2 guard lines, got ${guardCount}`);
    code = code.replace(guardRe, '');

    if (LEGACY) {
      code = code.replace(/^[ \t]*if \(STATE\._msgAbort\) \{ try \{ STATE\._msgAbort\.abort\(\); \} catch \(_\) \{\} \}[ \t]*$/gm, '');
      code = code.replace(/^[ \t]*if \(err && err\.name === 'AbortError'\)[^\r\n]*$/gm, '');
      code = code.replace(/const _append = \(sent, text, ts, enc, label, id\) => appendMessage\(sent, text, ts, enc, label, id, frag\);/,
        'const _append = (sent, text, ts, enc, label, id) => appendMessage(sent, text, ts, enc, label, id);');
      code = code.replace(/^[ \t]*list\.replaceChildren\(frag\);[ \t]*$/gm, '');
      code = code.replace(/(async function loadMessages\(conversationId\) \{[ \t]*\r?\n[ \t]*const list = document\.getElementById\('messagesList'\);)/,
        "$1\n  list.innerHTML = '<div class=\"date-divider\"><span>Today</span></div>';");
    }
  }
  if (process.env.DUMP) fs.writeFileSync(path.join(__dirname, '..', 'tmp', 'dump-chat.js'), code, 'utf8');
  return code;
}

// ── minimal DOM ────────────────────────────────────────────────
class El {
  constructor(tag, id = '') {
    this.tag = tag; this.id = id; this.children = []; this.dataset = {}; this._html = '';
    this.style = {}; this.scrollTop = 0;
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
  get scrollHeight() { return this.children.length; }
  appendChild(n) { this.children.push(n); return n; }
  replaceChildren(n) { this.children = n && n.children ? [...n.children] : []; this._html = ''; }
  querySelectorAll(sel) {
    const cls = sel.replace(/^\./, '');
    return this.children.filter((c) => c.classList.contains(cls));
  }
  focus() {}
}

const list = new El('div', 'messagesList');
const bar = new El('div', 'msgLoadingBar');
const input = new El('input', 'messageInput');
const elements = { messagesList: list, msgLoadingBar: bar, messageInput: input };

const documentStub = {
  getElementById: (id) => elements[id] || new El('div', id),
  createElement: (t) => new El(t),
  createDocumentFragment: () => new El('#fragment'),
};

const store = new Map();
const localStorageStub = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};

// A 慢 / B 快 → 复现「旧响应后到」；J = fetch 立刻返回但 res.json() 缓慢
const DELAYS = { A: 300, B: 30, C: 60, J: 0 };
const JSON_DELAYS = { J: 120 };
const COUNTS = { A: 5, B: 5, C: 5, J: 3 };

const messagesFor = (cid) => Array.from({ length: COUNTS[cid] ?? 5 }, (_, i) => ({
  id: `${cid}-${i + 1}`,
  senderUserId: 'peer',
  createdAt: 1000 + i,
  ciphertext: `CT-${cid}-${i + 1}`,
}));

// 预置明文缓存：渲染结果带可识别标记 PT-<cid>-<n>
for (const cid of ['A', 'B', 'C', 'J']) {
  for (let i = 1; i <= 3; i++) store.set(`fibemate_pt_${cid}-${i}`, `PT-${cid}-${i}`);
}

const fetchStub = async (url, opts = {}) => {
  const cid = /conversations\/([^/]+)\/messages/.exec(url)[1];
  const delay = DELAYS[cid] ?? 10;
  await new Promise((resolve, reject) => {
    const t = setTimeout(resolve, delay);
    if (opts.signal) {
      opts.signal.addEventListener('abort', () => {
        clearTimeout(t);
        const e = new Error('aborted');
        e.name = 'AbortError';
        reject(e);
      });
    }
  });
  return {
    ok: true,
    status: 200,
    json: async () => {
      const jd = JSON_DELAYS[cid] || 0;
      if (jd) await new Promise((r) => setTimeout(r, jd));
      return { messages: messagesFor(cid) };
    },
  };
};

const STATE = { currentConversationId: null, currentPeerId: null };
const sandbox = {
  STATE, API_BASE: 'http://test', localStorage: localStorageStub, document: documentStub,
  fetch: fetchStub, setTimeout, clearTimeout, performance, AbortController,
  console: { debug() {}, error: (...a) => { if (process.env.DEBUG) console.error('[sandbox]', ...a); }, log() {}, warn() {} },
  decodeCiphertext: (c) => c, showToast() {},
  MessageCrypto: { decrypt: async () => 'DEC' },
  ReadReceipts: undefined, Crypto: undefined, MessageCryptoV2: undefined,
};
vm.createContext(sandbox);
vm.runInContext(`(function(){ ${buildSource()}
  this.loadMessages = loadMessages;
  this.appendMessage = appendMessage;
})()`, sandbox);

const { loadMessages } = sandbox;
const markers = () => list.children.map((c) => c.innerHTML + (c.dataset.messageId || '')).join('|');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let blankTicks = 0;
let samples = 0;
const sampler = setInterval(() => { samples++; if (list.children.length === 0) blankTicks++; }, 10);

const results = [];
const check = (name, ok, detail) => results.push({ name, ok: !!ok, detail });

(async () => {
  // S1: 迟到响应不得污染新面板（A 慢 300ms / B 快 30ms）
  list.children = [Object.assign(new El('div'), { innerHTML: 'PREV' })];
  STATE.currentConversationId = 'A';
  const pA = loadMessages('A');
  await sleep(20);
  STATE.currentConversationId = 'B';
  const pB = loadMessages('B');
  await Promise.allSettled([pA, pB]);
  const s1 = markers();
  check('S1 迟到响应不污染新面板', !s1.includes('PT-A-') && s1.includes('PT-B-'), s1.slice(0, 100));

  // S2: A→B→A 连点 10 轮
  const settled = [];
  for (let i = 0; i < 10; i++) {
    for (const cid of ['A', 'B', 'A']) {
      STATE.currentConversationId = cid;
      const t0 = performance.now();
      settled.push(loadMessages(cid).then(() => ({ cid, ms: Math.round(performance.now() - t0) })));
      await sleep(5);
    }
  }
  const timings = await Promise.all(settled);
  await sleep(400);
  const s2 = markers();
  check('S2 连点 30 次后只显示最终会话', s2.includes('PT-A-') && !s2.includes('PT-B-'), s2.slice(0, 140));

  // S4: fetch 已返回、res.json() 还在解析时切走。
  // 这是 abort 覆盖不到的窗口：网络层已结束，abort() 是空操作，
  // 只有响应边界那道守卫（await res.json() 之后）能拦住。
  // 备查：S4 覆盖的就是 await res.json() 这个 await 边界；其后的 sort/slice 是同步段，
  // JS 单线程不会在同步代码中被切走，故不单独设 S5（否则只会得到一条恒 PASS 的装饰性测试）。
  // 另外：渲染循环对「收到的消息」全同步（第 140-146 行直接 continue），循环内那条守卫
  // 在当前实现下不可观测，属防御性代码——不假装它被单独验证过。
  list.children = [Object.assign(new El('div'), { innerHTML: 'PREV4' })];
  STATE.currentConversationId = 'J';
  const p4 = loadMessages('J');
  await sleep(40);
  STATE.currentConversationId = 'B';
  await Promise.race([p4, sleep(2000)]);
  await sleep(200);
  const s4 = markers();
  check('S4 fetch 已返回、解析中途切走不落盘', !s4.includes('PT-J-'), s4.slice(0, 100));

  clearInterval(sampler);
  check('S3 全程无空面板', blankTicks === 0, `blankTicks=${blankTicks}/${samples}`);

  console.log(`\nmode: ${MODE}`);
  for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}  ${r.detail || ''}`);
  const ms = timings.map((t) => t.ms).sort((a, b) => a - b);
  console.log(`timing: 30 次调用，中位 ${ms[Math.floor(ms.length / 2)]}ms / 最慢 ${ms[ms.length - 1]}ms`);
  console.log('\n归因：S1/S2 由 abort 独立覆盖（--guards-only 仍 PASS）；S4 由响应边界守卫独立覆盖（--guards-only 必红）。两者缺一不可。');
  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${failed === 0 ? 'ALL PASS' : failed + ' FAILED'}`);
  process.exit(failed === 0 ? 0 : 1);
})().catch((e) => { console.error('HARNESS ERROR:', e); process.exit(2); });
