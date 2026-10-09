// SPDX-License-Identifier: GPL-3.0-only
const { T, sleep } = require('./drv.js');
const fs = require('fs');

const CONV = '97e0b20a-3e4a-4dd7-9eb2-71f8edc842ef';
const A = { port: 9222, tag: 'A(009@1430)', uid: 'eb980664-5ee0-4f83-bd26-1abd8d61afa3', peer: '10ae1ef0-bf0f-4094-83da-acdb6036b8ff', name: '007' };
const B = { port: 9223, tag: 'B(007@1431)', uid: '10ae1ef0-bf0f-4094-83da-acdb6036b8ff', peer: 'eb980664-5ee0-4f83-bd26-1abd8d61afa3', name: '009' };
const SHOTDIR = require('path').join(__dirname, 'shots');
try { fs.mkdirSync(SHOTDIR, { recursive: true }); } catch (e) {}

const SET = X => `STATE.currentPeerId=${JSON.stringify(X.peer)};STATE.currentPeerName=${JSON.stringify(X.name)};STATE.currentConversationId=${JSON.stringify(CONV)};`;
const SEND_TEXT = (X, txt) => `(async()=>{ ${SET(X)} const i=document.getElementById('messageInput'); i.value=${JSON.stringify(txt)}; await sendMessage(); return 'ok'; })()`;
const SEND_MANY = (X, arr) => `(async()=>{ ${SET(X)} for(const t of ${JSON.stringify(arr)}){ document.getElementById('messageInput').value=t; await sendMessage(); await new Promise(r=>setTimeout(r,180)); } return 'ok'; })()`;
// 语音：app 加载后会异步清空 currentPeerId/currentConversationId，而 SET 在录音窗口之前、
// 真正发送在 4.2s 之后 → 需在 stopRecording 前重设一次。
const SEND_VOICE = (X, ms) => `(async()=>{ ${SET(X)} await VoiceMessage.startRecording(); await new Promise(r=>setTimeout(r,${ms})); ${SET(X)} VoiceMessage.stopRecording(true); await new Promise(r=>setTimeout(r,1800)); return 'ok'; })()`;
const PREP = X => `(async()=>{ ${SET(X)} let hs='n/a'; try{hs=await MessageCryptoV2.hasSession(${JSON.stringify(X.peer)});}catch(e){hs='err';} return JSON.stringify({uid:localStorage.getItem('fk_uid'), hasSession:hs, mapKeys:Object.keys(JSON.parse(localStorage.getItem('fibemate_rust_sessions_'+localStorage.getItem('fk_uid'))||'{}'))}); })()`;
const CLEAR = `(()=>{const m=document.getElementById('messagesList');if(m)m.innerHTML='';return 'cleared';})()`;
const LIST = `(async()=>{ const ml=document.getElementById('messagesList'); const all=ml?Array.from(ml.children):[]; const iso=e=>/voice/i.test(e.className||'')||!!e.querySelector('[class*="voice"]'); const selfish=e=>/self|sent|outgoing|right|mine/i.test(e.className||'')||/self|sent|outgoing|right|mine/i.test((e.querySelector('[class*="bubble"]')||{className:''}).className||''); return JSON.stringify({total:all.length, items:all.map(e=>({v:iso(e)?1:0,self:selfish(e)?1:0,txt:(e.innerText||'').replace(/\\s+/g,' ').slice(0,26)}))}); })()`;
const READF = `JSON.stringify((window.__f5||[]).filter(x=>x.type==='new_message').slice(-8).map(x=>({bytes:x.bytes,mt:x.mt,msgNum:x.msgNum})))`;
const RELOAD = `location.reload()`;
const TAP = fs.readFileSync(require('path').join(__dirname, 'ev-tap5.js'), 'utf8');
const SAFETY = `JSON.stringify({g:typeof getSafetyNumberFingerprint, m:(typeof MessageCryptoV2!=='undefined'&&typeof MessageCryptoV2.getSafetyNumberFingerprint==='function')?'M':'-', keys:(typeof MessageCryptoV2!=='undefined')?Object.keys(MessageCryptoV2).filter(k=>/safety|finger|verify/i.test(k)):[]})`;

// ④ 逐用例快照探针：定位「哪个用例污染了状态」（uid/peer/map/hybrid/tokenExp/ws）
const SNAP = `JSON.stringify((()=>{const uid=localStorage.getItem('fk_uid');const t=localStorage.getItem('fk_token');let expLeft=null;try{const p=JSON.parse(atob(t.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));expLeft=Math.round((p.exp*1000-Date.now())/1000);}catch(e){}const cp=STATE.currentPeerId;return{uid:uid&&uid.slice(0,8),peer:cp?cp.slice(0,8):null,map:Object.keys(JSON.parse(localStorage.getItem('fibemate_rust_sessions_'+uid)||'{}')).map(s=>s.slice(0,8)),hybBytes:(localStorage.getItem('fibemate_rust_hybrid_'+uid)||'').length,expLeft,ws:(STATE.ws?STATE.ws.readyState:-1)};})())`;
const snap = async (x, label) => { let s = await x.eval(SNAP); console.log('[SNAP] ' + label + ' ' + s); return parse(s); };

const R = [];
const rec = (n, ok, d) => { R.push({ n, ok, d }); console.log((ok ? 'PASS' : 'FAIL') + ' | ' + n + ' | ' + d); };
const parse = s => { try { return JSON.parse(s); } catch (e) { return null; } };
// READY 额外解 JWT exp：token 过期时显式失败，避免「假 FAIL」（真因是 B 的 token 22:52 过期→1/14）
const READY = `JSON.stringify((()=>{const t=localStorage.getItem('fk_token');let expOk=false,expLeft=null;try{if(t&&t.split('.').length===3){const p=JSON.parse(atob(t.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));expLeft=Math.round((p.exp*1000-Date.now())/1000);expOk=(p.exp*1000)>Date.now()+60000;}}catch(e){}return{ws:(typeof STATE!=='undefined'&&STATE.ws)?STATE.ws.readyState:-1,tok:!!t,expOk,expLeft,crypto:(typeof MessageCryptoV2!=='undefined'&&typeof MessageCryptoV2.getStatus==='function')?MessageCryptoV2.getStatus().initialized:false};})())`;
const waitReady = async (x, ms = 25000) => {
  const t0 = Date.now(); let last = null;
  while (Date.now() - t0 < ms) {
    last = parse(await x.eval(READY));
    if (last && last.ws === 1 && last.tok && last.expOk && last.crypto) return true;
    if (last && last.tok && !last.expOk) { console.log('[READY] TOKEN EXPIRED (expLeft=' + last.expLeft + 's) — 需重新登录'); return false; }
    await sleep(700);
  }
  console.log('[READY] timeout, last=' + JSON.stringify(last));
  return false;
};
// 重载后 app init 会异步覆盖 currentPeerId：反复 SET 直到连续 3 秒稳定
const waitStable = async (x, peerId, ms = 20000) => {
  const t0 = Date.now(); let held = 0;
  while (Date.now() - t0 < ms) {
    await x.eval(`STATE.currentPeerId=${JSON.stringify(peerId)};`);
    await sleep(1000);
    const cur = parse(await x.eval('JSON.stringify(STATE.currentPeerId)'));
    if (cur === peerId) { held++; if (held >= 3) return true; } else { held = 0; }
  }
  return false;
};
// armRecv：发送前先把「接收端」的目标设稳（连设两次、间隔 400ms）。
// 真因（2026-10-10 实测）：接收端 peer 若在首帧到达时为空，会被 msg.from===currentPeerId 守卫丢弃 → T1a/T3 假 FAIL。
const armRecv = async (x, X) => {
  await x.eval(`STATE.currentPeerId=${JSON.stringify(X.peer)};STATE.currentPeerName=${JSON.stringify(X.name)};`);
  await sleep(400);
  await x.eval(`STATE.currentPeerId=${JSON.stringify(X.peer)};`);
};
// 窄清 session：删 peer 的 Rust session + 删 sessions 映射键，保留 fibemate_rust_hybrid_* 与 fk_token
const RESET = `(async()=>{ const uid=localStorage.getItem('fk_uid'); const map=JSON.parse(localStorage.getItem('fibemate_rust_sessions_'+uid)||'{}'); const peers=Object.keys(map); for(const p of peers){ try{ await MessageCryptoV2.deleteSession(p); }catch(e){} } localStorage.removeItem('fibemate_rust_sessions_'+uid); return JSON.stringify({deleted:peers, hybridKept:!!localStorage.getItem('fibemate_rust_hybrid_'+uid), tokenKept:!!localStorage.getItem('fk_token')}); })()`;
// 轮询等待气泡（替代固定 sleep）：重载/首条后握手可能需 >5s，固定等待会“假 FAIL”
// setPeer：app 载入后会异步把 STATE.currentPeerId 清成 null（未打开会话窗口），
// 接收前需在轮询里持续重设，否则 msg.from===currentPeerId 守卫会丢弃首条消息。
const waitRecv = async (x, want, setPeer = '', ms = 25000) => {
  const t0 = Date.now(); let l = null;
  while (Date.now() - t0 < ms) {
    if (setPeer) await x.eval(setPeer);
    l = parse(await x.eval(LIST));
    if (l && l.items.some(want)) return { ok: true, l };
    await sleep(1000);
  }
  return { ok: false, l: parse(await x.eval(LIST)) };
};

(async () => {
  const a = await new T(A.port, A.tag).connect();
  const b = await new T(B.port, B.tag).connect();
  console.log('connected:', a.url, b.url);

  await waitReady(a); await waitReady(b);
  await waitStable(a, A.peer); await waitStable(b, B.peer);
  const boot = async (x) => { const p = await x.eval(PREP(x)); await x.eval(TAP); return parse(p); };
  const snapA = (l) => snap(a, l + ':A'), snapB = (l) => snap(b, l + ':B');
  await snapA('init'); await snapB('init');

  console.log('\n=== T1 双向语音短 ===');
  await a.eval(CLEAR); await b.eval(CLEAR); await boot(a); await boot(b);
  await snapA('T1a-before'); await snapB('T1a-before');
  await armRecv(b, B);
  await a.eval(SEND_VOICE(A, 2400));
  let r1a = await waitRecv(b, i => i.v === 1 && i.self === 0, SET(B)); let bl = r1a.l;
  rec('T1a A→B 语音', r1a.ok, JSON.stringify(bl));
  await snapA('T1a-after'); await snapB('T1a-after');
  await armRecv(a, A);
  await b.eval(SEND_VOICE(B, 2600));
  let r1b = await waitRecv(a, i => i.v === 1 && i.self === 0, SET(A)); let al = r1b.l;
  rec('T1b B→A 语音', r1b.ok, JSON.stringify(al));
  await a.shot(SHOTDIR + '/T1_a.png'); await b.shot(SHOTDIR + '/T1_b.png');

  console.log('\n=== T2 长语音 (>64KB) ===');
  await a.eval(CLEAR); await b.eval(CLEAR);
  await armRecv(b, B);
  await a.eval(SEND_VOICE(A, 11000)); await sleep(7000);
  let bf = parse(await b.eval(READF)); bl = parse(await b.eval(LIST));
  const bigF = bf && bf.find(x => x.mt === 'voice');
  rec('T2a A→B 长语音 收', !!(bl && bl.items.some(i => i.v === 1 && i.self === 0)), JSON.stringify(bl));
  rec('T2a 帧>64KB', !!(bigF && bigF.bytes > 65536), bigF ? ('bytes=' + bigF.bytes) : 'no voice frame');
  await armRecv(a, A);
  await b.eval(SEND_VOICE(B, 11000)); await sleep(7000);
  al = parse(await a.eval(LIST));
  rec('T2b B→A 长语音 收', !!(al && al.items.some(i => i.v === 1 && i.self === 0)), JSON.stringify(al));
  await a.shot(SHOTDIR + '/T2_a.png'); await b.shot(SHOTDIR + '/T2_b.png');

  console.log('\n=== T4 消息顺序 ===');
  await a.eval(CLEAR); await b.eval(CLEAR);
  await armRecv(b, B);
  await a.eval(SEND_MANY(A, ['1', '2', '3', '4', '5'])); await sleep(3500);
  bl = parse(await b.eval(LIST));
  const nums = bl ? bl.items.filter(i => i.self === 0).map(i => (i.txt || '').match(/^(\d+)/)?.[1] || '').filter(Boolean).join(',') : '';
  rec('T4 顺序 1-5', /^1,2,3,4,5$/.test(nums), 'got: ' + nums);

  console.log('\n=== T5 双方同时发 ===');
  await a.eval(CLEAR); await b.eval(CLEAR);
  await armRecv(a, A); await armRecv(b, B);
  await Promise.all([a.eval(SEND_TEXT(A, 'Aconcurrent')), b.eval(SEND_TEXT(B, 'Bconcurrent'))]);
  await sleep(3500);
  bl = parse(await b.eval(LIST)); al = parse(await a.eval(LIST));
  rec('T5 B 收到 A 并发', !!(bl && bl.items.some(i => i.self === 0 && /Aconcurrent/.test(i.txt))), JSON.stringify(bl));
  rec('T5 A 收到 B 并发', !!(al && al.items.some(i => i.self === 0 && /Bconcurrent/.test(i.txt))), JSON.stringify(al));

  console.log('\n=== T6 特殊字符 ===');
  await a.eval(CLEAR); await b.eval(CLEAR);
  const special = `"引号" {花} [方] \\反斜\\ 😀中文'单'`;
  await armRecv(b, B);
  await a.eval(SEND_TEXT(A, special)); await sleep(2500);
  bl = parse(await b.eval(LIST));
  rec('T6 特殊字符', !!(bl && bl.items.some(i => i.self === 0 && /引号/.test(i.txt) && /中文/.test(i.txt))), JSON.stringify(bl));

  console.log('\n=== T7 长文字 5000 ===');
  await a.eval(CLEAR); await b.eval(CLEAR);
  const longTxt = 'A'.repeat(2500) + '中'.repeat(2500);
  await armRecv(b, B);
  await a.eval(SEND_TEXT(A, longTxt)); await sleep(4000);
  bl = parse(await b.eval(LIST));
  const gotLen = bl && bl.items.filter(i => i.self === 0 && i.txt.startsWith('AAAA')).length;
  rec('T7 长文字5000 收', !!gotLen, JSON.stringify(bl && bl.items.map(i => i.txt.slice(0, 10))));

  console.log('\n=== T10 Safety Number ===');
  const sa = await a.eval(SAFETY); const sb = await b.eval(SAFETY);
  rec('T10 safety fn 存在', /"g":"function"|"m":"M"/.test(sa || '') || (parse(sa) && (parse(sa).g === 'function' || parse(sa).m === 'M')), 'A=' + sa + ' B=' + sb);

  console.log('\n=== T3 冷重启 ===');
  await a.eval(RELOAD); await b.eval(RELOAD);
  await waitReady(a); await waitReady(b);
  await waitStable(a, A.peer); await waitStable(b, B.peer);
  let sa1 = await boot(a); let sb1 = await boot(b);
  await snapA('T3a-afterReload'); await snapB('T3a-afterReload');
  await a.eval(CLEAR); await b.eval(CLEAR);
  await armRecv(b, B);
  await a.eval(SEND_TEXT(A, 'restart-both'));
  let r3a = await waitRecv(b, i => i.self === 0, SET(B)); bl = r3a.l;
  rec('T3a 两端重启后 A→B', r3a.ok, 'A:' + JSON.stringify(sa1 && sa1.hasSession) + ' B:' + JSON.stringify(sb1 && sb1.hasSession) + ' | ' + JSON.stringify(bl));

  await a.eval(RELOAD);
  await waitReady(a); await waitStable(a, A.peer);
  sa1 = await boot(a);
  await snapA('T3b-afterReload'); await snapB('T3b-afterReload');
  await a.eval(CLEAR); await b.eval(CLEAR);
  await armRecv(b, B);
  await a.eval(SEND_TEXT(A, 'restart-A'));
  let r3b = await waitRecv(b, i => i.self === 0, SET(B)); bl = r3b.l;
  rec('T3b 仅 A 重启后 A→B', r3b.ok, 'A:' + JSON.stringify(sa1 && sa1.hasSession) + ' | ' + JSON.stringify(bl));

  await b.eval(RELOAD);
  await waitReady(b); await waitStable(b, B.peer);
  sa1 = await boot(a); sb1 = await boot(b);
  await snapA('T3c-afterReload'); await snapB('T3c-afterReload');
  await a.eval(CLEAR); await b.eval(CLEAR);
  await armRecv(b, B);
  await a.eval(SEND_TEXT(A, 'restart-B'));
  let r3c = await waitRecv(b, i => i.self === 0, SET(B)); bl = r3c.l;
  rec('T3c 仅 B 重启后 A→B', r3c.ok, 'B:' + JSON.stringify(sb1 && sb1.hasSession) + ' | ' + JSON.stringify(bl));

  console.log('\n=== 汇总 ===');
  const pass = R.filter(r => r.ok).length;
  console.log('PASS ' + pass + ' / ' + R.length);
  fs.writeFileSync(SHOTDIR + '/report.json', JSON.stringify(R, null, 1));
  a.close(); b.close();
  process.exit(0);
})().catch(e => { console.log('RUNNER ERROR: ' + (e && e.message)); process.exit(1); });
