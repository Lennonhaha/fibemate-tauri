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
const SEND_VOICE = (X, ms) => `(async()=>{ ${SET(X)} await VoiceMessage.startRecording(); await new Promise(r=>setTimeout(r,${ms})); VoiceMessage.stopRecording(true); await new Promise(r=>setTimeout(r,1800)); return 'ok'; })()`;
const PREP = X => `(async()=>{ ${SET(X)} let hs='n/a'; try{hs=await MessageCryptoV2.hasSession(${JSON.stringify(X.peer)});}catch(e){hs='err';} return JSON.stringify({uid:localStorage.getItem('fk_uid'), hasSession:hs, mapKeys:Object.keys(JSON.parse(localStorage.getItem('fibemate_rust_sessions_'+localStorage.getItem('fk_uid'))||'{}'))}); })()`;
const CLEAR = `(()=>{const m=document.getElementById('messagesList');if(m)m.innerHTML='';return 'cleared';})()`;
const LIST = `(async()=>{ const ml=document.getElementById('messagesList'); const all=ml?Array.from(ml.children):[]; const iso=e=>/voice/i.test(e.className||'')||!!e.querySelector('[class*="voice"]'); const selfish=e=>/self|sent|outgoing|right|mine/i.test(e.className||'')||/self|sent|outgoing|right|mine/i.test((e.querySelector('[class*="bubble"]')||{className:''}).className||''); return JSON.stringify({total:all.length, items:all.map(e=>({v:iso(e)?1:0,self:selfish(e)?1:0,txt:(e.innerText||'').replace(/\\s+/g,' ').slice(0,26)}))}); })()`;
const READF = `JSON.stringify((window.__f5||[]).filter(x=>x.type==='new_message').slice(-8).map(x=>({bytes:x.bytes,mt:x.mt,msgNum:x.msgNum})))`;
const RELOAD = `location.reload()`;
const TAP = fs.readFileSync(require('path').join(__dirname, 'ev-tap5.js'), 'utf8');
const SAFETY = `JSON.stringify({g:typeof getSafetyNumberFingerprint, m:(typeof MessageCryptoV2!=='undefined'&&typeof MessageCryptoV2.getSafetyNumberFingerprint==='function')?'M':'-', keys:(typeof MessageCryptoV2!=='undefined')?Object.keys(MessageCryptoV2).filter(k=>/safety|finger|verify/i.test(k)):[]})`;

const R = [];
const rec = (n, ok, d) => { R.push({ n, ok, d }); console.log((ok ? 'PASS' : 'FAIL') + ' | ' + n + ' | ' + d); };
const parse = s => { try { return JSON.parse(s); } catch (e) { return null; } };

(async () => {
  const a = await new T(A.port, A.tag).connect();
  const b = await new T(B.port, B.tag).connect();
  console.log('connected:', a.url, b.url);

  const boot = async (x) => { const p = await x.eval(PREP(x)); await x.eval(TAP); return parse(p); };

  console.log('\n=== T1 双向语音短 ===');
  await a.eval(CLEAR); await b.eval(CLEAR); await boot(a); await boot(b);
  await a.eval(SEND_VOICE(A, 2400)); await sleep(4000);
  let bl = parse(await b.eval(LIST));
  rec('T1a A→B 语音', !!(bl && bl.items.some(i => i.v === 1 && i.self === 0)), JSON.stringify(bl));
  await b.eval(SEND_VOICE(B, 2600)); await sleep(4000);
  let al = parse(await a.eval(LIST));
  rec('T1b B→A 语音', !!(al && al.items.some(i => i.v === 1 && i.self === 0)), JSON.stringify(al));
  await a.shot(SHOTDIR + '/T1_a.png'); await b.shot(SHOTDIR + '/T1_b.png');

  console.log('\n=== T2 长语音 (>64KB) ===');
  await a.eval(CLEAR); await b.eval(CLEAR);
  await a.eval(SEND_VOICE(A, 11000)); await sleep(7000);
  let bf = parse(await b.eval(READF)); bl = parse(await b.eval(LIST));
  const bigF = bf && bf.find(x => x.mt === 'voice');
  rec('T2a A→B 长语音 收', !!(bl && bl.items.some(i => i.v === 1 && i.self === 0)), JSON.stringify(bl));
  rec('T2a 帧>64KB', !!(bigF && bigF.bytes > 65536), bigF ? ('bytes=' + bigF.bytes) : 'no voice frame');
  await b.eval(SEND_VOICE(B, 11000)); await sleep(7000);
  al = parse(await a.eval(LIST));
  rec('T2b B→A 长语音 收', !!(al && al.items.some(i => i.v === 1 && i.self === 0)), JSON.stringify(al));
  await a.shot(SHOTDIR + '/T2_a.png'); await b.shot(SHOTDIR + '/T2_b.png');

  console.log('\n=== T4 消息顺序 ===');
  await a.eval(CLEAR); await b.eval(CLEAR);
  await a.eval(SEND_MANY(A, ['1', '2', '3', '4', '5'])); await sleep(3500);
  bl = parse(await b.eval(LIST));
  const nums = bl ? bl.items.filter(i => i.self === 0).map(i => i.txt).join(',') : '';
  rec('T4 顺序 1-5', /1,2,3,4,5/.test(nums.replace(/\s/g, '')), 'got: ' + nums);

  console.log('\n=== T5 双方同时发 ===');
  await a.eval(CLEAR); await b.eval(CLEAR);
  await Promise.all([a.eval(SEND_TEXT(A, 'Aconcurrent')), b.eval(SEND_TEXT(B, 'Bconcurrent'))]);
  await sleep(3500);
  bl = parse(await b.eval(LIST)); al = parse(await a.eval(LIST));
  rec('T5 B 收到 A 并发', !!(bl && bl.items.some(i => i.self === 0 && /Aconcurrent/.test(i.txt))), JSON.stringify(bl));
  rec('T5 A 收到 B 并发', !!(al && al.items.some(i => i.self === 0 && /Bconcurrent/.test(i.txt))), JSON.stringify(al));

  console.log('\n=== T6 特殊字符 ===');
  await a.eval(CLEAR); await b.eval(CLEAR);
  const special = `"引号" {花} [方] \\反斜\\ 😀中文'单'`;
  await a.eval(SEND_TEXT(A, special)); await sleep(2500);
  bl = parse(await b.eval(LIST));
  rec('T6 特殊字符', !!(bl && bl.items.some(i => i.self === 0 && /引号/.test(i.txt) && /中文/.test(i.txt))), JSON.stringify(bl));

  console.log('\n=== T7 长文字 5000 ===');
  await a.eval(CLEAR); await b.eval(CLEAR);
  const longTxt = 'A'.repeat(2500) + '中'.repeat(2500);
  await a.eval(SEND_TEXT(A, longTxt)); await sleep(4000);
  bl = parse(await b.eval(LIST));
  const gotLen = bl && bl.items.filter(i => i.self === 0 && i.txt.startsWith('AAAA')).length;
  rec('T7 长文字5000 收', !!gotLen, JSON.stringify(bl && bl.items.map(i => i.txt.slice(0, 10))));

  console.log('\n=== T10 Safety Number ===');
  const sa = await a.eval(SAFETY); const sb = await b.eval(SAFETY);
  rec('T10 safety fn 存在', /"g":"function"|"m":"M"/.test(sa || '') || (parse(sa) && (parse(sa).g === 'function' || parse(sa).m === 'M')), 'A=' + sa + ' B=' + sb);

  console.log('\n=== T3 冷重启 ===');
  await a.eval(RELOAD); await b.eval(RELOAD); await sleep(13000);
  let sa1 = await boot(a); let sb1 = await boot(b);
  await a.eval(CLEAR); await b.eval(CLEAR);
  await a.eval(SEND_TEXT(A, 'restart-both')); await sleep(3000);
  bl = parse(await b.eval(LIST));
  rec('T3a 两端重启后 A→B', !!(bl && bl.items.some(i => i.self === 0)), 'A:' + JSON.stringify(sa1 && sa1.hasSession) + ' B:' + JSON.stringify(sb1 && sb1.hasSession) + ' | ' + JSON.stringify(bl));

  await a.eval(RELOAD); await sleep(11000);
  sa1 = await boot(a);
  await a.eval(CLEAR); await b.eval(CLEAR);
  await a.eval(SEND_TEXT(A, 'restart-A')); await sleep(3000);
  bl = parse(await b.eval(LIST));
  rec('T3b 仅 A 重启后 A→B', !!(bl && bl.items.some(i => i.self === 0)), 'A:' + JSON.stringify(sa1 && sa1.hasSession) + ' | ' + JSON.stringify(bl));

  await b.eval(RELOAD); await sleep(11000);
  sa1 = await boot(a); sb1 = await boot(b);
  await a.eval(CLEAR); await b.eval(CLEAR);
  await a.eval(SEND_TEXT(A, 'restart-B')); await sleep(3000);
  bl = parse(await b.eval(LIST));
  rec('T3c 仅 B 重启后 A→B', !!(bl && bl.items.some(i => i.self === 0)), 'B:' + JSON.stringify(sb1 && sb1.hasSession) + ' | ' + JSON.stringify(bl));

  console.log('\n=== 汇总 ===');
  const pass = R.filter(r => r.ok).length;
  console.log('PASS ' + pass + ' / ' + R.length);
  fs.writeFileSync(SHOTDIR + '/report.json', JSON.stringify(R, null, 1));
  a.close(); b.close();
  process.exit(0);
})().catch(e => { console.log('RUNNER ERROR: ' + (e && e.message)); process.exit(1); });
