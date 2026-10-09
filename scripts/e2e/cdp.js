// SPDX-License-Identifier: GPL-3.0-only
// cdp.js <port> [--eval "<js>"] [--file <path>]  — minimal CDP client using global WebSocket
const http = require('http');
const fs = require('fs');

function getJson(port, path) {
  return new Promise((res, rej) => {
    http.get({ host: '127.0.0.1', port, path }, r => {
      let d = ''; r.on('data', c => d += c); r.on('end', () => { try { res(JSON.parse(d)); } catch (e) { rej(new Error('bad json: ' + d.slice(0, 200))); } });
    }).on('error', rej);
  });
}

(async () => {
  const port = process.argv[2];
  const evalIdx = process.argv.indexOf('--eval');
  const fileIdx = process.argv.indexOf('--file');
  let expr = null;
  if (evalIdx >= 0) expr = process.argv[evalIdx + 1];
  else if (fileIdx >= 0) expr = fs.readFileSync(process.argv[fileIdx + 1], 'utf8');

  let list;
  try { list = await getJson(port, '/json/list'); } catch (e) { console.log('CDP list ERR:', e.message); process.exit(1); }
  const pages = list.filter(t => t.type === 'page' || t.type === 'webview' || t.webSocketDebuggerUrl);
  console.log('TARGETS:', JSON.stringify(list.map(t => ({ type: t.type, title: (t.title || '').slice(0, 60), url: (t.url || '').slice(0, 80) }))));
  if (!expr) process.exit(0);
  const target = pages.find(t => /main\.html/.test(t.url || '')) || pages[0];
  if (!target || !target.webSocketDebuggerUrl) { console.log('NO CDP TARGET'); process.exit(1); }
  console.log('EVAL ON:', target.url);

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  let id = 0; const pend = new Map();
  const send = (method, params) => new Promise(res => { const i = ++id; pend.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
  ws.addEventListener('message', ev => {
    const m = JSON.parse(ev.data);
    if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); }
  });
  ws.addEventListener('open', async () => {
    await send('Runtime.enable');
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true, userGesture: true });
    if (r.result && r.result.exceptionDetails) console.log('EXCEPTION:', JSON.stringify(r.result.exceptionDetails).slice(0, 800));
    else console.log('RESULT:', JSON.stringify(r.result && r.result.result ? r.result.result.value : r, null, 1).slice(0, 6000));
    ws.close(); process.exit(0);
  });
  ws.addEventListener('error', e => { console.log('WS ERR', e.message || e); process.exit(1); });
  setTimeout(() => { console.log('TIMEOUT'); process.exit(1); }, 30000);
})();
