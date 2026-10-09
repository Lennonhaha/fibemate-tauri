// SPDX-License-Identifier: GPL-3.0-only
const http = require('http');
const fs = require('fs');

function getJson(port, path) {
  return new Promise((res, rej) => {
    http.get({ host: '127.0.0.1', port, path }, r => {
      let d = ''; r.on('data', c => d += c); r.on('end', () => { try { res(JSON.parse(d)); } catch (e) { rej(new Error('bad json')); } });
    }).on('error', rej);
  });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

class T {
  constructor(port, tag) { this.port = port; this.tag = tag; this.id = 0; this.pend = new Map(); }
  async connect() {
    const list = await getJson(this.port, '/json/list');
    const target = list.find(t => /main\.html/.test(t.url || '')) || list[0];
    this.url = target.url;
    this.ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      this.ws.addEventListener('open', res);
      this.ws.addEventListener('error', e => rej(new Error('ws err')));
    });
    this.ws.addEventListener('message', ev => {
      const m = JSON.parse(ev.data);
      if (m.id && this.pend.has(m.id)) { this.pend.get(m.id)(m); this.pend.delete(m.id); }
    });
    await this.send('Runtime.enable');
    try { await this.send('Page.enable'); } catch (e) {}
    return this;
  }
  send(method, params) {
    return new Promise(res => { const i = ++this.id; this.pend.set(i, res); this.ws.send(JSON.stringify({ id: i, method, params })); });
  }
  async eval(expr, timeoutMs = 40000) {
    const p = this.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true, userGesture: true });
    const r = await Promise.race([p, sleep(timeoutMs).then(() => ({ __timeout: true }))]);
    if (r && r.__timeout) return { __timeout: true };
    if (r.result && r.result.exceptionDetails) return { __exc: JSON.stringify(r.result.exceptionDetails).slice(0, 400) };
    return r.result && r.result.result ? r.result.result.value : null;
  }
  async shot(path) {
    try {
      const r = await this.send('Page.captureScreenshot', { format: 'png' });
      if (r.result && r.result.data) { fs.writeFileSync(path, Buffer.from(r.result.data, 'base64')); return path; }
    } catch (e) {}
    return null;
  }
  close() { try { this.ws.close(); } catch (e) {} }
}
module.exports = { T, sleep, getJson };
