// SPDX-License-Identifier: GPL-3.0-only
(function () {
  if (window.__tap5) return 'already';
  window.__tap5 = true;
  window.__f5 = [];
  const dec = b => { try { return new TextDecoder().decode(b); } catch (e) { return ''; } };
  const numOf = s => { try { let e = typeof s === 'string' ? JSON.parse(s) : s; if (e && e.message) e = e.message; return { msgNum: e && e.messageNum, proto: e && e.protocol, mj: e && e.messageJson ? String(e.messageJson).length : 0 }; } catch (x) { return {}; } };
  STATE.ws.addEventListener('message', ev => {
    try {
      const d = ev.data; let u8;
      if (d instanceof ArrayBuffer) u8 = new Uint8Array(d); else if (ArrayBuffer.isView(d)) u8 = new Uint8Array(d.buffer); else return;
      let payload = null, cover = false;
      try { const r = (typeof WsPadding !== 'undefined') ? WsPadding.unpad(u8) : null; if (!r) cover = true; else if (r instanceof Uint8Array) payload = dec(r); else if (r.payload) payload = dec(r.payload); else payload = dec(u8); } catch (e) { payload = ''; }
      let o = null; try { o = payload ? JSON.parse(payload) : null; } catch (e) { o = null; }
      const rec = { t: Date.now(), bytes: u8.length, cover: cover, type: o && o.type, mt: o && o.messageType, from: o && o.from };
      if (o && o.envelope) Object.assign(rec, numOf(o.envelope));
      window.__f5.push(rec);
      if (window.__f5.length > 120) window.__f5.shift();
    } catch (e) {}
  }, true);
  return 'tap5';
})()
