// SPDX-License-Identifier: GPL-3.0-only
/**
 * TokenGuard — proactive access-token refresh + expiry warning (2026-10-10)
 *
 * Server contract (fibemate/src/index.js):
 *   POST /api/auth/refresh  { refreshToken } -> { token, refreshToken, userId, username }
 *   access token TTL = 2h (CONFIG.JWT_EXPIRES), refresh token TTL = 7d (JWT_REFRESH_EXPIRES);
 *   the server rotates BOTH tokens on every refresh call.
 *
 * Why this exists: an expired access token used to fail silently — the WebSocket
 * stayed up while every REST call 401'd, which reads to the user as "messages
 * suddenly stopped working" with no explanation. This module refreshes before
 * expiry and, when refresh itself fails, says so instead of failing quietly.
 *
 * Also installs a global fetch interceptor: any 401 from our own API gets one
 * silent refresh + one retry (single-flight refresh, recursion-guarded).
 *
 * Storage keys:
 *   fk_token          access token (existing)
 *   fk_refresh_token  refresh token (new; written by index.html at login/register)
 */
(function () {
  const WARN_SEC = 15 * 60;     // warn the user below this many seconds left
  const REFRESH_SEC = 30 * 60;  // attempt an automatic refresh below this
  const TICK_MS = 60 * 1000;
  const RELOGIN_URL = 'index.html';

  let timer = null;
  let warned = false;
  let refreshing = null;
  let bannerShown = false;

  function _b64urlToStr(s) {
    const b = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b.length % 4 ? '='.repeat(4 - (b.length % 4)) : '';
    const bin = atob(b + pad);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8').decode(bytes);
  }

  /** Decode a JWT payload without verifying it (exp/iat only — never trust for authz). */
  function decode(token) {
    try {
      if (!token || token.split('.').length < 3) return null;
      return JSON.parse(_b64urlToStr(token.split('.')[1]));
    } catch (e) {
      return null;
    }
  }

  function expLeftSec(token) {
    const p = decode(token);
    if (!p || typeof p.exp !== 'number') return null;
    return Math.round(p.exp - Date.now() / 1000);
  }

  function status() {
    const token = localStorage.getItem('fk_token');
    const refresh = localStorage.getItem('fk_refresh_token');
    const expLeft = token ? expLeftSec(token) : null;
    const refreshLeft = refresh ? expLeftSec(refresh) : null;
    return {
      hasToken: !!token,
      hasRefresh: !!refresh,
      expLeft,
      refreshLeft,
      expiring: expLeft !== null && expLeft <= REFRESH_SEC,
      expired: expLeft !== null && expLeft <= 0,
      typ: (decode(token) || {}).type || null
    };
  }

  function showBanner(msg) {
    if (bannerShown || typeof document === 'undefined') return;
    bannerShown = true;
    const el = document.createElement('div');
    el.id = 'tokenGuardBanner';
    el.style.cssText = [
      'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
      'background:#b91c1c', 'color:#fff', 'font:13px/1.5 system-ui,sans-serif',
      'padding:8px 12px', 'display:flex', 'gap:12px', 'align-items:center',
      'justify-content:center', 'box-shadow:0 2px 8px rgba(0,0,0,.35)'
    ].join(';');
    const span = document.createElement('span');
    span.textContent = msg;
    const btn = document.createElement('button');
    btn.textContent = '重新登录';
    btn.style.cssText = 'background:#fff;color:#b91c1c;border:0;border-radius:4px;padding:4px 12px;cursor:pointer;font-weight:600';
    btn.addEventListener('click', () => {
      localStorage.removeItem('fk_token');
      localStorage.removeItem('fk_refresh_token');
      window.location.href = RELOGIN_URL;
    });
    el.appendChild(span);
    el.appendChild(btn);
    document.body.appendChild(el);
  }

  function onExpired(reason) {
    STATE.authExpired = true;
    const msg = reason === 'no-refresh'
      ? '登录已过期（本端未保存 refresh token），请重新登录'
      : '登录已过期，请重新登录';
    console.warn('[TokenGuard] expired:', reason);
    try { showToast(msg, 'error'); } catch (e) { /* toast is optional */ }
    showBanner(msg);
  }

  /** POST /api/auth/refresh and persist the rotated pair. Returns true on success. */
  function refresh(manual) {
    if (refreshing) return refreshing;
    const refreshToken = localStorage.getItem('fk_refresh_token');
    if (!refreshToken) return Promise.resolve(false);
    refreshing = (async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refreshToken })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.token) {
          console.warn('[TokenGuard] refresh rejected', res.status, data && data.error);
          return false;
        }
        localStorage.setItem('fk_token', data.token);
        if (data.refreshToken) localStorage.setItem('fk_refresh_token', data.refreshToken);
        warned = false;
        bannerShown = false;
        const b = document.getElementById('tokenGuardBanner');
        if (b) b.remove();
        if (manual) { try { showToast('登录已续期', 'success'); } catch (e) {} }
        console.log('[TokenGuard] refreshed, expLeft=' + expLeftSec(data.token) + 's');
        return true;
      } catch (e) {
        console.warn('[TokenGuard] refresh failed:', e && e.message);
        return false;
      } finally {
        refreshing = null;
      }
    })();
    return refreshing;
  }

  // ------------------------------------------------------------------
  // Global fetch interceptor: 401 -> refresh once -> retry once
  // Covers every existing call site without touching them.
  //   - _refreshPromise : single-flight, concurrent 401s share one refresh
  //                       (the server rotates secrets on every /auth/refresh)
  //   - isRetry flag    : PER-REQUEST recursion guard. A module-level depth
  //                       counter breaks under concurrency (5 parallel 401s
  //                       would see depth>0 and bail out unretried).
  //   - stale/cooldown  : a 401 whose token is no longer the current one, or
  //                       that lands within 2s of a completed refresh, retries
  //                       WITHOUT a second refresh — otherwise concurrent 401s
  //                       rotate each other's fresh tokens out of validity.
  //   - _NO_RETRY       : auth endpoints are never intercepted — a 401 from
  //                       /auth/refresh must not recurse into refresh(), or
  //                       the single-flight promise awaits itself (deadlock).
  //   - API_BASE filter : third-party / non-API requests are never touched
  // ------------------------------------------------------------------
  let _origFetch = null;
  let _refreshPromise = null;
  let _lastRefreshAt = 0;
  const REFRESH_COOLDOWN_MS = 2000;   // one refresh serves every 401 in this window
  const _NO_RETRY = /\/auth\/(refresh|login|register|2fa\/verify-login)/;

  function _authHeaders(h) {
    const out = new Headers(h || {});
    const t = localStorage.getItem('fk_token');
    if (t) out.set('Authorization', 'Bearer ' + t);
    return out;
  }

  function _bearerOf(h) {
    try {
      const m = /^Bearer\s+(.+)$/i.exec(new Headers(h || {}).get('Authorization') || '');
      return m ? m[1] : null;
    } catch (e) { return null; }
  }

  function installFetchInterceptor() {
    if (_origFetch) return;                                    // idempotent
    if (typeof window === 'undefined' || typeof window.fetch !== 'function') return;
    _origFetch = window.fetch.bind(window);
    window.fetch = function (input, init) { return _guardedFetch(input, init, false); };
    console.log('[TokenGuard] fetch interceptor installed');
  }

  async function _guardedFetch(input, init, isRetry) {
    const url = typeof input === 'string' ? input
      : (input && typeof input.url === 'string') ? input.url : String(input);
    if (!API_BASE || url.indexOf(API_BASE) !== 0) return _origFetch(input, init);
    if (_NO_RETRY.test(url.split('?')[0])) return _origFetch(input, init);

    const isReq = typeof Request !== 'undefined' && input instanceof Request;
    const pristine = isReq ? input.clone() : null;
    const res = await _origFetch(input, init);
    if (res.status !== 401 || isRetry) return res;

    // Decide whether a refresh is actually needed. Two cases where it is NOT:
    //  (a) stale token  — this request carried a token that is no longer the
    //      current one, so another flight already refreshed; just retry.
    //  (b) cooldown     — a refresh completed <5s ago; the current token is
    //      already the fresh one; just retry.
    // Without (a)/(b) N concurrent 401s whose responses land on either side of
    // the first flight each start their own refresh and rotate each other out.
    const curTok = localStorage.getItem('fk_token');
    const sentTok = _bearerOf(isReq ? pristine.headers : (init && init.headers));
    const stale = !!(sentTok && curTok && sentTok !== curTok);
    const recentlyRefreshed = (Date.now() - _lastRefreshAt) < REFRESH_COOLDOWN_MS;

    if (!stale && !recentlyRefreshed) {
      if (!localStorage.getItem('fk_refresh_token')) return res;
      if (!_refreshPromise) {
        _refreshPromise = Promise.resolve(refresh(false))
          .then(ok => { if (ok) _lastRefreshAt = Date.now(); return ok; })
          .finally(() => { _refreshPromise = null; });
      }
      const ok = await _refreshPromise;
      if (!ok) return res;
    }
    if (!localStorage.getItem('fk_token')) return res;

    if (pristine) return _guardedFetch(new Request(pristine, { headers: _authHeaders(pristine.headers) }), undefined, true);
    const retryInit = Object.assign({}, init || {}, { headers: _authHeaders(init && init.headers) });
    return _guardedFetch(input, retryInit, true);
  }

  async function check() {
    const st = status();
    if (!st.hasToken) return;                      // login page / logged out
    if (st.expLeft === null) return;               // opaque token — nothing to judge
    if (st.expired) { onExpired(st.hasRefresh ? 'expired' : 'no-refresh'); return; }
    if (st.expLeft <= REFRESH_SEC) {
      const ok = await refresh(false);
      if (!ok && st.expLeft <= WARN_SEC && !warned) {
        warned = true;
        if (st.hasRefresh) onExpired('expired');
        else {
          try { showToast('登录将在 ' + Math.max(1, Math.round(st.expLeft / 60)) + ' 分钟后过期，请重新登录', 'error'); } catch (e) {}
        }
      }
    }
  }

  function start() {
    if (timer) return;                              // idempotent
    installFetchInterceptor();
    timer = setInterval(check, TICK_MS);
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => { if (!document.hidden) check(); });
      window.addEventListener('focus', () => check());
    }
    check();
    const st = status();
    console.log('[TokenGuard] started; expLeft=' + st.expLeft + 's refresh=' + st.hasRefresh);
  }

  function stop() {
    if (timer) { clearInterval(timer); timer = null; }
  }

  /** Opt-in hook for existing 401 call sites: reports the failure and surfaces it once. */
  function handle401(context) {
    const st = status();
    console.warn('[TokenGuard] 401 at', context || 'unknown', st);
    if (st.expired || !st.hasRefresh) onExpired('expired');
    return st;
  }

  const TokenGuard = { start, stop, check, refresh, status, decode, expLeftSec, handle401, installFetchInterceptor };
  if (typeof window !== 'undefined') window.TokenGuard = TokenGuard;
  if (typeof globalThis !== 'undefined') globalThis.TokenGuard = TokenGuard;
})();
