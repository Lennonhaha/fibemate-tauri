// SPDX-License-Identifier: GPL-3.0-only

  // ============================================================
  // 重放保护中间件（手写 Map，零新依赖）
  // ============================================================
  (function () {
    const REPLAY_TTL_MS = 5 * 60 * 1000; // 5 分钟
    const seenNonces = new Map(); // nonce → timestamp
    let cleanupTimer = null;

    function isNonceReplayed(nonce) {
      if (!nonce || typeof nonce !== 'string' || nonce.length === 0) return false;
      const now = Date.now();
      const entry = seenNonces.get(nonce);
      if (entry !== undefined) {
        if (now - entry.ts < REPLAY_TTL_MS) return true; // 还在 TTL 内 = 重放
        seenNonces.delete(nonce); // 已过期，删除并放行
      }
      seenNonces.set(nonce, { ts: now });
      // 定期清理过期项
      if (seenNonces.size > 10000) scheduleCleanup();
      return false;
    }

    function scheduleCleanup() {
      if (cleanupTimer) return;
      cleanupTimer = setTimeout(() => {
        cleanupTimer = null;
        const now = Date.now();
        for (const [k, v] of seenNonces) {
          if (now - v.ts >= REPLAY_TTL_MS) seenNonces.delete(k);
        }
      }, 60000);
    }

    // 暴露到全局，供 fetch 拦截使用
    window.__replayProtect = { isNonceReplayed, REPLAY_TTL_MS };
  })();

  // ============================================================
  // 带重放保护的 fetch 包装
  // ============================================================
  (function () {
    const _fetch = window.fetch.bind(window);
    window.fetch = async function (url, options = {}) {
      const method = (options.method || 'GET').toUpperCase();
      // 只保护写操作
      if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) return _fetch(url, options);

      // 注入 replayProtect nonce
      let headers = options.headers || {};
      let nonce = headers['X-Request-Id'] || headers['x-request-id'];
      if (!nonce) {
        nonce = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2);
        headers = { ...headers, 'X-Request-Id': nonce };
      }

      // 重放检查
      if (window.__replayProtect && window.__replayProtect.isNonceReplayed(nonce)) {
        throw new Error('\u8BF7\u6C42\u5DF2\u88AB\u91CD\u653E\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BDD');
      }

      return _fetch(url, { ...options, headers });
    };
  })();

  // ============================================================
  // 登录 / 注册逻辑
  // ============================================================
  document.addEventListener('DOMContentLoaded', () => {
    if (FIBEMATE_ZK && FIBEMATE_ZK.isLoggedIn()) {
      window.location.href = 'main.html';
      return;
    }
    initLoginForm();
    initPhoneLogin();
    initRegisterForm();
  });

  // ----------------------------------------------------------
  // 密码登录
  // ----------------------------------------------------------
  function initLoginForm() {
    const form = document.getElementById('loginForm');
    const errorEl = document.getElementById('loginError');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value;
      if (!username || !password) return;

      setLoading('loginBtn', 'loginBtnText', true);
      errorEl.style.display = 'none';

      try {
        const data = await FIBEMATE_ZK.doLogin(username, password);
        if (data.token) {
          localStorage.setItem('fk_token', data.token);
          localStorage.setItem('fk_uid', data.userId);
        }
        if (data.refreshToken) localStorage.setItem('fk_refresh_token', data.refreshToken);
        if (data.publicKey) localStorage.setItem('fk_public_key', data.publicKey);
        if (data.displayName) {
          localStorage.setItem('fk_displayName', data.displayName);
          localStorage.setItem('fk_uname', data.displayName);
        } else {
          localStorage.setItem('fk_uname', username);
        }
        showToast('\u767B\u5F55\u6210\u529F\uFF0C\u6B63\u5728\u8DF3\u8F6C...', 'success');
        setTimeout(() => { window.location.href = 'main.html'; }, 500);
      } catch (err) {
        errorEl.textContent = err.message;
        errorEl.style.display = 'block';
      } finally {
        setLoading('loginBtn', 'loginBtnText', false);
      }
    });

    document.getElementById('goRegister').addEventListener('click', (e) => {
      e.preventDefault();
      document.querySelector('.login-wrapper').style.display = 'none';
      document.getElementById('registerView').style.display = 'flex';
    });
  }

  // ----------------------------------------------------------
  // 手机号登录
  // ----------------------------------------------------------
  function initPhoneLogin() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const loginForm = document.getElementById('loginForm');
    const phoneForm = document.getElementById('phoneLoginForm');
    const sendBtn = document.getElementById('sendCaptchaBtn');
    const phoneFormEl = document.getElementById('phoneLoginForm');
    const errorEl = document.getElementById('phoneLoginError');

    // 标签切换
    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        tabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const tab = btn.dataset.tab;
        if (tab === 'password') {
          loginForm.style.display = 'flex';
          phoneForm.style.display = 'none';
        } else {
          loginForm.style.display = 'none';
          phoneForm.style.display = 'flex';
        }
      });
    });

    // 发送验证码
    sendBtn.addEventListener('click', async () => {
      const phone = document.getElementById('phoneNumber').value.trim();
      if (!/^1[3-9]\d{9}$/.test(phone)) {
        errorEl.textContent = '\u8BF7\u8F93\u5165\u6B63\u786E\u7684\u624B\u673A\u53F7';
        errorEl.style.display = 'block';
        return;
      }
      sendBtn.disabled = true;
      errorEl.style.display = 'none';
      try {
        const apiUrl = localStorage.getItem('fk_api_url') || 'https://fibemate.net/api';
        const res = await fetch(`${apiUrl}/auth/send-captcha`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ phone })
        });
        const data = await res.json();
        if (data.success) {
          startCountdown(sendBtn);
          showToast('\u9A8C\u8BC1\u7801\u5DF2\u53D1\u9001', 'success');
        } else {
          errorEl.textContent = data.message || '\u53D1\u9001\u5931\u8D25';
          errorEl.style.display = 'block';
          sendBtn.disabled = false;
        }
      } catch {
        errorEl.textContent = '\u53D1\u9001\u5931\u8D25\uFF0C\u8BF7\u91CD\u8BD5';
        errorEl.style.display = 'block';
        sendBtn.disabled = false;
      }
    });

    // 手机号登录
    phoneFormEl.addEventListener('submit', async (e) => {
      e.preventDefault();
      const phone = document.getElementById('phoneNumber').value.trim();
      const code = document.getElementById('phoneCaptcha').value.trim();
      if (!phone || !code) return;

      setLoading('phoneLoginBtn', 'phoneLoginBtnText', true);
      errorEl.style.display = 'none';

      try {
        const apiUrl = localStorage.getItem('fk_api_url') || 'https://fibemate.net/api';
        const verifyRes = await fetch(`${apiUrl}/auth/verify-captcha`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ phone, code })
        });
        const verifyData = await verifyRes.json();
        if (!verifyData.success) {
          errorEl.textContent = verifyData.message || '\u9A8C\u8BC1\u7801\u9519\u8BEF';
          errorEl.style.display = 'block';
          setLoading('phoneLoginBtn', 'phoneLoginBtnText', false);
          return;
        }
        const loginRes = await fetch(`${apiUrl}/auth/phone-login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tempToken: verifyData.tempToken, phone })
        });
        const loginData = await loginRes.json();
        if (loginData.success) {
          localStorage.setItem('fk_token', loginData.token);
          localStorage.setItem('fk_uid', loginData.userId);
          if (loginData.refreshToken) localStorage.setItem('fk_refresh_token', loginData.refreshToken);
          localStorage.setItem('fk_user_level', loginData.userLevel || '1');
          // NOTE: phone is PII — do NOT persist to localStorage (clear-text storage).
          // fk_uname is load-bearing (used by settings/main/two-factor), set from server displayName/username instead.
          localStorage.setItem('fk_uname', loginData.displayName || loginData.username || '');
          showToast('\u767B\u5F55\u6210\u529F\uFF0C\u6B63\u5728\u8DF3\u8F6C...', 'success');
          setTimeout(() => { window.location.href = 'main.html'; }, 500);
        } else {
          errorEl.textContent = loginData.message || '\u767B\u5F55\u5931\u8D25';
          errorEl.style.display = 'block';
        }
      } catch {
        errorEl.textContent = '\u767B\u5F55\u5931\u8D25\uFF0C\u8BF7\u91CD\u8BD5';
        errorEl.style.display = 'block';
      } finally {
        setLoading('phoneLoginBtn', 'phoneLoginBtnText', false);
      }
    });
  }

  // ----------------------------------------------------------
  // 注册
  // ----------------------------------------------------------
  function initRegisterForm() {
    const form = document.getElementById('registerForm');
    const errorEl = document.getElementById('registerError');

    document.getElementById('goLogin').addEventListener('click', () => {
      document.getElementById('registerView').style.display = 'none';
      document.querySelector('.login-wrapper').style.display = 'flex';
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('regUsername').value.trim();
      const password = document.getElementById('regPassword').value;
      const passwordConfirm = document.getElementById('regPasswordConfirm').value;

      errorEl.style.display = 'none';
      if (!username || !password) {
        errorEl.textContent = '\u8BF7\u586B\u5199\u6240\u6709\u5B57\u6BB5';
        errorEl.style.display = 'block';
        return;
      }
      if (password.length < 8) {
        errorEl.textContent = '\u5BC6\u7801\u81F3\u5C11 8 \u4F4D';
        errorEl.style.display = 'block';
        return;
      }
      if (password !== passwordConfirm) {
        errorEl.textContent = '\u4E24\u6B21\u5BC6\u7801\u4E0D\u4E00\u81F4';
        errorEl.style.display = 'block';
        return;
      }

      setLoading('registerBtn', 'registerBtnText', true);
      try {
        const data = await FIBEMATE_ZK.doRegister(username, password);
        // 保存会话凭证（修复：注册成功后未存 token/uid 会被 main.js 弹回登录页）
        if (data.token) {
          localStorage.setItem('fk_token', data.token);
          localStorage.setItem('fk_uid', data.userId);
        }
        if (data.refreshToken) localStorage.setItem('fk_refresh_token', data.refreshToken);
        if (data.publicKey) localStorage.setItem('fk_public_key', data.publicKey);
        if (data.displayName) {
          localStorage.setItem('fk_displayName', data.displayName);
          localStorage.setItem('fk_uname', data.displayName);
        } else {
          localStorage.setItem('fk_uname', username);
        }
        showToast('\u6B22\u8FCE ' + (data.displayName || username) + '\uFF0C\u6CE8\u518C\u6210\u529F\uFF01', 'success');
        setTimeout(() => { window.location.href = 'main.html'; }, 500);
      } catch (err) {
        errorEl.textContent = err.message;
        errorEl.style.display = 'block';
      } finally {
        setLoading('registerBtn', 'registerBtnText', false);
      }
    });
  }

  // ----------------------------------------------------------
  // 工具函数
  // ----------------------------------------------------------
  function startCountdown(btn) {
    let count = 60;
    btn.textContent = count + 's';
    const timer = setInterval(() => {
      btn.textContent = (--count) + 's';
      if (count <= 0) {
        clearInterval(timer);
        btn.textContent = '\u83B7\u53D6\u9A8C\u8BC1\u7801';
        btn.disabled = false;
      }
    }, 1000);
  }

  function setLoading(btnId, textId, loading) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    btn.disabled = loading;
    if (textId) {
      const textEl = document.getElementById(textId);
      if (textEl) {
        if (btnId === 'loginBtn') textEl.textContent = loading ? '\u5904\u7406\u4E2D...' : '\u767B\u5F55; \u00B7 \u6CE8\u518C';
        else if (btnId === 'registerBtn') textEl.textContent = loading ? '\u5904\u7406\u4E2D...' : '\u521B\u5EFA\u8D26\u53F7';
        else textEl.textContent = loading ? '\u5904\u7406\u4E2D...' : textEl.textContent;
      }
    }
  }

  function showToast(message, type) {
    type = type || 'info';
    let toast = document.getElementById('toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'toast';
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.className = 'toast ' + type;
    toast.style.display = 'block';
    setTimeout(function () { toast.style.display = 'none'; }, 4000);
  }
  