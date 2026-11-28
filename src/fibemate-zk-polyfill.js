/**
 * FIBEMATE_ZK Polyfill — bridges existing auth UI to direct API calls
 * FIBEMATE_ZK.doLogin() / doRegister() are referenced but never defined in source.
 */
(function() {
  const API = () => localStorage.getItem('fk_api_url') || 'https://fibemate.net/api';
  const DeviceId = () => window.FIBEMATE_DEVICE_ID;

  function getDeviceId(username) {
    try { return DeviceId() ? DeviceId().getOrCreate(username) : ''; }
    catch (e) { console.warn('[FIBEMATE_ZK] deviceId unavailable:', e.message); return ''; }
  }

  function rememberDeviceId(username, id) {
    try { return DeviceId() ? DeviceId().remember(username, id) : ''; }
    catch (e) { console.warn('[FIBEMATE_ZK] deviceId store failed:', e.message); return ''; }
  }

  function resetDeviceId(username) {
    try { return DeviceId() ? DeviceId().reset(username) : ''; }
    catch (e) { console.warn('[FIBEMATE_ZK] deviceId reset failed:', e.message); return ''; }
  }

  window.FIBEMATE_ZK = {
    /** One login POST; deviceId is omitted when the helper is unavailable. */
    async _loginRequest(username, password, deviceId) {
      const body = deviceId ? { username, password, deviceId } : { username, password };
      return fetch(`${API()}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
    },

    /** Standard password login */
    async doLogin(username, password) {
      let deviceId = getDeviceId(username);
      let res = await this._loginRequest(username, password, deviceId);
      let data = await res.json();

      // A copied profile can carry an id now owned by another account. Mint a
      // fresh one once; a second failure is a real error, not a retry loop.
      if (res.status === 400 && data && data.code === 'E_DEVICE_OWNED') {
        deviceId = resetDeviceId(username);
        res = await this._loginRequest(username, password, deviceId);
        data = await res.json();
      }

      // An account with 2FA gets no token: the server answers 200
      // { twoFARequired: true, ticket }. Without this branch the client threw
      // "Login failed" and the ticket died unused — the user was locked out.
      if (data && data.twoFARequired) {
        const twofa = (typeof TwoFactorAuth !== 'undefined') ? TwoFactorAuth : null;
        if (!twofa || typeof twofa.showLogin2FA !== 'function') {
          throw new Error('This account requires a two-factor code, but this build cannot ask for one. Install the latest FIBEMATE build.');
        }
        const verified = await new Promise((resolve, reject) => {
          twofa.showLogin2FA(
            username,
            data.ticket,
            (payload) => resolve(payload || {}),
            () => reject(new Error('Login cancelled'))
          );
        });
        if (!verified || !verified.token) {
          throw new Error('Two-factor verification did not return a session. Sign in again.');
        }
        if (verified.deviceId) rememberDeviceId(username, verified.deviceId);
        return {
          success: true,
          token: verified.token,
          refreshToken: verified.refreshToken || null,
          userId: verified.userId || verified.user_id,
          displayName: verified.displayName || username,
          publicKey: verified.publicKey || '',
          deviceId: verified.deviceId || deviceId
        };
      }

      if (!data.success && !data.token) {
        throw new Error(data.error || data.message || 'Login failed');
      }
      if (data.deviceId) rememberDeviceId(username, data.deviceId);
      return {
        success: true,
        token: data.token,
        refreshToken: data.refreshToken || null, // TokenGuard: needed for silent renewal
        userId: data.userId || data.user_id,
        displayName: data.displayName || data.display_name || username,
        publicKey: data.publicKey || '',
        deviceId: data.deviceId || deviceId
      };
    },

    /** Standard register — 后端强制要求 publicKey，注册时生成 ECDH P-256 身份密钥对并随表单提交 */
    async doRegister(username, password) {
      let publicKeyHex = '';
      try {
        const kp = await crypto.subtle.generateKey(
          { name: 'ECDH', namedCurve: 'P-256' },
          true,
          ['deriveBits']
        );
        const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
        publicKeyHex = Array.from(raw).map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (e) {
        console.warn('[FIBEMATE_ZK] keygen failed, sending empty publicKey:', e.message);
      }
      const res = await fetch(`${API()}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          displayName: username,
          publicKey: publicKeyHex,
          signedPrekey: publicKeyHex
        })
      });
      const data = await res.json();
      if (!data.success && !data.token) {
        throw new Error(data.error || data.message || 'Registration failed');
      }
      return {
        success: true,
        token: data.token,
        refreshToken: data.refreshToken || null, // TokenGuard: needed for silent renewal
        userId: data.userId || data.user_id,
        displayName: data.displayName || data.display_name || username,
        publicKey: publicKeyHex,
        deviceId: data.deviceId || ''
      };
    },

    /** ZK registration (stub — same as standard for now) */
    async doZKRegister(username, password) {
      return this.doRegister(username, password);
    },

    /** Check if user is logged in */
    isLoggedIn() {
      return !!localStorage.getItem('fk_token');
    },

    getDeviceId(username) { return getDeviceId(username); },
    rememberDeviceId(username, id) { return rememberDeviceId(username, id); },
    resetDeviceId(username) { return resetDeviceId(username); }
  };

  console.log('[FIBEMATE_ZK polyfill] Loaded — API:', API());
})();
