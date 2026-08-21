/**
 * FIBEMATE_ZK Polyfill — bridges existing auth UI to direct API calls
 * FIBEMATE_ZK.doLogin() / doRegister() are referenced but never defined in source.
 */
(function() {
  const API = () => localStorage.getItem('fk_api_url') || 'https://fibemate.net/api';

  window.FIBEMATE_ZK = {
    /** Standard password login */
    async doLogin(username, password) {
      const res = await fetch(`${API()}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!data.success && !data.token) {
        throw new Error(data.error || data.message || 'Login failed');
      }
      return {
        success: true,
        token: data.token,
        userId: data.userId || data.user_id,
        displayName: data.displayName || data.display_name || username,
        publicKey: data.publicKey || ''
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
        userId: data.userId || data.user_id,
        displayName: data.displayName || data.display_name || username,
        publicKey: publicKeyHex
      };
    },

    /** ZK registration (stub — same as standard for now) */
    async doZKRegister(username, password) {
      return this.doRegister(username, password);
    },

    /** Check if user is logged in */
    isLoggedIn() {
      return !!localStorage.getItem('fk_token');
    }
  };

  console.log('[FIBEMATE_ZK polyfill] Loaded — API:', API());
})();
