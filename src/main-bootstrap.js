// SPDX-License-Identifier: GPL-3.0-only

    document.addEventListener('DOMContentLoaded', () => {
      // 应用版本号显示（从 Tauri 后端读取 package_info().version）
      const verEl = document.getElementById('appVersion');
      if (verEl && window.__TAURI__ && window.__TAURI__.core) {
        window.__TAURI__.core.invoke('get_version')
          .then(v => { verEl.textContent = 'v' + v; })
          .catch(() => { /* 保持默认占位 */ });
      }

      const logoutBtn = document.getElementById('btnLogout');
      if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
          e.preventDefault();
          if (!confirm('退出登录？')) return;
          // Clear only the auth/session keys. The encrypted key caches
          // (fibemate_rust_hybrid_<uid>, fibemate_rust_sessions_<uid>) must
          // survive a logout -- wiping everything here breaks E2EE on the
          // next login with the same account.
          localStorage.removeItem('fk_token');
          localStorage.removeItem('fk_uname');
          localStorage.removeItem('fk_uid');
          localStorage.removeItem('fk_displayName');
          window.location.href = 'index.html';
        });
      }
    });
  