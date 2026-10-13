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
        // (1) 原 #btnLogout 内联 onclick 的行为（原样外置）
        logoutBtn.addEventListener('click', (e) => {
          e.preventDefault();
          if (confirm('退出登录？')) {
            localStorage.removeItem('fk_token');
            localStorage.removeItem('fk_uname');
            localStorage.removeItem('fk_uid');
            localStorage.removeItem('fk_displayName');
            window.location.href = 'index.html';
          }
        });
        // (2) 原内联脚本里 addEventListener 的行为（原样外置）
        logoutBtn.addEventListener('click', (e) => {
          e.preventDefault();
          localStorage.clear();
          window.location.href = 'index.html';
        });
      }
    });
