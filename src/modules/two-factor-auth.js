/**
 * FIBEMATE Two-Factor Authentication (2FA) Module
 * 双因素认证 — TOTP (Time-based One-Time Password)
 *
 * 功能：
 * - TOTP 设置/启用/禁用
 * - 二维码生成（扫码绑定 Authenticator App）
 * - 验证码校验（服务端 RFC 6238）
 * - 恢复码由服务端生成
 * - 登录流程 2FA 验证步骤
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

const TwoFactorAuth = (() => {
  // ── 状态 ──
  // Enrolment is closed until the login flow can carry device identity.
  // /api/auth/2fa/verify-login returns tokens with deviceId:'', so an account
  // that enables 2FA stops acking messages: readBy stays empty and isRead never
  // flips. The server refuses /api/auth/2fa/enable with 403 for the same
  // reason; this flag keeps the button from inviting users into that refusal.
  // Turning 2FA off stays available for anyone already in that state.
  const ENROLMENT_AVAILABLE = true;
  const ENROLMENT_UNAVAILABLE_HINT = 'Temporarily unavailable: device identity binding is not complete.';

  let is2FAEnabled = false;
  let setupPhase = false; // 设置阶段（验证中）

  // ── 初始化 ──
  function init() {
    _injectStyles();
    _check2FAStatus();
    _addSettingsSection();
    console.log('[2FA] Module initialized');
  }

  // ── 注入样式 ──
  function _injectStyles() {
    const style = document.createElement('style');
    style.id = 'twofactor-auth-styles';
    style.textContent = `
      /* 2FA 设置面板 */
      .twofa-setup-panel {
        padding: 16px;
      }

      .twofa-card {
        background: var(--bg-input);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 12px;
      }

      .twofa-card-title {
        font-size: 14px;
        font-weight: 600;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .twofa-card-desc {
        font-size: 12px;
        color: var(--text-secondary);
        line-height: 1.6;
      }

      /* 2FA 状态指示器 */
      .twofa-status-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border-radius: 8px;
        font-size: 11px;
        font-weight: 600;
      }

      .twofa-status-badge.enabled {
        background: rgba(0,229,195,0.08);
        color: var(--accent);
        border: 1px solid rgba(0,229,195,0.2);
      }

      .twofa-status-badge.disabled {
        background: rgba(255,71,87,0.08);
        color: var(--danger);
        border: 1px solid rgba(255,71,87,0.2);
      }

      /* QR码容器 */
      .twofa-qr-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        padding: 16px;
      }

      .twofa-qr-canvas {
        display: block;
        width: 200px;
        height: 200px;
        box-sizing: content-box;
        background: white;
        border-radius: 8px;
        padding: 8px;
        margin-bottom: 12px;
        image-rendering: pixelated;
      }

      .twofa-secret-key {
        font-family: 'Courier New', monospace;
        font-size: 13px;
        color: var(--accent);
        word-break: break-all;
        text-align: center;
        padding: 8px;
        background: var(--bg-card);
        border-radius: 6px;
        margin-top: 8px;
        letter-spacing: 1px;
      }

      /* 验证码输入 */
      .twofa-code-input {
        display: flex;
        gap: 8px;
        justify-content: center;
        margin: 16px 0;
      }

      .twofa-code-digit {
        width: 40px;
        height: 48px;
        text-align: center;
        font-size: 20px;
        font-weight: 700;
        font-family: 'Courier New', monospace;
        background: var(--bg-input);
        border: 2px solid var(--border-subtle);
        border-radius: 8px;
        color: var(--text-primary);
        outline: none;
        transition: border-color 0.15s;
      }

      .twofa-code-digit:focus {
        border-color: var(--accent);
        box-shadow: 0 0 0 3px var(--accent-dim);
      }

      .twofa-code-digit.filled {
        border-color: var(--accent);
      }

      /* 恢复码 */
      .twofa-recovery-codes {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 6px;
        margin: 12px 0;
      }

      .twofa-recovery-code {
        font-family: 'Courier New', monospace;
        font-size: 12px;
        padding: 6px 10px;
        background: var(--bg-card);
        border-radius: 6px;
        text-align: center;
        letter-spacing: 1px;
      }

      .twofa-recovery-warning {
        font-size: 11px;
        color: var(--danger);
        text-align: center;
        margin: 8px 0;
        padding: 8px;
        background: rgba(255,71,87,0.06);
        border-radius: 6px;
      }

      /* 2FA 登录验证模态框 */
      .twofa-login-modal .modal {
        max-width: 380px;
        text-align: center;
      }

      .twofa-login-icon {
        font-size: 48px;
        margin-bottom: 12px;
      }

      .twofa-login-title {
        font-size: 18px;
        font-weight: 700;
        margin-bottom: 4px;
      }

      .twofa-login-desc {
        font-size: 12px;
        color: var(--text-secondary);
        margin-bottom: 20px;
      }

      .twofa-actions {
        display: flex;
        gap: 8px;
        margin-top: 12px;
      }

      .twofa-actions button {
        flex: 1;
        padding: 10px;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.15s;
      }

      .twofa-btn-enable {
        background: var(--accent);
        color: var(--bg-primary);
        border: none;
      }

      .twofa-btn-enable:hover {
        filter: brightness(1.1);
      }

      .twofa-btn-disable {
        background: transparent;
        color: var(--danger);
        border: 1px solid var(--danger);
      }

      .twofa-btn-disable:hover {
        background: rgba(255,71,87,0.08);
      }

      .twofa-btn-secondary {
        background: var(--bg-input);
        color: var(--text-primary);
        border: 1px solid var(--border-subtle);
      }

      .twofa-btn-secondary:hover {
        border-color: var(--text-secondary);
      }

      /* 步骤指示器 */
      .twofa-steps {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 4px;
        margin-bottom: 16px;
      }

      .twofa-step {
        width: 28px;
        height: 4px;
        border-radius: 2px;
        background: var(--border-subtle);
        transition: background 0.3s;
      }

      .twofa-step.active {
        background: var(--accent);
      }

      .twofa-step.done {
        background: var(--accent-dim);
      }
    `;
    document.head.appendChild(style);
  }

  // ── 检查2FA状态 ──
  async function _check2FAStatus() {
    try {
      const token = localStorage.getItem('fk_token');
      const res = await fetch(`${API_BASE}/auth/2fa/status`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        is2FAEnabled = data.enabled || false;
        _updateSettingsUI();
      }
    } catch (e) {
      // 后端可能尚未支持，静默处理
      console.warn('[2FA] Status check failed (backend may not support 2FA yet):', e.message);
    }
  }

  // ── 在设置面板中添加2FA区域 ──
  function _addSettingsSection() {
    // 延迟执行，等待 settings 模块渲染
    setTimeout(() => {
      const settingsSections = document.getElementById('settingsSections');
      if (!settingsSections) return;

      const section = document.createElement('div');
      section.className = 'settings-section';
      section.id = 'twofaSettingsSection';
      section.innerHTML = `
        <div class="settings-section-title">
          <span>Two-Factor Authentication</span>
        </div>
        <div class="twofa-card">
          <div class="twofa-card-title">
            <span class="twofa-status-badge ${is2FAEnabled ? 'enabled' : 'disabled'}" id="twofaStatusBadge">
              ${is2FAEnabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
          <div class="twofa-card-desc">
            ${is2FAEnabled
              ? 'Your account is protected with two-factor authentication. You\'ll need your authenticator app when logging in.'
              : (ENROLMENT_AVAILABLE
                ? 'Add an extra layer of security to your account. When enabled, you\'ll need both your password and an authenticator code to log in.'
                : ENROLMENT_UNAVAILABLE_HINT)}
          </div>
          <div class="twofa-actions" style="margin-top:12px">
            <button class="${is2FAEnabled ? 'twofa-btn-disable' : 'twofa-btn-enable'}" id="btnToggle2FA"${(!is2FAEnabled && !ENROLMENT_AVAILABLE) ? ' disabled title="' + ENROLMENT_UNAVAILABLE_HINT + '"' : ''}>
              ${is2FAEnabled ? 'Disable 2FA' : (ENROLMENT_AVAILABLE ? 'Enable 2FA' : 'Enable 2FA (coming soon)')}
            </button>
          </div>
        </div>
      `;

      settingsSections.appendChild(section);

      document.getElementById('btnToggle2FA')?.addEventListener('click', () => {
        if (is2FAEnabled) {
          _showDisableFlow();
        } else if (ENROLMENT_AVAILABLE) {
          _showSetupFlow();
        }
      });
    }, 500);
  }

  // ── 更新设置UI ──
  function _updateSettingsUI() {
    const badge = document.getElementById('twofaStatusBadge');
    const btn = document.getElementById('btnToggle2FA');
    const card = document.querySelector('#twofaSettingsSection .twofa-card-desc');

    if (badge) {
      badge.className = `twofa-status-badge ${is2FAEnabled ? 'enabled' : 'disabled'}`;
      badge.textContent = is2FAEnabled ? 'Enabled' : 'Disabled';
    }

    if (btn) {
      btn.className = is2FAEnabled ? 'twofa-btn-disable' : 'twofa-btn-enable';
      btn.textContent = is2FAEnabled ? 'Disable 2FA' : (ENROLMENT_AVAILABLE ? 'Enable 2FA' : 'Enable 2FA (coming soon)');
      if (!is2FAEnabled && !ENROLMENT_AVAILABLE) {
        btn.disabled = true;
        btn.title = ENROLMENT_UNAVAILABLE_HINT;
      } else {
        btn.disabled = false;
        btn.removeAttribute('title');
      }
    }

    if (card) {
      card.textContent = is2FAEnabled
        ? 'Your account is protected with two-factor authentication. You\'ll need your authenticator app when logging in.'
        : (ENROLMENT_AVAILABLE
          ? 'Add an extra layer of security to your account. When enabled, you\'ll need both your password and an authenticator code to log in.'
          : ENROLMENT_UNAVAILABLE_HINT);
    }
  }

  // ── 设置流程（3步） ──
  async function _showSetupFlow() {
    setupPhase = true;
    const modal = _create2FAModal();

    // The overlay has to be in the document BEFORE step 1 renders: step 1 looked its
    // nodes up with document.getElementById(), and a detached subtree is invisible to
    // that call. It threw "Cannot set properties of null (setting 'textContent')" and
    // left setupPhase=true with no modal on screen. Unreachable while enrolment was
    // disabled, which is why it survived unnoticed until the button came back.
    document.body.appendChild(modal.overlay);

    // Step 1: 生成密钥 + QR码
    _renderSetupStep1(modal);
  }

  async function _renderSetupStep1(modal) {
    const body = modal.bodyEl;
    body.innerHTML = `
      <div class="twofa-steps">
        <div class="twofa-step active"></div>
        <div class="twofa-step"></div>
        <div class="twofa-step"></div>
      </div>
      <div class="twofa-login-icon">🔐</div>
      <div class="twofa-login-title">Set Up Authenticator</div>
      <div class="twofa-login-desc">Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)</div>
      <div class="twofa-qr-container">
        <canvas class="twofa-qr-canvas" id="twofaQRCanvas"></canvas>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Or enter this key manually:</div>
        <div class="twofa-secret-key" id="twofaSecretDisplay">Loading...</div>
      </div>
      <div class="twofa-actions">
        <button class="twofa-btn-secondary" id="btn2FACancel">Cancel</button>
        <button class="twofa-btn-enable" id="btn2FANext">Next →</button>
      </div>
    `;

    body.querySelector('#btn2FACancel')?.addEventListener('click', () => _closeModal(modal));

    const username = localStorage.getItem('fk_uname') || 'user';

    // The secret comes from the server. POST /auth/2fa/enable stores it against
    // the account and returns the same secret behind the QR. Generating it in the
    // renderer made the scanned QR and the stored secret two different values:
    // the code from the app could never match, and confirm-enable was never called.
    let secret, uri;
    try {
      const token = localStorage.getItem('fk_token');
      const res = await fetch(`${API_BASE}/auth/2fa/enable`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({})
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg = data.error === 'E_2FA_DEVICE_IDENTITY_PENDING'
          ? '设备身份尚未就绪，请稍后重试'
          : (data.error || '无法开始 2FA 设置');
        showToast(msg, 'error');
        _closeModal(modal);
        return;
      }
      secret = data.secret;
      uri = data.uri;
      if (!secret) {
        showToast('服务器未返回 2FA 密钥', 'error');
        _closeModal(modal);
        return;
      }
    } catch (e) {
      showToast('无法连接服务器，2FA 设置未开始', 'error');
      _closeModal(modal);
      return;
    }

    const secretEl = body.querySelector('#twofaSecretDisplay');
    if (secretEl) secretEl.textContent = _formatSecretKey(secret);

    _generateQRCode(secret, username, body, uri);

    body.querySelector('#btn2FANext')?.addEventListener('click', () => _renderSetupStep2(modal));
  }

  function _renderSetupStep2(modal) {
    const body = modal.bodyEl;
    body.innerHTML = `
      <div class="twofa-steps">
        <div class="twofa-step done"></div>
        <div class="twofa-step active"></div>
        <div class="twofa-step"></div>
      </div>
      <div class="twofa-login-icon">✅</div>
      <div class="twofa-login-title">Verify Code</div>
      <div class="twofa-login-desc">Enter the 6-digit code from your authenticator app</div>
      <div class="twofa-code-input" id="twofaCodeInput">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="0" inputmode="numeric" pattern="[0-9]">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="1" inputmode="numeric" pattern="[0-9]">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="2" inputmode="numeric" pattern="[0-9]">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="3" inputmode="numeric" pattern="[0-9]">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="4" inputmode="numeric" pattern="[0-9]">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="5" inputmode="numeric" pattern="[0-9]">
      </div>
      <div class="twofa-actions">
        <button class="twofa-btn-secondary" id="btn2FABack">← Back</button>
        <button class="twofa-btn-enable" id="btn2FAVerify">Verify</button>
      </div>
    `;

    // 自动跳转 + 自动粘贴
    const digits = body.querySelectorAll('.twofa-code-digit');
    digits.forEach((input, i) => {
      input.addEventListener('input', (e) => {
        const val = e.target.value.replace(/[^0-9]/g, '');
        e.target.value = val.charAt(0) || '';
        if (val && i < digits.length - 1) {
          digits[i + 1].focus();
        }
        if (val) e.target.classList.add('filled');
        else e.target.classList.remove('filled');

        // 6位输满自动验证
        if (_getOTPValue().length === 6) {
          setTimeout(() => document.getElementById('btn2FAVerify')?.click(), 200);
        }
      });

      input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !e.target.value && i > 0) {
          digits[i - 1].focus();
          digits[i - 1].value = '';
          digits[i - 1].classList.remove('filled');
        }
      });

      // 支持粘贴完整6位码
      input.addEventListener('paste', (e) => {
        e.preventDefault();
        const pasted = (e.clipboardData || window.clipboardData).getData('text').replace(/[^0-9]/g, '');
        for (let j = 0; j < Math.min(pasted.length, 6); j++) {
          if (digits[j]) {
            digits[j].value = pasted[j];
            digits[j].classList.add('filled');
          }
        }
        if (pasted.length >= 6) {
          setTimeout(() => document.getElementById('btn2FAVerify')?.click(), 200);
        }
      });
    });

    digits[0]?.focus();

    document.getElementById('btn2FABack')?.addEventListener('click', () => _renderSetupStep1(modal));
    document.getElementById('btn2FAVerify')?.addEventListener('click', () => _verifyAndEnable(modal));
  }

  async function _verifyAndEnable(modal) {
    const code = _getOTPValue();
    if (code.length !== 6) {
      showToast('请输入6位验证码', 'error');
      return;
    }

    try {
      const token = localStorage.getItem('fk_token');
      const res = await fetch(`${API_BASE}/auth/2fa/confirm-enable`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ code })
      });
      const data = await res.json().catch(() => ({}));

      if (res.ok) {
        is2FAEnabled = true;
        _renderSetupStep3(modal, data.recoveryCodes || []);
      } else {
        showToast(data.error || '验证码错误，请重试', 'error');
      }
    } catch (e) {
      showToast('无法连接服务器，2FA 未启用', 'error');
    }
  }

  function _renderSetupStep3(modal, recoveryCodes) {
    const body = modal.bodyEl;
    const codesHTML = recoveryCodes.map(c => `<div class="twofa-recovery-code">${c}</div>`).join('');

    body.innerHTML = `
      <div class="twofa-steps">
        <div class="twofa-step done"></div>
        <div class="twofa-step done"></div>
        <div class="twofa-step active"></div>
      </div>
      <div class="twofa-login-icon">🎉</div>
      <div class="twofa-login-title">2FA Enabled!</div>
      <div class="twofa-login-desc">Save these recovery codes in a safe place. Each code can only be used once.</div>
      <div class="twofa-recovery-codes">${codesHTML}</div>
      <div class="twofa-recovery-warning">⚠️ 这些恢复码只在本次显示一次。请妥善保存，丢失后无法找回。</div>
      <div class="twofa-actions">
        <button class="twofa-btn-secondary" id="btn2FACopyCodes">📋 Copy Codes</button>
        <button class="twofa-btn-enable" id="btn2FADone">Done</button>
      </div>
    `;

    document.getElementById('btn2FACopyCodes')?.addEventListener('click', () => {
      navigator.clipboard.writeText(recoveryCodes.join('\n')).then(() => {
        showToast('恢复码已复制', 'success');
      });
    });

    document.getElementById('btn2FADone')?.addEventListener('click', () => {
      _closeModal(modal);
      _updateSettingsUI();
      showToast('2FA 已启用', 'success');
    });
  }

  // ── 禁用流程 ──
  function _showDisableFlow() {
    const modal = _create2FAModal('twofa-login-modal');
    const body = modal.bodyEl;

    body.innerHTML = `
      <div class="twofa-login-icon">⚠️</div>
      <div class="twofa-login-title">Disable 2FA?</div>
      <div class="twofa-login-desc">This will reduce your account security. Enter your authenticator code to confirm.</div>
      <div class="twofa-code-input" id="twofaDisableCodeInput">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="0" inputmode="numeric">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="1" inputmode="numeric">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="2" inputmode="numeric">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="3" inputmode="numeric">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="4" inputmode="numeric">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="5" inputmode="numeric">
      </div>
      <div class="twofa-actions">
        <button class="twofa-btn-secondary" id="btn2FACancelDisable">Cancel</button>
        <button class="twofa-btn-disable" id="btn2FAConfirmDisable">Disable 2FA</button>
      </div>
    `;

    // 输入逻辑同上
    const digits = body.querySelectorAll('.twofa-code-digit');
    digits.forEach((input, i) => {
      input.addEventListener('input', (e) => {
        const val = e.target.value.replace(/[^0-9]/g, '');
        e.target.value = val.charAt(0) || '';
        if (val && i < digits.length - 1) digits[i + 1].focus();
      });
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !e.target.value && i > 0) digits[i - 1].focus();
      });
      input.addEventListener('paste', (e) => {
        e.preventDefault();
        const pasted = (e.clipboardData || window.clipboardData).getData('text').replace(/[^0-9]/g, '');
        for (let j = 0; j < Math.min(pasted.length, 6); j++) {
          if (digits[j]) digits[j].value = pasted[j];
        }
      });
    });

    digits[0]?.focus();

    document.getElementById('btn2FACancelDisable')?.addEventListener('click', () => _closeModal(modal));
    document.getElementById('btn2FAConfirmDisable')?.addEventListener('click', async () => {
      const code = _getOTPValue();
      try {
        const token = localStorage.getItem('fk_token');
        const res = await fetch(`${API_BASE}/auth/2fa/disable`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ code })
        });
        if (res.ok) {
          is2FAEnabled = false;
          _closeModal(modal);
          _updateSettingsUI();
          showToast('2FA 已禁用', 'info');
        } else {
          showToast('验证码错误', 'error');
        }
      } catch (e) {
        showToast('无法连接服务器，2FA 未禁用', 'error');
      }
    });

    document.body.appendChild(modal.overlay);
  }

  // ── 登录时2FA验证（供登录流程调用） ──
  function showLogin2FA(username, ticket, onVerified) {
    const modal = _create2FAModal('twofa-login-modal');
    const body = modal.bodyEl;

    body.innerHTML = `
      <div class="twofa-login-icon">🔐</div>
      <div class="twofa-login-title">Two-Factor Auth</div>
      <div class="twofa-login-desc">Enter the code from your authenticator app for ${username}</div>
      <div class="twofa-code-input" id="twofaLoginCodeInput">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="0" inputmode="numeric">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="1" inputmode="numeric">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="2" inputmode="numeric">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="3" inputmode="numeric">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="4" inputmode="numeric">
        <input type="text" class="twofa-code-digit" maxlength="1" data-index="5" inputmode="numeric">
      </div>
      <div style="text-align:center;margin-top:4px">
        <a href="#" id="btn2FAUseRecovery" style="font-size:11px;color:var(--text-muted)">Use recovery code</a>
      </div>
      <div class="twofa-actions">
        <button class="twofa-btn-secondary" id="btn2FACancelLogin">Cancel</button>
        <button class="twofa-btn-enable" id="btn2FAVerifyLogin">Verify</button>
      </div>
    `;

    const digits = body.querySelectorAll('.twofa-code-digit');
    digits.forEach((input, i) => {
      input.addEventListener('input', (e) => {
        const val = e.target.value.replace(/[^0-9]/g, '');
        e.target.value = val.charAt(0) || '';
        if (val && i < digits.length - 1) digits[i + 1].focus();
      });
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !e.target.value && i > 0) digits[i - 1].focus();
      });
    });

    digits[0]?.focus();

    document.getElementById('btn2FACancelLogin')?.addEventListener('click', () => _closeModal(modal));
    document.getElementById('btn2FAVerifyLogin')?.addEventListener('click', async () => {
      const code = _getOTPValue();
      try {
        const res = await fetch(`${API_BASE}/auth/2fa/verify-login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ticket, code })
        });
        if (res.ok) {
          _closeModal(modal);
          if (onVerified) onVerified(await res.json());
        } else {
          showToast('验证码错误', 'error');
        }
      } catch (e) {
        showToast('验证失败', 'error');
      }
    });

    document.body.appendChild(modal.overlay);
  }

  // ── QR code generation (vendored qrcode-generator, MIT) ──
  function _generateQRCode(secret, username, scope, uri) {
    const canvas = (scope || document).querySelector('#twofaQRCanvas');
    if (!canvas) return;

    // Prefer the URI the server built and stored; fall back to the same fields
    // only if an older server did not return one.
    const otpauth = uri || `otpauth://totp/FIBEMATE:${encodeURIComponent(username)}?secret=${encodeURIComponent(secret)}&issuer=FIBEMATE&algorithm=SHA1&digits=6&period=30`;

    // A real QR encoder, not a decorative pattern. qrcode-generator is vendored
    // under src/vendor (MIT); qrcode_UTF8.js extends it so non-ASCII usernames
    // are encoded as UTF-8 bytes.
    if (typeof qrcode !== 'function') {
      canvas.title = otpauth;
      console.error('[2FA] qrcode-generator is not loaded; the QR cannot be drawn');
      return;
    }

    try {
      const qr = qrcode(0, 'M');
      qr.addData(otpauth);
      qr.make();
      const dataUrl = qr.createDataURL(4, 4);
      const img = new Image();
      img.onload = () => {
        canvas.width = img.naturalWidth || img.width;
        canvas.height = img.naturalHeight || img.height;
        const ctx = canvas.getContext('2d');
        ctx.imageSmoothingEnabled = false;
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0);
      };
      img.onerror = () => {
        canvas.title = otpauth;
        console.error('[2FA] QR image failed to render');
      };
      img.src = dataUrl;
    } catch (e) {
      canvas.title = otpauth;
      console.error('[2FA] QR generation failed:', e);
    }

    canvas.title = otpauth;
    canvas.style.cursor = 'pointer';
    canvas.onclick = () => {
      navigator.clipboard.writeText(otpauth).then(() => {
        showToast('OTP URI 已复制', 'success');
      });
    };
  }

  // ── 工具函数 ──
  function _getOTPValue() {
    const digits = document.querySelectorAll('.twofa-code-digit');
    return Array.from(digits).map(d => d.value).join('');
  }

  function _formatSecretKey(secret) {
    return secret.match(/.{1,4}/g)?.join(' ') || secret;
  }

  function _create2FAModal(extraClass = '') {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay twofa-login-modal';
    overlay.style.display = 'flex';

    const modal = document.createElement('div');
    modal.className = `modal ${extraClass}`.trim();

    const body = document.createElement('div');
    body.className = 'twofa-setup-panel';
    modal.appendChild(body);

    overlay.appendChild(modal);

    // 点击遮罩关闭
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) _closeModal({ overlay });
    });

    return { overlay, bodyEl: body };
  }

  function _closeModal(modal) {
    if (modal?.overlay) modal.overlay.remove();
    setupPhase = false;
  }

  // ── 公共 API ──
  return {
    init,
    showLogin2FA,
    isEnabled: () => is2FAEnabled
  };
})();
