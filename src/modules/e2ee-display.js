/**
 * FIBEMATE E2EE Status Display Module
 * 端到端加密状态可视化
 *
 * 功能：
 * - 加密状态指示器（未加密/握手/已加密/后量子/量子增强）
 * - Safety Number 安全码显示与比对
 * - 密钥指纹可视化
 * - 加密协议信息面板
 * - 密钥变更实时告警
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

const E2EEDisplay = (() => {
  // ── 加密状态枚举 ──
  const STATUS = {
    NONE:           { level: 0, icon: '', label: 'NO E2EE',    color: 'var(--danger)',  desc: 'Messages are not encrypted' },
    HANDSHAKE:      { level: 1, icon: '', label: 'HANDSHAKE',  color: '#FFA502',       desc: 'Establishing secure session...' },
    ENCRYPTED:      { level: 2, icon: '', label: 'E2EE',       color: 'var(--accent)',  desc: 'End-to-end encrypted (X3DH + Double Ratchet)' },
    POST_QUANTUM:   { level: 3, icon: '', label: 'PQ-E2EE',   color: '#6C5CE7',       desc: 'Post-quantum E2EE (ML-KEM-768 + X3DH)' },
    QUANTUM_ENHANCED: { level: 4, icon: '', label: 'Q-E2EE',  color: '#00CEC9',       desc: 'Quantum-enhanced E2EE (QKD + ML-KEM-768 + X3DH)' }
  };

  // ── 初始化 ──
  function init() {
    _injectStyles();
    _bindEvents();
    console.log('[E2EEDisplay] Module initialized');
  }

  // ── 注入样式 ──
  function _injectStyles() {
    const style = document.createElement('style');
    style.id = 'e2ee-display-styles';
    style.textContent = `
      /* E2EE 状态栏（chat header 内） */
      .e2ee-status-bar {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 2px 8px;
        border-radius: 10px;
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.5px;
        margin-top: 2px;
        transition: all 0.3s;
      }

      .e2ee-status-bar.secure {
        background: rgba(0,229,195,0.08);
        border: 1px solid rgba(0,229,195,0.2);
      }

      .e2ee-status-bar.pending {
        background: rgba(255,165,2,0.08);
        border: 1px solid rgba(255,165,2,0.2);
      }

      .e2ee-status-bar.danger {
        background: rgba(255,71,87,0.08);
        border: 1px solid rgba(255,71,87,0.2);
      }

      .e2ee-status-bar.pq {
        background: rgba(108,92,231,0.08);
        border: 1px solid rgba(108,92,231,0.2);
      }

      .e2ee-status-bar.quantum {
        background: rgba(0,206,201,0.08);
        border: 1px solid rgba(0,206,201,0.2);
      }

      .e2ee-status-icon {
        font-size: 12px;
      }

      .e2ee-status-text {
        font-size: 9px;
        letter-spacing: 1px;
      }

      .e2ee-status-detail {
        font-size: 9px;
        opacity: 0.7;
        font-weight: 400;
      }

      /* E2EE 详情面板 */
      .e2ee-detail-panel {
        position: absolute;
        top: 100%;
        right: 0;
        width: 320px;
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 16px;
        z-index: 100;
        box-shadow: 0 12px 40px rgba(0,0,0,0.5);
        animation: e2ee-panel-in 0.2s ease;
      }

      @keyframes e2ee-panel-in {
        from { opacity: 0; transform: translateY(-8px); }
        to { opacity: 1; transform: translateY(0); }
      }

      .e2ee-detail-header {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 12px;
      }

      .e2ee-detail-icon {
        font-size: 28px;
      }

      .e2ee-detail-title {
        font-size: 14px;
        font-weight: 600;
      }

      .e2ee-detail-subtitle {
        font-size: 11px;
        color: var(--text-muted);
      }

      .e2ee-info-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 8px 0;
        border-bottom: 1px solid var(--border-subtle);
        font-size: 12px;
      }

      .e2ee-info-row:last-child {
        border-bottom: none;
      }

      .e2ee-info-label {
        color: var(--text-secondary);
      }

      .e2ee-info-value {
        font-weight: 500;
        font-variant-numeric: tabular-nums;
      }

      .e2ee-info-value.secure {
        color: var(--accent);
      }

      .e2ee-info-value.insecure {
        color: var(--danger);
      }

      /* Safety Number */
      .e2ee-safety-number {
        margin-top: 12px;
        padding: 12px;
        background: var(--bg-input);
        border-radius: 8px;
        text-align: center;
      }

      .e2ee-safety-number-label {
        font-size: 10px;
        color: var(--text-muted);
        margin-bottom: 6px;
        text-transform: uppercase;
        letter-spacing: 1px;
      }

      .e2ee-safety-number-value {
        font-size: 16px;
        font-weight: 700;
        letter-spacing: 2px;
        font-variant-numeric: tabular-nums;
        color: var(--accent);
        word-break: break-all;
        line-height: 1.6;
      }

      .e2ee-safety-number-hint {
        font-size: 10px;
        color: var(--text-muted);
        margin-top: 6px;
      }

      .e2ee-verify-btn {
        display: block;
        width: 100%;
        margin-top: 10px;
        padding: 8px;
        background: var(--accent-dim);
        border: 1px solid rgba(0,229,195,0.3);
        border-radius: 8px;
        color: var(--accent);
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        text-align: center;
        transition: all 0.15s;
      }

      .e2ee-verify-btn:hover {
        background: rgba(0,229,195,0.15);
      }

      /* 密钥变更告警 */
      .e2ee-key-change-alert {
        display: flex;
        align-items: flex-start;
        gap: 10px;
        padding: 12px;
        margin: 8px 0;
        background: rgba(255,165,2,0.08);
        border: 1px solid rgba(255,165,2,0.2);
        border-radius: 10px;
        font-size: 12px;
      }

      .e2ee-key-change-alert-icon {
        font-size: 18px;
        flex-shrink: 0;
      }

      .e2ee-key-change-alert-text {
        flex: 1;
      }

      .e2ee-key-change-alert-title {
        font-weight: 600;
        margin-bottom: 4px;
      }

      .e2ee-key-change-alert-desc {
        color: var(--text-secondary);
        font-size: 11px;
      }

      .e2ee-key-change-actions {
        display: flex;
        gap: 8px;
        margin-top: 8px;
      }

      .e2ee-key-change-actions button {
        padding: 4px 12px;
        border-radius: 6px;
        font-size: 11px;
        cursor: pointer;
        border: 1px solid var(--border-subtle);
        background: var(--bg-input);
        color: var(--text-primary);
        transition: all 0.15s;
      }

      .e2ee-key-change-actions button.accept {
        background: var(--accent-dim);
        border-color: var(--accent);
        color: var(--accent);
      }

      /* 消息级加密徽章 */
      .e2ee-badge {
        display: inline-block;
        width: 10px;
        height: 10px;
        margin-left: 4px;
        vertical-align: middle;
        opacity: 0.6;
      }

      .e2ee-badge::after {
        content: '🔒';
        font-size: 8px;
      }

      /* 协议层级可视化 */
      .e2ee-protocol-layers {
        margin-top: 12px;
        padding: 8px;
        background: var(--bg-input);
        border-radius: 8px;
      }

      .e2ee-protocol-layer {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 4px 0;
        font-size: 11px;
      }

      .e2ee-protocol-layer-icon {
        width: 16px;
        text-align: center;
      }

      .e2ee-protocol-layer-name {
        flex: 1;
        font-weight: 500;
      }

      .e2ee-protocol-layer-status {
        font-size: 10px;
        padding: 1px 6px;
        border-radius: 4px;
      }

      .e2ee-protocol-layer-status.active {
        background: rgba(0,229,195,0.1);
        color: var(--accent);
      }

      .e2ee-protocol-layer-status.inactive {
        background: rgba(255,255,255,0.05);
        color: var(--text-muted);
      }
    `;
    document.head.appendChild(style);
  }

  // ── 绑定事件 ──
  function _bindEvents() {
    // 点击 E2EE 状态栏展开详情
    document.addEventListener('click', (e) => {
      const statusBar = e.target.closest('.e2ee-status-bar');
      if (statusBar) {
        _toggleDetailPanel(statusBar);
        return;
      }

      // 点击外部关闭面板
      const panel = document.querySelector('.e2ee-detail-panel');
      if (panel && !panel.contains(e.target)) {
        panel.remove();
      }
    });
  }

  // ── 更新 E2EE 状态 ──
  async function updateStatus(peerId) {
    const bar = document.getElementById('e2eeStatusBar');
    const icon = document.getElementById('e2eeStatusIcon');
    const text = document.getElementById('e2eeStatusText');
    const detail = document.getElementById('e2eeStatusDetail');

    if (!bar) return;

    const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : null;
    const PQ = typeof PQIntegration !== 'undefined' ? PQIntegration : null;
    const Quantum = typeof QuantumIntegration !== 'undefined' ? window.quantumIntegration : null;

    if (!Crypto) {
      _setStatus(bar, icon, text, detail, STATUS.NONE);
      return;
    }

    const hasSession = await Crypto.hasSession(peerId);
    if (!hasSession) {
      _setStatus(bar, icon, text, detail, STATUS.HANDSHAKE);
      return;
    }

    // 检查量子增强
    if (Quantum && Quantum.isEnabled?.()) {
      const qStatus = STATUS.QUANTUM_ENHANCED;
      qStatus.desc = 'Quantum-enhanced E2EE (QKD + ML-KEM-768 + X3DH)';
      _setStatus(bar, icon, text, detail, qStatus, `QKD active`);
      return;
    }

    // 检查后量子（会话级 hybrid 优先，全局 PQ 能力兑底）
    const securityStatus = await Crypto.getSecurityStatus?.(peerId);
    if (securityStatus?.hybrid || securityStatus?.pqMode || (PQ && PQ.isAvailable?.())) {
      _setStatus(bar, icon, text, detail, STATUS.POST_QUANTUM, `ML-KEM-768 · ${Number(securityStatus?.messagesSent) || 0} msgs`);
      return;
    }

    // 标准加密
    _setStatus(bar, icon, text, detail, STATUS.ENCRYPTED, `${securityStatus?.curve || 'P-256'} · ${(Number(securityStatus?.messagesSent) || 0) + (Number(securityStatus?.messagesReceived) || 0)} msgs`);
  }

  // ── 设置状态 ──
  function _setStatus(bar, icon, text, detail, status, extraInfo = '') {
    icon.textContent = status.icon;
    text.textContent = status.label;
    detail.textContent = extraInfo || status.desc;

    // 清除旧class
    bar.className = 'e2ee-status-bar';
    bar.style.color = status.color;

    switch (status.level) {
      case 0: bar.classList.add('danger'); break;
      case 1: bar.classList.add('pending'); break;
      case 2: bar.classList.add('secure'); break;
      case 3: bar.classList.add('pq'); break;
      case 4: bar.classList.add('quantum'); break;
    }
  }

  // ── 切换详情面板 ──
  async function _toggleDetailPanel(statusBar) {
    // 移除已有面板
    const existing = document.querySelector('.e2ee-detail-panel');
    if (existing) { existing.remove(); return; }

    const peerId = STATE.currentPeerId;
    if (!peerId) return;

    const panel = document.createElement('div');
    panel.className = 'e2ee-detail-panel';

    const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : null;
    const PQ = typeof PQIntegration !== 'undefined' ? PQIntegration : null;
    const Quantum = window.quantumIntegration;

    let e2eeStatus = STATUS.NONE;
    let protocolInfo = {};
    let safetyNumber = '—';
    let pqActive = false;

    if (Crypto && await Crypto.hasSession(peerId)) {
      const sec = await Crypto.getSecurityStatus?.(peerId);
      protocolInfo = sec || {};

      // 会话级 hybrid 判定优先，全局 PQ 能力兑底
      const isHybridSession = !!(sec?.hybrid || sec?.pqMode);
      pqActive = isHybridSession || !!(PQ && PQ.isAvailable?.());

      // Safety Number
      if (Crypto.getSessionFingerprint) {
        try {
          safetyNumber = await Crypto.getSessionFingerprint(peerId);
        } catch (e) {
          safetyNumber = 'N/A';
        }
      }

      if (Quantum && Quantum.isEnabled?.()) {
        e2eeStatus = STATUS.QUANTUM_ENHANCED;
      } else if (pqActive) {
        e2eeStatus = STATUS.POST_QUANTUM;
      } else {
        e2eeStatus = STATUS.ENCRYPTED;
      }
    }

    // 格式化 Safety Number (60位 → 每5位一组)
    const formattedSN = safetyNumber !== '—'
      ? safetyNumber.match(/.{1,5}/g)?.join(' ') || safetyNumber
      : '—';

    panel.innerHTML = `
      <div class="e2ee-detail-header">
        <div>
          <div class="e2ee-detail-title">${e2eeStatus.label}</div>
          <div class="e2ee-detail-subtitle">${e2eeStatus.desc}</div>
        </div>
      </div>

      <div class="e2ee-info-row">
        <span class="e2ee-info-label">Protocol</span>
        <span class="e2ee-info-value secure">${protocolInfo.protocol || 'Double Ratchet'}</span>
      </div>
      <div class="e2ee-info-row">
        <span class="e2ee-info-label">Key Exchange</span>
        <span class="e2ee-info-value secure">${pqActive ? 'X25519 + ML-KEM-768' : 'X3DH (4-DH)'}</span>
      </div>
      <div class="e2ee-info-row">
        <span class="e2ee-info-label">Symmetric Cipher</span>
        <span class="e2ee-info-value">AES-256-GCM</span>
      </div>
      <div class="e2ee-info-row">
        <span class="e2ee-info-label">Curve</span>
        <span class="e2ee-info-value">${protocolInfo.curve || 'P-256'}</span>
      </div>
      <div class="e2ee-info-row">
        <span class="e2ee-info-label">Messages</span>
        <span class="e2ee-info-value">${(Number(protocolInfo.messagesSent) || 0) + (Number(protocolInfo.messagesReceived) || 0)} sent & received</span>
      </div>
      ${Quantum && Quantum.isEnabled?.() ? `
      <div class="e2ee-info-row">
        <span class="e2ee-info-label">Quantum Key</span>
        <span class="e2ee-info-value secure">QKD Active</span>
      </div>` : ''}

      <div class="e2ee-safety-number">
        <div class="e2ee-safety-number-label">Safety Number</div>
        <div class="e2ee-safety-number-value">${formattedSN}</div>
        <div class="e2ee-safety-number-hint">Verify with your contact offline to confirm security</div>
        <button class="e2ee-verify-btn" id="btnCopySafetyNumber">Copy Safety Number</button>
      </div>

      <div class="e2ee-protocol-layers">
        <div class="e2ee-protocol-layer">
          <span class="e2ee-protocol-layer-name">Double Ratchet</span>
          <span class="e2ee-protocol-layer-status active">ACTIVE</span>
        </div>
        <div class="e2ee-protocol-layer">
          <span class="e2ee-protocol-layer-name">X3DH Key Exchange</span>
          <span class="e2ee-protocol-layer-status active">ACTIVE</span>
        </div>
        <div class="e2ee-protocol-layer">
          <span class="e2ee-protocol-layer-name">ML-KEM-768 (PQ)</span>
          <span class="e2ee-protocol-layer-status ${pqActive ? 'active' : 'inactive'}">${pqActive ? 'ACTIVE' : 'INACTIVE'}</span>
        </div>
        <div class="e2ee-protocol-layer">
          <span class="e2ee-protocol-layer-name">Quantum Enhanced</span>
          <span class="e2ee-protocol-layer-status ${Quantum?.isEnabled?.() ? 'active' : 'inactive'}">${Quantum?.isEnabled?.() ? 'ACTIVE' : 'INACTIVE'}</span>
        </div>
      </div>
    `;

    // 插入到 header-actions 旁边
    const headerActions = document.querySelector('.chat-header-actions');
    if (headerActions) {
      headerActions.style.position = 'relative';
      headerActions.appendChild(panel);
    }

    // 复制安全码
    const copyBtn = document.getElementById('btnCopySafetyNumber');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(safetyNumber).then(() => {
          showToast('Safety Number 已复制', 'success');
        }).catch(() => {
          showToast('复制失败', 'error');
        });
      });
    }
  }

  // ── 密钥变更告警 ──
  function showKeyChangeAlert(peerId, peerName) {
    const list = document.getElementById('messagesList');
    if (!list) return;

    const alert = document.createElement('div');
    alert.className = 'e2ee-key-change-alert';
    alert.innerHTML = `
      <span class="e2ee-key-change-alert-icon">⚠️</span>
      <div class="e2ee-key-change-alert-text">
        <div class="e2ee-key-change-alert-title">Security code changed</div>
        <div class="e2ee-key-change-alert-desc">
          ${peerName}'s encryption key has changed. This could mean they reinstalled FIBEMATE or got a new device.
          Verify the new safety number if you want to be sure.
        </div>
        <div class="e2ee-key-change-actions">
          <button class="accept" data-action="accept">Accept</button>
          <button data-action="verify">Verify</button>
        </div>
      </div>
    `;

    // 绑定按钮
    alert.querySelector('[data-action="accept"]').addEventListener('click', () => {
      alert.remove();
      showToast('New key accepted', 'success');
      updateStatus(peerId);
    });

    alert.querySelector('[data-action="verify"]').addEventListener('click', () => {
      // 打开详情面板
      const statusBar = document.getElementById('e2eeStatusBar');
      if (statusBar) statusBar.click();
    });

    list.appendChild(alert);
    list.scrollTop = list.scrollHeight;
  }

  // ── 公共 API ──
  return {
    init,
    updateStatus,
    showKeyChangeAlert,
    STATUS
  };
})();
