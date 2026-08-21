/**
 * FIBEMATE Read Receipts Module
 * 已读回执 — 显示消息已读/未读状态
 *
 * 功能：
 * - 消息状态：发送中 → 已发送 → 已送达 → 已读
 * - 隐私模式：可关闭已读回执（对方看不到你的阅读状态）
 * - 实时 WebSocket 同步
 * - 消息气泡底部状态图标
 * - 批量已读标记（进入对话时标记全部）
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

const ReadReceipts = (() => {
  // ── 消息状态枚举 ──
  const MSG_STATUS = {
    SENDING:   { icon: '⏳', label: 'Sending',    color: 'var(--text-muted)',  order: 0 },
    SENT:      { icon: '✓',  label: 'Sent',       color: 'var(--text-muted)',  order: 1 },
    DELIVERED: { icon: '✓✓', label: 'Delivered',  color: 'var(--text-secondary)', order: 2 },
    READ:      { icon: '✓✓', label: 'Read',       color: 'var(--accent)',      order: 3 }
  };

  // ── 状态 ──
  let receiptEnabled = true;       // 是否发送已读回执
  let receiptPrivacyMode = false;  // 隐私模式（不自动发送已读）
  let pendingReads = new Set();    // 待标记已读的消息ID
  let readDebounceTimer = null;

  // ── 初始化 ──
  function init() {
    _injectStyles();
    _loadPreferences();
    _addSettingsToggle();
    _bindScrollEvent();
    _bindWebSocketHandler();
    console.log('[ReadReceipts] Module initialized');
  }

  // ── 注入样式 ──
  function _injectStyles() {
    const style = document.createElement('style');
    style.id = 'read-receipts-styles';
    style.textContent = `
      /* 消息状态图标 */
      .msg-status-indicator {
        display: inline-flex;
        align-items: center;
        gap: 2px;
        font-size: 12px;
        font-weight: 700;
        margin-left: 4px;
        transition: color 0.3s;
      }

      .msg-status-indicator.sending {
        color: var(--text-muted);
        opacity: 0.5;
      }

      .msg-status-indicator.sent {
        color: var(--text-muted);
      }

      .msg-status-indicator.delivered {
        color: var(--text-secondary);
      }

      .msg-status-indicator.read {
        color: var(--accent);
      }

      /* 双勾样式 */
      .msg-status-checks {
        position: relative;
        display: inline-flex;
        width: 16px;
        height: 10px;
      }

      .msg-status-checks svg {
        width: 12px;
        height: 10px;
      }

      .msg-status-checks.double svg:last-child {
        position: absolute;
        left: 4px;
        top: 0;
      }

      /* 消息时间行增强（含状态） */
      .msg-time {
        display: flex;
        align-items: center;
        gap: 4px;
      }

      /* 已读回执设置 */
      .read-receipt-toggle {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 0;
        border-bottom: 1px solid var(--border-subtle);
      }

      .read-receipt-toggle-label {
        font-size: 13px;
      }

      .read-receipt-toggle-desc {
        font-size: 11px;
        color: var(--text-muted);
        margin-top: 2px;
      }

      /* 开关组件 */
      .toggle-switch {
        position: relative;
        width: 44px;
        height: 24px;
        flex-shrink: 0;
      }

      .toggle-switch input {
        opacity: 0;
        width: 0;
        height: 0;
      }

      .toggle-slider {
        position: absolute;
        cursor: pointer;
        inset: 0;
        background: var(--bg-input);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        transition: all 0.2s;
      }

      .toggle-slider::before {
        content: '';
        position: absolute;
        width: 18px;
        height: 18px;
        left: 2px;
        top: 2px;
        background: var(--text-secondary);
        border-radius: 50%;
        transition: all 0.2s;
      }

      .toggle-switch input:checked + .toggle-slider {
        background: var(--accent-dim);
        border-color: var(--accent);
      }

      .toggle-switch input:checked + .toggle-slider::before {
        transform: translateX(20px);
        background: var(--accent);
      }

      /* 隐私模式标记 */
      .privacy-badge {
        font-size: 9px;
        padding: 1px 6px;
        border-radius: 4px;
        background: rgba(255,165,2,0.1);
        color: #FFA502;
        margin-left: 6px;
      }
    `;
    document.head.appendChild(style);
  }

  // ── 加载偏好 ──
  function _loadPreferences() {
    const saved = localStorage.getItem('fk_read_receipts');
    if (saved !== null) receiptEnabled = saved === 'true';

    const privacy = localStorage.getItem('fk_receipt_privacy');
    if (privacy !== null) receiptPrivacyMode = privacy === 'true';
  }

  // ── 设置面板开关 ──
  function _addSettingsToggle() {
    setTimeout(() => {
      const settingsSections = document.getElementById('settingsSections');
      if (!settingsSections) return;

      const section = document.createElement('div');
      section.className = 'settings-section';
      section.id = 'readReceiptSettings';
      section.innerHTML = `
        <div class="settings-section-title">
          <span>👁️</span>
          <span>Read Receipts</span>
        </div>
        <div class="read-receipt-toggle">
          <div>
            <div class="read-receipt-toggle-label">Send Read Receipts</div>
            <div class="read-receipt-toggle-desc">Let others know when you've read their messages</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" id="toggleReadReceipts" ${receiptEnabled ? 'checked' : ''}>
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="read-receipt-toggle">
          <div>
            <div class="read-receipt-toggle-label">
              Privacy Mode
              <span class="privacy-badge" id="privacyModeBadge" style="${receiptPrivacyMode ? '' : 'display:none'}">ON</span>
            </div>
            <div class="read-receipt-toggle-desc">Don't auto-send receipts — only when you manually mark</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" id="toggleReceiptPrivacy" ${receiptPrivacyMode ? 'checked' : ''}>
            <span class="toggle-slider"></span>
          </label>
        </div>
      `;

      settingsSections.appendChild(section);

      document.getElementById('toggleReadReceipts')?.addEventListener('change', (e) => {
        receiptEnabled = e.target.checked;
        localStorage.setItem('fk_read_receipts', receiptEnabled);
        showToast(receiptEnabled ? 'Read receipts enabled' : 'Read receipts disabled', 'info');
      });

      document.getElementById('toggleReceiptPrivacy')?.addEventListener('change', (e) => {
        receiptPrivacyMode = e.target.checked;
        localStorage.setItem('fk_receipt_privacy', receiptPrivacyMode);
        const badge = document.getElementById('privacyModeBadge');
        if (badge) badge.style.display = receiptPrivacyMode ? '' : 'none';
        showToast(receiptPrivacyMode ? 'Privacy mode on' : 'Privacy mode off', 'info');
      });
    }, 600);
  }

  // ── 绑定滚动事件（自动标记已读） ──
  function _bindScrollEvent() {
    const messagesList = document.getElementById('messagesList');
    if (!messagesList) return;

    messagesList.addEventListener('scroll', () => {
      if (receiptPrivacyMode || !receiptEnabled) return;
      _debounceMarkVisibleAsRead();
    });
  }

  // ── 防抖标记可见消息为已读 ──
  function _debounceMarkVisibleAsRead() {
    clearTimeout(readDebounceTimer);
    readDebounceTimer = setTimeout(() => {
      _markVisibleMessagesAsRead();
    }, 500);
  }

  function _markVisibleMessagesAsRead() {
    const messagesList = document.getElementById('messagesList');
    if (!messagesList) return;

    const receivedMsgs = messagesList.querySelectorAll('.message.received:not(.recalled)');
    const messageIds = [];

    receivedMsgs.forEach(msg => {
      const rect = msg.getBoundingClientRect();
      const listRect = messagesList.getBoundingClientRect();

      // 消息在可视区域内
      if (rect.top >= listRect.top - 50 && rect.bottom <= listRect.bottom + 50) {
        const msgId = msg.dataset.messageId;
        if (msgId && !msg.dataset.read) {
          messageIds.push(msgId);
          msg.dataset.read = 'true';
        }
      }
    });

    if (messageIds.length > 0) {
      _sendReadReceipts(messageIds);
    }
  }

  // ── 发送已读回执 ──
  function _sendReadReceipts(messageIds) {
    if (!receiptEnabled || !STATE.currentPeerId) return;

    const payload = {
      type: 'read_receipt',
      messageIds,
      conversationId: STATE.currentConversationId,
      to: STATE.currentPeerId,
      readAt: Date.now()
    };

    // WebSocket 发送
    if (STATE.ws && STATE.ws.readyState === WebSocket.OPEN) {
      STATE.ws.send(JSON.stringify(payload));
    }

    // REST 备选
    try {
      const token = localStorage.getItem('fk_token');
      fetch(`${API_BASE}/messages/read`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ messageIds, conversationId: STATE.currentConversationId })
      }).catch(() => {});
    } catch (e) {}

    console.log(`[ReadReceipts] Marked ${messageIds.length} messages as read`);
  }

  // ── 更新消息状态图标 ──
  function updateMessageStatus(msgEl, status) {
    if (!msgEl) return;

    const statusInfo = MSG_STATUS[status];
    if (!statusInfo) return;

    // 查找或创建状态指示器
    let indicator = msgEl.querySelector('.msg-status-indicator');
    if (!indicator) {
      indicator = document.createElement('span');
      indicator.className = 'msg-status-indicator';

      const timeEl = msgEl.querySelector('.msg-time');
      if (timeEl) {
        timeEl.appendChild(indicator);
      }
    }

    indicator.className = `msg-status-indicator ${status.toLowerCase()}`;

    switch (status) {
      case 'SENDING':
        indicator.innerHTML = '⏳';
        break;
      case 'SENT':
        indicator.innerHTML = '✓';
        break;
      case 'DELIVERED':
        indicator.innerHTML = '<span class="msg-status-checks double"><svg viewBox="0 0 12 10" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 5l3 3 7-7"/></svg><svg viewBox="0 0 12 10" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 5l3 3 7-7"/></svg></span>';
        break;
      case 'READ':
        indicator.innerHTML = '<span class="msg-status-checks double" style="color:var(--accent)"><svg viewBox="0 0 12 10" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 5l3 3 7-7"/></svg><svg viewBox="0 0 12 10" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 5l3 3 7-7"/></svg></span>';
        break;
    }
  }

  // ── 处理收到的已读回执 ──
  function _handleReadReceipt(data) {
    const messageIds = data.messageIds || [];
    if (messageIds.length === 0) return;

    const messagesList = document.getElementById('messagesList');
    if (!messagesList) return;

    // 更新发送消息的状态为已读
    const sentMsgs = messagesList.querySelectorAll('.message.sent');
    sentMsgs.forEach(msg => {
      const msgId = msg.dataset.messageId;
      if (msgId && messageIds.includes(msgId)) {
        updateMessageStatus(msg, 'READ');
      }
    });

    // 如果是批量已读，将所有已送达消息标记为已读
    if (data.allRead) {
      sentMsgs.forEach(msg => {
        const indicator = msg.querySelector('.msg-status-indicator');
        if (indicator && (indicator.classList.contains('delivered') || indicator.classList.contains('sent'))) {
          updateMessageStatus(msg, 'READ');
        }
      });
    }
  }

  // ── WebSocket 处理 ──
  function _bindWebSocketHandler() {
    document.addEventListener('ws-read-receipt', (e) => {
      _handleReadReceipt(e.detail);
    });
  }

  // ── 增强发送流程：消息发送后更新状态 ──
  function trackMessage(msgEl) {
    if (!msgEl) return;

    // 初始状态：发送中
    updateMessageStatus(msgEl, 'SENDING');

    // 500ms后：已发送
    setTimeout(() => {
      if (msgEl.isConnected) {
        updateMessageStatus(msgEl, 'SENT');
      }
    }, 500);

    // 2s后：已送达（假设WebSocket已连接）
    setTimeout(() => {
      if (msgEl.isConnected && STATE.ws?.readyState === WebSocket.OPEN) {
        updateMessageStatus(msgEl, 'DELIVERED');
      }
    }, 2000);
  }

  // ── 打开对话时批量标记已读 ──
  function markConversationAsRead() {
    if (receiptPrivacyMode || !receiptEnabled) return;

    const messagesList = document.getElementById('messagesList');
    if (!messagesList) return;

    const messageIds = [];
    messagesList.querySelectorAll('.message.received:not(.recalled)').forEach(msg => {
      const msgId = msg.dataset.messageId;
      if (msgId && !msg.dataset.read) {
        messageIds.push(msgId);
        msg.dataset.read = 'true';
      }
    });

    if (messageIds.length > 0) {
      _sendReadReceipts(messageIds);
    }
  }

  // ── 公共 API ──
  return {
    init,
    updateMessageStatus,
    trackMessage,
    markConversationAsRead,
    isEnabled: () => receiptEnabled,
    isPrivacyMode: () => receiptPrivacyMode
  };
})();
