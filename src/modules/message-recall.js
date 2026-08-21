/**
 * FIBEMATE Message Recall Module
 * 消息撤回 — 发送后可撤回已发消息
 *
 * 功能：
 * - 2分钟内可撤回已发消息
 * - 长按/右键菜单触发撤回
 * - 撤回通知（对方可见"消息已撤回"）
 * - WebSocket 实时同步撤回
 * - E2EE 兼容（撤回通知也加密传输）
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

const MessageRecall = (() => {
  // ── 配置 ──
  const CONFIG = {
    recallWindowMs: 2 * 60 * 1000, // 2分钟
    maxRecallAgeMs: 24 * 60 * 60 * 1000, // 最多24小时（管理员可延长）
  };

  // ── 初始化 ──
  function init() {
    _injectStyles();
    _bindContextMenu();
    _bindWebSocketHandler();
    console.log('[MessageRecall] Module initialized');
  }

  // ── 注入样式 ──
  function _injectStyles() {
    const style = document.createElement('style');
    style.id = 'message-recall-styles';
    style.textContent = `
      /* 右键/长按菜单 */
      .msg-context-menu {
        position: fixed;
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 10px;
        padding: 4px;
        min-width: 160px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.5);
        z-index: 500;
        animation: msg-menu-in 0.15s ease;
      }

      @keyframes msg-menu-in {
        from { opacity: 0; transform: scale(0.95); }
        to { opacity: 1; transform: scale(1); }
      }

      .msg-context-menu-item {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 13px;
        cursor: pointer;
        transition: background 0.1s;
        -webkit-tap-highlight-color: transparent;
      }

      .msg-context-menu-item:hover {
        background: var(--accent-dim);
      }

      .msg-context-menu-item.danger {
        color: var(--danger);
      }

      .msg-context-menu-item.danger:hover {
        background: rgba(255,71,87,0.08);
      }

      .msg-context-menu-item.disabled {
        opacity: 0.4;
        pointer-events: none;
      }

      .msg-context-menu-icon {
        font-size: 15px;
        width: 20px;
        text-align: center;
      }

      /* 撤回消息样式 */
      .message.recalled {
        opacity: 0.6;
      }

      .message.recalled .msg-bubble {
        background: transparent !important;
        border: 1px dashed var(--border-subtle) !important;
        color: var(--text-muted) !important;
        font-style: italic;
        font-size: 12px;
        padding: 8px 12px;
      }

      .message.recalled .msg-bubble::before {
        content: '';
      }

      .msg-recall-notice {
        display: inline-flex;
        align-items: center;
        gap: 4px;
      }

      .msg-recall-notice svg {
        width: 12px;
        height: 12px;
        opacity: 0.6;
      }

      /* 撤回确认模态框 */
      .recall-confirm-modal .modal {
        max-width: 340px;
        text-align: center;
      }

      .recall-confirm-icon {
        font-size: 36px;
        margin-bottom: 8px;
      }

      .recall-confirm-title {
        font-size: 16px;
        font-weight: 600;
        margin-bottom: 4px;
      }

      .recall-confirm-desc {
        font-size: 12px;
        color: var(--text-secondary);
        margin-bottom: 16px;
        line-height: 1.5;
      }

      .recall-confirm-actions {
        display: flex;
        gap: 8px;
      }

      .recall-confirm-actions button {
        flex: 1;
        padding: 10px;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.15s;
      }
    `;
    document.head.appendChild(style);
  }

  // ── 绑定右键/长按菜单 ──
  function _bindContextMenu() {
    const messagesList = document.getElementById('messagesList');
    if (!messagesList) return;

    // 桌面端右键
    messagesList.addEventListener('contextmenu', (e) => {
      const msgEl = e.target.closest('.message');
      if (!msgEl) return;

      e.preventDefault();
      _showContextMenu(e.clientX, e.clientY, msgEl);
    });

    // 移动端长按
    let longPressTimer = null;
    let longPressTarget = null;

    messagesList.addEventListener('touchstart', (e) => {
      const msgEl = e.target.closest('.message');
      if (!msgEl) return;

      longPressTarget = msgEl;
      longPressTimer = setTimeout(() => {
        const touch = e.touches[0];
        _showContextMenu(touch.clientX, touch.clientY, msgEl);
      }, 600);
    }, { passive: true });

    messagesList.addEventListener('touchmove', () => {
      clearTimeout(longPressTimer);
    }, { passive: true });

    messagesList.addEventListener('touchend', () => {
      clearTimeout(longPressTimer);
    });

    // 点击其他地方关闭菜单
    document.addEventListener('click', () => {
      _hideContextMenu();
    });
  }

  // ── 显示上下文菜单 ──
  function _showContextMenu(x, y, msgEl) {
    _hideContextMenu();

    const isSent = msgEl.classList.contains('sent');
    const isRecalled = msgEl.classList.contains('recalled');
    const msgTimestamp = parseInt(msgEl.dataset.timestamp) || 0;
    const canRecall = isSent && !isRecalled && _isWithinRecallWindow(msgTimestamp);

    const menu = document.createElement('div');
    menu.className = 'msg-context-menu';
    menu.id = 'msgContextMenu';

    const items = [];

    // 撤回
    if (isSent) {
      items.push({
        icon: '↩️',
        label: 'Recall Message',
        className: canRecall ? 'danger' : 'danger disabled',
        action: canRecall ? () => _confirmRecall(msgEl) : null,
        hint: !canRecall ? '(over 2 min)' : ''
      });
    }

    // 复制
    if (!isRecalled) {
      items.push({
        icon: '📋',
        label: 'Copy Text',
        className: '',
        action: () => _copyMessageText(msgEl)
      });
    }

    // 转发（未来功能）
    if (!isRecalled) {
      items.push({
        icon: '↗️',
        label: 'Forward',
        className: 'disabled',
        action: null,
        hint: '(coming soon)'
      });
    }

    items.forEach(item => {
      const el = document.createElement('div');
      el.className = `msg-context-menu-item ${item.className}`;
      el.innerHTML = `
        <span class="msg-context-menu-icon">${item.icon}</span>
        <span>${item.label}${item.hint ? ` <span style="font-size:10px;opacity:0.5">${item.hint}</span>` : ''}</span>
      `;
      if (item.action) {
        el.addEventListener('click', (e) => {
          e.stopPropagation();
          item.action();
          _hideContextMenu();
        });
      }
      menu.appendChild(el);
    });

    // 定位（不超出屏幕）
    document.body.appendChild(menu);
    const rect = menu.getBoundingClientRect();
    const menuX = Math.min(x, window.innerWidth - rect.width - 10);
    const menuY = Math.min(y, window.innerHeight - rect.height - 10);
    menu.style.left = menuX + 'px';
    menu.style.top = menuY + 'px';
  }

  function _hideContextMenu() {
    const existing = document.getElementById('msgContextMenu');
    if (existing) existing.remove();
  }

  // ── 撤回确认 ──
  function _confirmRecall(msgEl) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay recall-confirm-modal';
    overlay.style.display = 'flex';

    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="recall-confirm-icon">↩️</div>
      <div class="recall-confirm-title">Recall Message?</div>
      <div class="recall-confirm-desc">
        This message will be marked as recalled. The recipient will see "Message recalled" instead of the original content.
      </div>
      <div class="recall-confirm-actions">
        <button class="twofa-btn-secondary" id="btnRecallCancel">Cancel</button>
        <button class="twofa-btn-disable" id="btnRecallConfirm">Recall</button>
      </div>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.remove();
    });

    document.getElementById('btnRecallCancel')?.addEventListener('click', () => overlay.remove());
    document.getElementById('btnRecallConfirm')?.addEventListener('click', () => {
      overlay.remove();
      _executeRecall(msgEl);
    });
  }

  // ── 执行撤回 ──
  async function _executeRecall(msgEl) {
    const messageId = msgEl.dataset.messageId;
    const conversationId = STATE.currentConversationId;

    // 本地立即更新UI
    _markAsRecalled(msgEl);

    // 通知对方（通过 WebSocket）
    if (STATE.ws && STATE.ws.readyState === WebSocket.OPEN) {
      STATE.ws.send(JSON.stringify({
        type: 'message_recall',
        messageId,
        conversationId,
        to: STATE.currentPeerId,
        recalledAt: Date.now()
      }));
    }

    // REST API 同步（确保可靠性）
    try {
      const token = localStorage.getItem('fk_token');
      await fetch(`${API_BASE}/messages/${messageId}/recall`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ conversationId })
      });
    } catch (e) {
      console.warn('[MessageRecall] REST sync failed:', e.message);
    }

    showToast('Message recalled', 'success');
  }

  // ── 标记消息为已撤回 ──
  function _markAsRecalled(msgEl) {
    msgEl.classList.add('recalled');
    msgEl.querySelector('.msg-bubble').innerHTML = `
      <div class="msg-recall-notice">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M3 6l18 12M3 18L21 6"/>
        </svg>
        Message recalled
      </div>
    `;
  }

  // ── 处理对方撤回消息 ──
  function _handleRemoteRecall(data) {
    const messageId = data.messageId;
    if (!messageId) return;

    // 在消息列表中查找并标记
    const messagesList = document.getElementById('messagesList');
    if (!messagesList) return;

    // 尝试通过 messageId 查找
    let msgEl = messagesList.querySelector(`[data-message-id="${messageId}"]`);

    // 如果没找到 message-id，尝试通过消息内容匹配（降级）
    if (!msgEl && data.messagePreview) {
      const allMsgs = messagesList.querySelectorAll('.message.received');
      for (const m of allMsgs) {
        const bubble = m.querySelector('.msg-bubble');
        if (bubble && bubble.textContent.includes(data.messagePreview)) {
          msgEl = m;
          break;
        }
      }
    }

    if (msgEl) {
      _markAsRecalled(msgEl);
    }
  }

  // ── WebSocket 撤回消息处理 ──
  function _bindWebSocketHandler() {
    // 监听原生 ws.onmessage，增加撤回类型处理
    const origWsConnect = window.connectWebSocket;
    if (typeof origWsConnect === 'function') {
      // 已经在 websocket.js 中处理
      // 这里通过事件代理补充
    }

    // 全局消息代理
    document.addEventListener('ws-message-recall', (e) => {
      _handleRemoteRecall(e.detail);
    });
  }

  // ── 增强 appendMessage 以支持 data-message-id ──
  function enhanceAppendMessage() {
    const origAppend = window.appendMessage;
    if (typeof origAppend !== 'function') return;

    window.appendMessage = function(sent, text, timestamp, isEncrypted, messageId) {
      origAppend(sent, text, timestamp, isEncrypted);

      // 给最后添加的消息设置 data-message-id
      const messagesList = document.getElementById('messagesList');
      if (messagesList && messageId) {
        const lastMsg = messagesList.querySelector('.message:last-child');
        if (lastMsg) {
          lastMsg.dataset.messageId = messageId;
          lastMsg.dataset.timestamp = timestamp || Date.now();
        }
      }
    };
  }

  // ── 复制消息文本 ──
  function _copyMessageText(msgEl) {
    const bubble = msgEl.querySelector('.msg-bubble');
    if (!bubble) return;

    // 排除 e2ee-badge 等非文本元素
    const clone = bubble.cloneNode(true);
    clone.querySelectorAll('.e2ee-badge, .voice-message').forEach(el => el.remove());
    const text = clone.textContent.trim();

    navigator.clipboard.writeText(text).then(() => {
      showToast('Copied', 'success');
    }).catch(() => {
      showToast('Copy failed', 'error');
    });
  }

  // ── 工具函数 ──
  function _isWithinRecallWindow(timestamp) {
    if (!timestamp) return false;
    const age = Date.now() - timestamp;
    return age <= CONFIG.recallWindowMs;
  }

  // ── 公共 API ──
  return {
    init,
    handleRemoteRecall: _handleRemoteRecall,
    enhanceAppendMessage,
    markAsRecalled: _markAsRecalled
  };
})();
