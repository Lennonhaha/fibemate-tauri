// ================================================
// Conversations  — v3 适配后端格式 { conversations: [{ id, otherUser, ... }] }
// ================================================
async function loadConversations() {
  const list = document.getElementById('conversationList');
  const empty = document.getElementById('emptyState');
  try {
    const token = localStorage.getItem('fk_token');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(`${API_BASE}/conversations`, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const convs = data.conversations || [];
    if (!convs || convs.length === 0) {
      if (empty) {
        empty.style.display = 'flex';
        empty.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width: 48px; height: 48px; color: var(--text-muted); margin-bottom: 16px;">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
          </svg>
          <p style="color: var(--text-secondary); font-size: 14px; margin-bottom: 8px;">No messages yet</p>
          <p style="color: var(--text-muted); font-size: 12px;">Start a conversation from Contacts</p>
        `;
      }
      list.innerHTML = '';
      return;
    }
    if (empty) empty.style.display = 'none';
    list.innerHTML = convs.map(c => buildConvItem(c)).join('');
    list.querySelectorAll('.conversation-item').forEach(item => {
      item.addEventListener('click', () => openChat(item.dataset.userId, item.dataset.name));
    });
  } catch (err) {
    console.error('[Conversations v3] Load failed:', err);
    if (empty) {
      empty.style.display = 'flex';
      empty.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width: 48px; height: 48px; color: var(--danger); margin-bottom: 16px;">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <p style="color: var(--text-secondary); font-size: 14px; margin-bottom: 8px;">Failed to load conversations</p>
        <button class="btn-secondary" onclick="loadConversations()" style="margin-top: 8px;">Retry</button>
      `;
    }
    list.innerHTML = '';
  }
}

// v3: 适配后端返回格式 { id, otherUser: { id, username, displayName }, lastMessage, lastMessageAt, unreadCount }
function buildConvItem(c) {
  const other = c.otherUser || {};
  const time = c.lastMessageAt ? formatTime(c.lastMessageAt) : '';
  const lastMsg = c.lastMessage || {};
  const preview = lastMsg.ciphertext ? '[Encrypted]' : 'No messages yet';
  const badge = c.unreadCount ? `<span class="conv-badge">${c.unreadCount}</span>` : '';
  const online = other.isOnline ? '<span class="online-dot"></span>' : '';
  return `<div class="conversation-item" data-user-id="${other.id || ''}" data-name="${escapeHtml(other.displayName || other.username || 'Unknown')}" data-conv-id="${c.id}">
    <div class="conv-avatar">${(other.displayName || other.username || 'U').charAt(0).toUpperCase()}${online}</div>
    <div class="conv-info"><div class="conv-name">${escapeHtml(other.displayName || other.username || 'Unknown')}</div><div class="conv-preview">${escapeHtml(preview)}</div></div>
    <div class="conv-meta"><span class="conv-time">${time}</span>${badge}</div>
  </div>`;
}

