/**
 * FIBEMATE Tauri - Main Interface Logic v3
 * Features: Messages, Contacts, Vault, Key Management, Settings, Voice Call
 * Backend: http://localhost:3006 (proxy to ECS 8.156.77.68:3001)
 * CHANGED from v2: API_BASE, token key names, conversationId flow, WebSocket URL, contacts from backend
 */

// API_BASE: 优先从环境变量/配置文件读取，其次使用默认值
// 生产环境应通过构建流程注入或从配置文件加载
const API_BASE = (() => {
  // 尝试从 localStorage 读取自定义配置（用于开发和测试）
  const customApi = localStorage.getItem('fk_api_base');
  if (customApi) return customApi;
  
  // 尝试从运行时配置读取（Electron preload 注入）
  if (typeof window !== 'undefined' && window.__FIBEMATE_CONFIG__?.apiBase) {
    return window.__FIBEMATE_CONFIG__.apiBase;
  }
  
  // 默认：生产环境 HTTPS 域名
  return 'https://fibemate.net/api';
})();

// ================================================
// State
// ================================================
const STATE = {};
STATE.currentPeerId = null;
STATE.currentPeerName = null;
STATE.currentConversationId = null;  // v3: 新增，v2 中缺失
STATE.currentTab = 'messages';
STATE.callTimer = null;
STATE.callSeconds = 0;
STATE.ws = null;

// ================================================
// Loading State Helpers
// ================================================
function showLoading(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = `
    <div class="loading-overlay">
      <div class="loading-spinner"></div>
    </div>
  `;
}

function showSkeleton(containerId, count = 3) {
  const container = document.getElementById(containerId);
  if (!container) return;
  let html = '';
  for (let i = 0; i < count; i++) {
    html += `
      <div class="conversation-item" style="opacity: 0.6;">
        <div class="conv-avatar skeleton skeleton-avatar"></div>
        <div class="conv-info" style="flex: 1;">
          <div class="conv-name skeleton skeleton-text" style="width: 120px;"></div>
          <div class="conv-preview skeleton skeleton-text short"></div>
        </div>
      </div>
    `;
  }
  container.innerHTML = html;
}

function hideLoading(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const overlay = container.querySelector('.loading-overlay');
  if (overlay) overlay.remove();
}

