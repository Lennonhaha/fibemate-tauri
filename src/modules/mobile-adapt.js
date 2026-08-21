/**
 * FIBEMATE Mobile Adaptation Module
 * 移动端响应式适配
 *
 * 功能：
 * - 视口自适应（手机/平板/桌面）
 * - 侧边栏折叠/展开手势
 * - 触摸优化（滑动操作、长按菜单）
 * - 移动端导航栏
 * - 虚拟键盘避让
 * - PWA 支持
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

const MobileAdapt = (() => {
  // ── 断点 ──
  const BREAKPOINTS = {
    mobile: 768,
    tablet: 1024,
    desktop: 1280
  };

  // ── 状态 ──
  let currentViewport = 'desktop';
  let sidebarOpen = false;
  let touchStartX = 0;
  let touchStartY = 0;
  let touchStartTime = 0;
  let swipeThreshold = 80;
  let isSwiping = false;

  // ── 初始化 ──
  function init() {
    _injectStyles();
    _injectMeta();
    _detectViewport();
    _bindResizeEvent();
    _bindTouchEvents();
    _handleVirtualKeyboard();
    _setupMobileNav();

    console.log(`[MobileAdapt] Initialized (${currentViewport})`);
  }

  // ── 注入 PWA meta ──
  function _injectMeta() {
    // Viewport meta（如果不存在）
    let viewport = document.querySelector('meta[name="viewport"]');
    if (!viewport) {
      viewport = document.createElement('meta');
      viewport.name = 'viewport';
      document.head.appendChild(viewport);
    }
    viewport.content = 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover';

    // Apple mobile web app
    const metas = [
      { name: 'apple-mobile-web-app-capable', content: 'yes' },
      { name: 'apple-mobile-web-app-status-bar-style', content: 'black-translucent' },
      { name: 'mobile-web-app-capable', content: 'yes' },
      { name: 'theme-color', content: '#0A0A0F' }
    ];

    metas.forEach(m => {
      if (!document.querySelector(`meta[name="${m.name}"]`)) {
        const el = document.createElement('meta');
        el.name = m.name;
        el.content = m.content;
        document.head.appendChild(el);
      }
    });
  }

  // ── 注入样式 ──
  function _injectStyles() {
    const style = document.createElement('style');
    style.id = 'mobile-adapt-styles';
    style.textContent = `
      /* ── 移动端布局 ── */
      @media (max-width: ${BREAKPOINTS.mobile}px) {
        .app-container {
          flex-direction: column;
        }

        .sidebar {
          position: fixed;
          left: 0;
          top: 0;
          bottom: 0;
          width: 85vw;
          max-width: 320px;
          z-index: 200;
          transform: translateX(-100%);
          transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .sidebar.open {
          transform: translateX(0);
        }

        /* 侧边栏遮罩 */
        .sidebar-backdrop {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.6);
          z-index: 199;
          opacity: 0;
          pointer-events: none;
          transition: opacity 0.3s;
        }

        .sidebar-backdrop.visible {
          opacity: 1;
          pointer-events: auto;
        }

        /* 移动端底部导航 */
        .mobile-bottom-nav {
          display: flex !important;
          position: fixed;
          bottom: 0;
          left: 0;
          right: 0;
          height: 56px;
          background: var(--bg-card);
          border-top: 1px solid var(--border-subtle);
          z-index: 100;
          padding-bottom: env(safe-area-inset-bottom, 0);
        }

        /* 主题切换小球挪到右上角，避开底部导航设置键 */
        #btnThemeToggle {
          bottom: auto !important;
          top: 16px !important;
          right: 16px !important;
          width: 34px !important;
          height: 34px !important;
          font-size: 15px !important;
          z-index: 90 !important;
          opacity: 0.75;
        }

        .mobile-nav-item {
          flex: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 2px;
          color: var(--text-muted);
          font-size: 10px;
          cursor: pointer;
          transition: color 0.15s;
          -webkit-tap-highlight-color: transparent;
        }

        .mobile-nav-item.active {
          color: var(--accent);
        }

        .mobile-nav-item svg {
          width: 20px;
          height: 20px;
        }

        /* 主内容区占满 */
        .chat-area {
          width: 100vw !important;
          padding-bottom: 56px;
        }

        /* 移动端汉堡菜单按钮 */
        .mobile-menu-btn {
          display: flex !important;
          width: 36px;
          height: 36px;
          align-items: center;
          justify-content: center;
          border-radius: 8px;
          cursor: pointer;
          -webkit-tap-highlight-color: transparent;
        }

        .mobile-menu-btn:active {
          background: var(--accent-dim);
        }

        /* 聊天头部移动端适配 */
        .chat-header {
          padding: 8px 12px;
        }

        .chat-peer-info {
          flex: 1;
          min-width: 0;
        }

        .chat-peer-name {
          font-size: 15px;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        /* 消息气泡移动端 */
        .msg-bubble {
          max-width: 80vw;
          font-size: 14px;
          padding: 8px 12px;
        }

        /* 输入栏移动端 */
        .chat-input-bar {
          padding: 8px 12px;
          padding-bottom: calc(8px + env(safe-area-inset-bottom, 0));
        }

        .chat-input-bar input {
          font-size: 16px; /* 防止 iOS 自动缩放 */
          padding: 10px 12px;
        }

        /* 搜索栏 */
        .search-bar input {
          font-size: 16px;
        }

        /* 会话列表项 */
        .conversation-item {
          padding: 12px 16px;
        }

        .conv-preview {
          font-size: 12px;
        }

        /* 通话视图移动端 */
        .call-view {
          padding: 40px 20px;
        }

        .call-avatar {
          width: 80px;
          height: 80px;
          font-size: 32px;
        }

        .call-actions {
          gap: 20px;
        }

        /* 模态框移动端 */
        .modal {
          width: 92vw;
          max-height: 80vh;
          margin: auto;
          border-radius: 16px;
        }

        /* 隐藏桌面端导航标签 */
        .sidebar-nav {
          display: none;
        }

        /* 用户栏移动端 */
        .user-bar {
          padding: 10px 16px;
        }

        /* 设置面板移动端 */
        .settings-detail-view {
          padding: 16px;
        }

        /* 安全区域 */
        body {
          padding-top: env(safe-area-inset-top, 0);
        }
      }

      /* ── 平板适配 ── */
      @media (min-width: ${BREAKPOINTS.mobile + 1}px) and (max-width: ${BREAKPOINTS.tablet}px) {
        .sidebar {
          width: 240px;
        }

        .sidebar-nav span {
          display: none;
        }

        .nav-tab {
          justify-content: center;
          padding: 10px;
        }

        .nav-tab svg {
          width: 22px;
          height: 22px;
        }
      }

      /* ── 桌面端隐藏移动元素 ── */
      @media (min-width: ${BREAKPOINTS.mobile + 1}px) {
        .mobile-bottom-nav,
        .mobile-menu-btn {
          display: none !important;
        }

        .sidebar-backdrop {
          display: none;
        }
      }

      /* ── 触摸反馈 ── */
      @media (hover: none) and (pointer: coarse) {
        .conversation-item:active,
        .contact-item:active {
          background: var(--accent-dim);
        }

        .icon-btn:active {
          background: var(--accent-dim);
          transform: scale(0.95);
        }

        .btn-primary:active {
          filter: brightness(0.9);
        }

        /* 禁用长按上下文菜单 */
        .msg-bubble,
        .voice-message,
        .conversation-item {
          -webkit-touch-callout: none;
          -webkit-user-select: none;
          user-select: none;
        }
      }

      /* ── 滚动条移动端隐藏 ── */
      @media (max-width: ${BREAKPOINTS.mobile}px) {
        .messages-list::-webkit-scrollbar,
        .conversation-list::-webkit-scrollbar {
          display: none;
        }

        .messages-list,
        .conversation-list {
          -ms-overflow-style: none;
          scrollbar-width: none;
        }
      }
    `;
    document.head.appendChild(style);
  }

  // ── 检测视口 ──
  function _detectViewport() {
    const width = window.innerWidth;
    if (width <= BREAKPOINTS.mobile) {
      currentViewport = 'mobile';
    } else if (width <= BREAKPOINTS.tablet) {
      currentViewport = 'tablet';
    } else {
      currentViewport = 'desktop';
    }
    _applyViewportChanges();
  }

  // ── 应用视口变更 ──
  function _applyViewportChanges() {
    document.body.dataset.viewport = currentViewport;

    if (currentViewport === 'desktop') {
      // 确保侧边栏始终可见
      const sidebar = document.querySelector('.sidebar');
      if (sidebar) sidebar.classList.remove('open');
      _hideBackdrop();
    }
  }

  // ── 绑定窗口大小变更 ──
  function _bindResizeEvent() {
    let resizeTimer;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        const oldViewport = currentViewport;
        _detectViewport();
        if (oldViewport !== currentViewport) {
          console.log(`[MobileAdapt] Viewport changed: ${oldViewport} → ${currentViewport}`);
        }
      }, 150);
    });
  }

  // ── 绑定触摸事件 ──
  function _bindTouchEvents() {
    const container = document.querySelector('.app-container');
    if (!container) return;

    container.addEventListener('touchstart', (e) => {
      touchStartX = e.touches[0].clientX;
      touchStartY = e.touches[0].clientY;
      touchStartTime = Date.now();
      isSwiping = false;
    }, { passive: true });

    container.addEventListener('touchmove', (e) => {
      if (isSwiping) return;

      const deltaX = e.touches[0].clientX - touchStartX;
      const deltaY = e.touches[0].clientY - touchStartY;

      // 水平滑动大于垂直滑动才视为手势
      if (Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > 20) {
        isSwiping = true;

        if (currentViewport === 'mobile') {
          // 从左边缘右滑 → 打开侧边栏
          if (touchStartX < 20 && deltaX > 0) {
            _openSidebar();
          }
          // 侧边栏打开时左滑 → 关闭
          else if (sidebarOpen && deltaX < -swipeThreshold) {
            _closeSidebar();
          }
        }
      }
    }, { passive: true });

    container.addEventListener('touchend', () => {
      isSwiping = false;
    }, { passive: true });
  }

  // ── 侧边栏控制 ──
  function _openSidebar() {
    if (currentViewport !== 'mobile') return;
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
      sidebar.classList.add('open');
      sidebarOpen = true;
      _showBackdrop();
    }
  }

  function _closeSidebar() {
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
      sidebar.classList.remove('open');
      sidebarOpen = false;
      _hideBackdrop();
    }
  }

  function _toggleSidebar() {
    if (sidebarOpen) {
      _closeSidebar();
    } else {
      _openSidebar();
    }
  }

  // ── 遮罩层 ──
  function _showBackdrop() {
    let backdrop = document.querySelector('.sidebar-backdrop');
    if (!backdrop) {
      backdrop = document.createElement('div');
      backdrop.className = 'sidebar-backdrop';
      document.body.appendChild(backdrop);
      backdrop.addEventListener('click', _closeSidebar);
    }
    requestAnimationFrame(() => backdrop.classList.add('visible'));
  }

  function _hideBackdrop() {
    const backdrop = document.querySelector('.sidebar-backdrop');
    if (backdrop) {
      backdrop.classList.remove('visible');
    }
  }

  // ── 移动端底部导航 ──
  function _setupMobileNav() {
    // 检查是否已存在
    if (document.querySelector('.mobile-bottom-nav')) return;

    const nav = document.createElement('nav');
    nav.className = 'mobile-bottom-nav';
    nav.style.display = 'none'; // 默认隐藏，CSS媒体查询控制
    nav.innerHTML = `
      <div class="mobile-nav-item active" data-tab="messages">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
        </svg>
        <span>Messages</span>
      </div>
      <div class="mobile-nav-item" data-tab="contacts">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>
          <path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
        </svg>
        <span>Contacts</span>
      </div>
      <div class="mobile-nav-item" data-tab="vault">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <span>Vault</span>
      </div>
      <div class="mobile-nav-item" data-tab="keys">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
        </svg>
        <span>Keys</span>
      </div>
      <div class="mobile-nav-item" data-tab="settings">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="3"/>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
        </svg>
        <span>Settings</span>
      </div>
    `;

    document.body.appendChild(nav);

    // 绑定导航点击
    nav.querySelectorAll('.mobile-nav-item').forEach(item => {
      item.addEventListener('click', () => {
        const tab = item.dataset.tab;

        // 切换活跃状态
        nav.querySelectorAll('.mobile-nav-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');

        // 切换侧边栏面板
        const navTab = document.querySelector(`.nav-tab[data-tab="${tab}"]`);
        if (navTab) navTab.click();

        // 打开侧边栏
        _openSidebar();
      });
    });

    // 添加汉堡菜单按钮到聊天头部
    const chatHeader = document.querySelector('.chat-header');
    if (chatHeader) {
      const menuBtn = document.createElement('button');
      menuBtn.className = 'mobile-menu-btn icon-btn';
      menuBtn.id = 'btnMobileMenu';
      menuBtn.title = 'Menu';
      menuBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="3" y1="6" x2="21" y2="6"/>
          <line x1="3" y1="12" x2="21" y2="12"/>
          <line x1="3" y1="18" x2="21" y2="18"/>
        </svg>
      `;
      menuBtn.style.display = 'none'; // CSS媒体查询控制显示
      menuBtn.addEventListener('click', _toggleSidebar);

      const btnBack = document.getElementById('btnBack');
      if (btnBack) {
        chatHeader.insertBefore(menuBtn, btnBack);
      } else {
        chatHeader.insertBefore(menuBtn, chatHeader.firstChild);
      }
    }
  }

  // ── 虚拟键盘避让 ──
  function _handleVirtualKeyboard() {
    if (!('visualViewport' in window)) return;

    window.visualViewport.addEventListener('resize', () => {
      const chatInput = document.querySelector('.chat-input-bar');
      if (!chatInput) return;

      // 检测键盘弹出
      const isKeyboardOpen = window.innerHeight - window.visualViewport.height > 150;

      if (isKeyboardOpen && currentViewport === 'mobile') {
        const offset = window.innerHeight - window.visualViewport.height;
        chatInput.style.transform = `translateY(-${offset}px)`;
        document.querySelector('.messages-list')?.scrollTo(0, 999999);
      } else {
        chatInput.style.transform = '';
      }
    });

    window.visualViewport.addEventListener('scroll', () => {
      // 防止键盘弹出时页面滚动
      if (currentViewport === 'mobile') {
        window.scrollTo(0, 0);
      }
    });
  }

  // ── 公共 API ──
  return {
    init,
    openSidebar: _openSidebar,
    closeSidebar: _closeSidebar,
    toggleSidebar: _toggleSidebar,
    getViewport: () => currentViewport,
    isMobile: () => currentViewport === 'mobile'
  };
})();
