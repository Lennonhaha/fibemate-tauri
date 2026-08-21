// ================================================
// Navigation
// ================================================
function initNavigation() {
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      switchTab(target);
    });
  });
}

function switchTab(tab) {
  STATE.currentTab = tab;
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `panel${capitalize(tab)}`));
  hideAllMainViews();
  if (tab === 'messages') {
    document.getElementById('chatEmpty').style.display = 'flex';
  } else if (tab === 'keys') {
    document.getElementById('keyDetailView').style.display = 'flex';
  } else if (tab === 'settings') {
    document.getElementById('settingsDetailView').style.display = 'flex';
  }
  const placeholders = { messages: 'Search messages...', contacts: 'Search contacts...', vault: 'Search vault...', keys: 'Search keys...', settings: 'Search settings...' };
  document.getElementById('searchInput').placeholder = placeholders[tab] || 'Search...';

  // 切到 contacts 时重新从后端拉取好友列表（修「点开无好友」）
  if (tab === 'contacts' && typeof loadContacts === 'function') {
    loadContacts().catch(() => {});
  }
  if (tab === 'messages' && typeof loadConversations === 'function') {
    loadConversations().catch(() => {});
  }
}

function hideAllMainViews() {
  document.getElementById('chatEmpty').style.display = 'none';
  document.getElementById('chatWindow').style.display = 'none';
  document.getElementById('callView').style.display = 'none';
  document.getElementById('keyDetailView').style.display = 'none';
  document.getElementById('settingsDetailView').style.display = 'none';
}

function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

