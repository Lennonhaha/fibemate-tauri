// ================================================
// Contacts v3.0-preview — Contact management with groups, favorites, safety numbers
// ================================================

let contacts = JSON.parse(localStorage.getItem('fk_contacts') || '[]');
let contactGroups = JSON.parse(localStorage.getItem('fk_contactGroups') || '[]');
let contactCurrentFilter = 'all'; // all | favorites | groups | online
let contactSearchQuery = '';

// ========== CONTACT CRUD ==========

function addContact(peer) {
  if (!peer.id) return false;
  const exists = contacts.find(c => c.id === peer.id);
  if (exists) { showToast('Contact already exists', 'info'); return false; }

  contacts.push({
    id: peer.id,
    name: peer.name || peer.displayName || 'Unknown',
    displayName: peer.displayName || peer.name || '',
    avatar: peer.avatar || peer.name?.charAt(0)?.toUpperCase() || '?',
    safetyNumber: peer.safetyNumber || '',
    safetyVerified: false,
    isFavorite: false,
    isOnline: peer.isOnline || false,
    lastSeen: peer.lastSeen || null,
    groups: peer.groups || [],
    addedAt: Date.now()
  });

  localStorage.setItem('fk_contacts', JSON.stringify(contacts));
  showToast('Contact added: ' + contacts[contacts.length - 1].name, 'success');
  return true;
}

// v3: 从「Add Contact」输入框读用户名，调后端 API 搜索并添加联系人。
// 绑定到 btnConfirmAddContact 按钮（main.js）。旧版 addContact(peer) 保留给
// syncContactsFromPeers 等本地调用，此处是真正的后端交互版本。
async function addContactFromInput() {
  const usernameInput = document.getElementById('contactUsername');
  const displayNameInput = document.getElementById('contactDisplayName');
  const username = (usernameInput?.value || '').trim();
  if (!username) { showToast('Please enter a username', 'error'); return; }

  try {
    const token = localStorage.getItem('fk_token');
    const api = (typeof API_BASE !== 'undefined') ? API_BASE : 'https://fibemate.net/api';

    // 1) 搜索用户
    const searchRes = await fetch(`${api}/users/search?q=${encodeURIComponent(username)}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!searchRes.ok) {
      const e = await searchRes.text().catch(() => '');
      showToast('Search failed: ' + (searchRes.status === 401 ? 'not authenticated' : e || ('HTTP ' + searchRes.status)), 'error');
      return;
    }
    const searchData = await searchRes.json();
    const users = (searchData.users || []).filter(u => (u.username || '').toLowerCase() === username.toLowerCase() ||
      (u.displayName && u.displayName.toLowerCase() === username.toLowerCase()));
    if (users.length === 0) {
      showToast('User "' + username + '" not found', 'error');
      return;
    }
    const targetUser = users[0];

    // 2) 添加联系人（后端双向 pending）
    const res = await fetch(`${api}/contacts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ userId: targetUser.id })
    });
    if (!res.ok) {
      const err = await res.text().catch(() => '');
      if (res.status === 409) { showToast('Already a contact', 'info'); }
      else { showToast('Add failed: ' + (err || ('HTTP ' + res.status)), 'error'); }
      return;
    }

    if (typeof hideModal === 'function') hideModal('modalAddContact');
    if (usernameInput) usernameInput.value = '';
    if (displayNameInput) displayNameInput.value = '';
    showToast('Added ' + (targetUser.displayName || targetUser.username), 'success');

    // 3) 同步到本地缓存并刷新列表
    const newContact = {
      id: targetUser.id,
      name: targetUser.displayName || targetUser.username,
      displayName: targetUser.displayName || targetUser.username,
      username: targetUser.username,
      avatar: (targetUser.displayName || targetUser.username).charAt(0).toUpperCase(),
      isOnline: !!targetUser.isOnline,
      addedAt: Date.now()
    };
    if (!contacts.find(c => c.id === newContact.id)) {
      contacts.push(newContact);
      localStorage.setItem('fk_contacts', JSON.stringify(contacts));
    }
    if (typeof loadContacts === 'function') await loadContacts().catch(() => {});
    if (typeof renderContactList === 'function') renderContactList();
  } catch (err) {
    console.error('[AddContact v3]', err);
    showToast('Add contact failed: ' + (err && err.message ? err.message : err), 'error');
  }
}

function removeContact(contactId) {
  contacts = contacts.filter(c => c.id !== contactId);
  localStorage.setItem('fk_contacts', JSON.stringify(contacts));
  showToast('Contact removed', 'info');
  renderContactList();
}

function toggleFavorite(contactId) {
  const contact = contacts.find(c => c.id === contactId);
  if (!contact) return;
  contact.isFavorite = !contact.isFavorite;
  localStorage.setItem('fk_contacts', JSON.stringify(contacts));
  renderContactList();
}

function verifySafetyNumber(contactId) {
  const contact = contacts.find(c => c.id === contactId);
  if (!contact) return;

  // Get current safety number
  let safetyNumber = contact.safetyNumber;
  if (!safetyNumber && typeof MessageCryptoV2 !== 'undefined') {
    MessageCryptoV2.getSessionFingerprint?.(contactId).then(fp => {
      if (fp) {
        contact.safetyNumber = fp;
        localStorage.setItem('fk_contacts', JSON.stringify(contacts));
        _showSafetyNumberModal(contact);
      }
    }).catch(() => _showSafetyNumberModal(contact));
  } else {
    _showSafetyNumberModal(contact);
  }
}

function _showSafetyNumberModal(contact) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.style.display = 'flex';
  overlay.style.zIndex = '300';

  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.style.cssText = 'max-width:400px;width:90%;padding:24px;text-align:center;';

  const sn = contact.safetyNumber || 'Not available — start a session first';

  modal.innerHTML =
    '<h3 style="margin-bottom:4px">Safety Number</h3>' +
    '<p style="font-size:12px;color:var(--text-muted);margin-bottom:16px">Verify with ' + escapeHtml(contact.displayName || contact.name) + ' to ensure encryption</p>' +
    '<div style="background:var(--bg-input);border-radius:8px;padding:16px;margin-bottom:8px;font-family:monospace;font-size:13px;letter-spacing:1px;word-break:break-all;color:var(--text-primary)">' + escapeHtml(sn) + '</div>' +
    (contact.safetyVerified ? '<div style="color:#4CAF50;font-size:13px;margin-bottom:12px">\u2705 Verified</div>' :
      '<div style="display:flex;gap:8px;justify-content:center;margin-top:12px">' +
        '<button id="btnVerifySN" style="padding:10px 20px;background:#4CAF50;border:none;border-radius:8px;color:#fff;font-weight:600;cursor:pointer">Mark as Verified</button>' +
        '<button id="btnCloseSN" style="padding:10px 20px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:8px;color:var(--text-primary);cursor:pointer">Close</button>' +
      '</div>');

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });

  document.getElementById('btnVerifySN')?.addEventListener('click', () => {
    contact.safetyVerified = true;
    localStorage.setItem('fk_contacts', JSON.stringify(contacts));
    overlay.remove();
    showToast('Safety number verified for ' + contact.name, 'success');
    renderContactList();
  });

  document.getElementById('btnCloseSN')?.addEventListener('click', () => overlay.remove());
}

// ========== GROUPS ==========

function createContactGroup(name) {
  if (!name || !name.trim()) return;
  if (contactGroups.find(g => g.name === name.trim())) {
    showToast('Group already exists', 'error');
    return;
  }
  contactGroups.push({ name: name.trim(), createdAt: Date.now() });
  localStorage.setItem('fk_contactGroups', JSON.stringify(contactGroups));
  showToast('Group "' + name.trim() + '" created', 'success');
  renderContactList();
}

function deleteContactGroup(name) {
  contactGroups = contactGroups.filter(g => g.name !== name);
  // Remove group from all contacts
  contacts.forEach(c => { c.groups = c.groups.filter(g => g !== name); });
  localStorage.setItem('fk_contactGroups', JSON.stringify(contactGroups));
  localStorage.setItem('fk_contacts', JSON.stringify(contacts));
  renderContactList();
}

function assignContactToGroup(contactId, groupName) {
  const contact = contacts.find(c => c.id === contactId);
  if (!contact) return;
  if (!contact.groups) contact.groups = [];
  if (contact.groups.includes(groupName)) {
    contact.groups = contact.groups.filter(g => g !== groupName);
    showToast('Removed from "' + groupName + '"', 'info');
  } else {
    contact.groups.push(groupName);
    showToast('Added to "' + groupName + '"', 'info');
  }
  localStorage.setItem('fk_contacts', JSON.stringify(contacts));
  renderContactList();
}

// ========== RENDER ==========

function renderContactList() {
  const container = document.getElementById('contactList') || document.getElementById('contactsList');
  if (!container) return;

  // Filter contacts
  let filtered = [...contacts];

  // Search
  if (contactSearchQuery) {
    const q = contactSearchQuery.toLowerCase();
    filtered = filtered.filter(c =>
      c.name.toLowerCase().includes(q) ||
      (c.displayName && c.displayName.toLowerCase().includes(q))
    );
  }

  // Category filter
  if (contactCurrentFilter === 'favorites') {
    filtered = filtered.filter(c => c.isFavorite);
  } else if (contactCurrentFilter === 'online') {
    filtered = filtered.filter(c => c.isOnline);
  } else if (contactCurrentFilter.startsWith('group:')) {
    const gn = contactCurrentFilter.replace('group:', '');
    filtered = filtered.filter(c => c.groups && c.groups.includes(gn));
  }

  // Sort: favorites first, then online, then alphabetical
  filtered.sort((a, b) => {
    if (a.isFavorite !== b.isFavorite) return a.isFavorite ? -1 : 1;
    if (a.isOnline !== b.isOnline) return a.isOnline ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  // Search bar + filter tabs
  let html =
    '<div style="padding:8px 12px">' +
      '<div style="position:relative;margin-bottom:8px">' +
        '<svg style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text-muted)" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>' +
        '<input type="text" id="contactSearchInput" placeholder="Search contacts..." value="' + escapeHtml(contactSearchQuery) + '" ' +
        'style="width:100%;padding:8px 8px 8px 34px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:8px;color:var(--text-primary);font-size:13px;outline:none">' +
      '</div>' +
    '</div>' +

    // Filter tabs
    '<div style="display:flex;gap:6px;padding:0 12px 8px;overflow-x:auto" id="contactFilterTabs">' +
      '<button class="contact-filter-btn' + (contactCurrentFilter === 'all' ? ' active' : '') + '" data-filter="all" ' +
      'style="padding:4px 12px;border-radius:12px;font-size:12px;cursor:pointer;white-space:nowrap;' +
      'background:' + (contactCurrentFilter === 'all' ? 'var(--accent,#4a9eff)' : 'var(--bg-input,#1a1a2e)') + ';' +
      'color:' + (contactCurrentFilter === 'all' ? '#fff' : 'var(--text-secondary,#888)') + ';' +
      'border:1px solid var(--border-subtle,#333)">All (' + contacts.length + ')</button>' +
      '<button class="contact-filter-btn' + (contactCurrentFilter === 'favorites' ? ' active' : '') + '" data-filter="favorites" ' +
      'style="padding:4px 12px;border-radius:12px;font-size:12px;cursor:pointer;white-space:nowrap;' +
      'background:' + (contactCurrentFilter === 'favorites' ? 'var(--accent,#4a9eff)' : 'var(--bg-input,#1a1a2e)') + ';' +
      'color:' + (contactCurrentFilter === 'favorites' ? '#fff' : 'var(--text-secondary,#888)') + ';' +
      'border:1px solid var(--border-subtle,#333)">\u2B50 Favorites</button>' +
      '<button class="contact-filter-btn' + (contactCurrentFilter === 'online' ? ' active' : '') + '" data-filter="online" ' +
      'style="padding:4px 12px;border-radius:12px;font-size:12px;cursor:pointer;white-space:nowrap;' +
      'background:' + (contactCurrentFilter === 'online' ? 'var(--accent,#4a9eff)' : 'var(--bg-input,#1a1a2e)') + ';' +
      'color:' + (contactCurrentFilter === 'online' ? '#fff' : 'var(--text-secondary,#888)') + ';' +
      'border:1px solid var(--border-subtle,#333)">\uD83D\uDFE2 Online</button>';

  // Group filter buttons
  contactGroups.forEach(g => {
    const active = contactCurrentFilter === 'group:' + g.name;
    html += '<button class="contact-filter-btn' + (active ? ' active' : '') + '" data-filter="group:' + g.name + '" ' +
      'style="padding:4px 12px;border-radius:12px;font-size:12px;cursor:pointer;white-space:nowrap;' +
      'background:' + (active ? 'var(--accent,#4a9eff)' : 'var(--bg-input,#1a1a2e)') + ';' +
      'color:' + (active ? '#fff' : 'var(--text-secondary,#888)') + ';' +
      'border:1px solid var(--border-subtle,#333)">\uD83D\uDCC1 ' + escapeHtml(g.name) + '</button>';
  });

  html += '</div>';

  // New group button
  html += '<div style="padding:0 12px 8px">' +
    '<button id="btnNewGroup" style="font-size:11px;padding:4px 12px;border-radius:12px;background:transparent;border:1px dashed var(--border-subtle,#444);color:var(--text-muted);cursor:pointer">+ New Group</button>' +
    '</div>';

  // Contact list
  if (filtered.length === 0) {
    html += '<p style="text-align:center;padding:32px;color:var(--text-muted);font-size:13px">No contacts found</p>';
  } else {
    html += '<div id="contactItems">' +
      filtered.map(c => _buildContactItem(c)).join('') +
      '</div>';
  }

  container.innerHTML = html;
  _bindContactEvents();
}

function _buildContactItem(contact) {
  const onlineDot = contact.isOnline
    ? '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#4CAF50;position:absolute;bottom:0;right:0;border:2px solid var(--bg-primary,#0a0a0a)"></span>'
    : '';
  const favoriteStar = contact.isFavorite
    ? ' \u2B50'
    : '';
  const verifiedBadge = contact.safetyVerified
    ? ' \u2705'
    : '';

  const lastSeen = contact.lastSeen
    ? 'Last seen ' + formatTime(contact.lastSeen)
    : contact.isOnline ? 'Online' : '';

  return '<div class="contact-item" data-id="' + contact.id + '" style="display:flex;align-items:center;gap:12px;padding:10px 12px;cursor:pointer;border-bottom:1px solid var(--border-subtle,#333)">' +
    '<div style="position:relative;width:40px;height:40px;border-radius:50%;background:var(--accent,#4a9eff);display:flex;align-items:center;justify-content:center;font-size:18px;color:#fff;flex-shrink:0">' +
      escapeHtml(contact.avatar) +
      onlineDot +
    '</div>' +
    '<div style="flex:1;min-width:0">' +
      '<div style="font-size:14px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + escapeHtml(contact.displayName || contact.name) + favoriteStar + verifiedBadge + '</div>' +
      (lastSeen ? '<div style="font-size:11px;color:var(--text-muted)">' + lastSeen + '</div>' : '') +
    '</div>' +
    '<div style="display:flex;gap:4px">' +
      '<button class="icon-btn contact-favorite" data-id="' + contact.id + '" title="' + (contact.isFavorite ? 'Remove favorite' : 'Add favorite') + '" style="padding:4px;color:' + (contact.isFavorite ? '#FFD700' : 'var(--text-muted)') + ';cursor:pointer;background:none;border:none;font-size:14px">' + (contact.isFavorite ? '\u2B50' : '\u2606') + '</button>' +
      '<button class="icon-btn contact-call" data-id="' + contact.id + '" data-name="' + escapeHtml(contact.displayName || contact.name) + '" title="Call" style="padding:4px;color:var(--accent,#4a9eff);cursor:pointer;background:none;border:none"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg></button>' +
      '<button class="icon-btn contact-more" data-id="' + contact.id + '" data-name="' + escapeHtml(contact.displayName || contact.name) + '" title="More" style="padding:4px;color:var(--text-muted);cursor:pointer;background:none;border:none">\u22EE</button>' +
    '</div>' +
  '</div>';
}

function _bindContactEvents() {
  // Contact click → open chat
  document.querySelectorAll('.contact-item').forEach(item => {
    item.addEventListener('click', (e) => {
      if (e.target.closest('button')) return;
      const contactId = item.dataset.id;
      const contact = contacts.find(c => c.id === contactId);
      if (contact && typeof selectPeer === 'function') {
        selectPeer({ id: contact.id, name: contact.name, displayName: contact.displayName || contact.name });
      }
    });
  });

  // Favorite toggle
  document.querySelectorAll('.contact-favorite').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleFavorite(btn.dataset.id);
    });
  });

  // Quick call
  document.querySelectorAll('.contact-call').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      STATE.currentPeerName = btn.dataset.name;
      STATE.currentPeerId = btn.dataset.id;
      if (typeof startCall === 'function') startCall();
    });
  });

  // More options
  document.querySelectorAll('.contact-more').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const contactId = btn.dataset.id;
      const contact = contacts.find(c => c.id === contactId);
      if (!contact) return;
      _showContactActions(contact);
    });
  });

  // Filter tabs
  document.querySelectorAll('.contact-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      contactCurrentFilter = btn.dataset.filter;
      renderContactList();
    });
  });

  // Search
  document.getElementById('contactSearchInput')?.addEventListener('input', (e) => {
    contactSearchQuery = e.target.value;
    renderContactList();
  });

  // New group
  document.getElementById('btnNewGroup')?.addEventListener('click', () => {
    const name = prompt('Enter group name:');
    if (name) createContactGroup(name);
  });
}

function _showContactActions(contact) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.style.display = 'flex';
  overlay.style.zIndex = '300';

  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.style.cssText = 'max-width:320px;width:90%;padding:0;border-radius:12px;overflow:hidden;';

  const header = document.createElement('div');
  header.style.cssText = 'padding:20px;text-align:center;border-bottom:1px solid var(--border-subtle,#333);';
  header.innerHTML =
    '<div style="font-size:40px;margin-bottom:8px;width:56px;height:56px;border-radius:50%;background:var(--accent,#4a9eff);display:flex;align-items:center;justify-content:center;color:#fff;margin:0 auto">' + escapeHtml(contact.avatar) + '</div>' +
    '<div style="font-size:16px;font-weight:600;color:var(--text-primary)">' + escapeHtml(contact.displayName || contact.name) + '</div>' +
    (contact.safetyVerified ? '<div style="font-size:12px;color:#4CAF50">\u2705 Safety Number Verified</div>' : '');

  const actions = document.createElement('div');
  actions.style.cssText = 'padding:8px 0;';

  const menuItems = [
    { text: '\uD83D\uDD10 Safety Number', action: () => { overlay.remove(); verifySafetyNumber(contact.id); } },
    { text: '\uD83D\uDCC1 Assign to Group', action: () => { overlay.remove(); _showGroupPicker(contact.id); } },
    { text: '\uD83D\uDCE4 Send Message', action: () => { overlay.remove(); if (typeof selectPeer === 'function') selectPeer({ id: contact.id, name: contact.name, displayName: contact.displayName || contact.name }); } },
    { text: (contact.isFavorite ? '\u2605' : '\u2606') + ' ' + (contact.isFavorite ? 'Remove from Favorites' : 'Add to Favorites'), action: () => { overlay.remove(); toggleFavorite(contact.id); } },
    { text: '\uD83D\uDDD1 Remove Contact', action: () => { overlay.remove(); if (confirm('Remove ' + contact.name + ' from contacts?')) removeContact(contact.id); }, danger: true },
  ];

  menuItems.forEach(item => {
    const btn = document.createElement('button');
    btn.style.cssText = 'display:block;width:100%;text-align:left;padding:12px 20px;background:none;border:none;color:' + (item.danger ? '#ff4444' : 'var(--text-primary)') + ';font-size:14px;cursor:pointer;border-bottom:1px solid var(--border-subtle,#333)';
    btn.textContent = item.text;
    btn.onclick = item.action;
    actions.appendChild(btn);
  });

  const cancelBtn = document.createElement('button');
  cancelBtn.style.cssText = 'display:block;width:100%;padding:12px;background:none;border:none;color:var(--text-muted);font-size:14px;cursor:pointer;';
  cancelBtn.textContent = 'Cancel';
  cancelBtn.onclick = () => overlay.remove();
  actions.appendChild(cancelBtn);

  modal.appendChild(header);
  modal.appendChild(actions);
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
}

function _showGroupPicker(contactId) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.style.display = 'flex';
  overlay.style.zIndex = '300';

  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.style.cssText = 'max-width:320px;width:90%;padding:20px;';

  const contact = contacts.find(c => c.id === contactId);

  let html = '<h3 style="margin-bottom:16px">Assign to Group</h3>';

  if (contactGroups.length === 0) {
    html += '<p style="color:var(--text-muted);font-size:13px;text-align:center;margin-bottom:16px">No groups yet. Create one first.</p>';
    html += '<input id="inputNewGroup" type="text" placeholder="Group name..." style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:8px;color:var(--text-primary);font-size:13px;margin-bottom:8px">';
    html += '<button id="btnCreateGroup" style="display:block;width:100%;padding:10px;background:var(--accent,#4a9eff);border:none;border-radius:8px;color:#fff;cursor:pointer;font-weight:600">Create & Assign</button>';
  } else {
    html += contactGroups.map(g => {
      const assigned = contact?.groups?.includes(g.name);
      return '<div style="display:flex;align-items:center;justify-content:space-between;padding:8px;border-bottom:1px solid var(--border-subtle,#333)">' +
        '<span>' + escapeHtml(g.name) + '</span>' +
        '<button class="group-assign-btn" data-group="' + escapeHtml(g.name) + '" style="padding:4px 12px;border-radius:12px;background:' + (assigned ? 'var(--accent,#4a9eff)' : 'transparent') + ';color:' + (assigned ? '#fff' : 'var(--text-secondary)') + ';border:1px solid var(--border-subtle);cursor:pointer;font-size:12px">' + (assigned ? 'Remove' : 'Add') + '</button>' +
        '</div>';
    }).join('');
    html += '<div style="display:flex;gap:8px;margin-top:12px"><input id="inputNewGroup" type="text" placeholder="New group..." style="flex:1;padding:8px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:8px;color:var(--text-primary);font-size:13px"><button id="btnCreateGroup" style="padding:8px 16px;background:var(--accent,#4a9eff);border:none;border-radius:8px;color:#fff;cursor:pointer">Create</button></div>';
  }

  html += '<button id="btnCloseGroupPicker" style="display:block;width:100%;padding:10px;margin-top:8px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:8px;color:var(--text-primary);cursor:pointer">Close</button>';

  modal.innerHTML = html;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('btnCloseGroupPicker')?.addEventListener('click', () => overlay.remove());

  document.getElementById('btnCreateGroup')?.addEventListener('click', () => {
    const input = document.getElementById('inputNewGroup');
    const name = input?.value?.trim();
    if (name) {
      createContactGroup(name);
      assignContactToGroup(contactId, name);
      overlay.remove();
    }
  });

  document.querySelectorAll('.group-assign-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      assignContactToGroup(contactId, btn.dataset.group);
      overlay.remove();
    });
  });
}

// Initialize: load contacts from global peer store if available
function syncContactsFromPeers() {
  if (typeof STATE !== 'undefined' && STATE.peers && Array.isArray(STATE.peers)) {
    STATE.peers.forEach(peer => {
      if (!contacts.find(c => c.id === peer.id)) {
        addContact(peer);
      }
    });
    renderContactList();
  }
}

// v3: 从后端加载联系人（与 loadConversations 对应）。
// 注意：此函数被 main.js 的初始化链 await，必须内部 try-catch，
// 绝不抛异常，否则会中断 loadVault/bindEvents 等后续初始化。
async function loadContacts() {
  const list = document.getElementById('contactList');
  const empty = document.getElementById('emptyContacts');
  try {
    const token = localStorage.getItem('fk_token');
    // 加 8s 超时保护，防止网络挂起阻断初始化链
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(`${API_BASE}/contacts`, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const remote = data.contacts || [];

    if (remote.length === 0) {
      if (empty) empty.style.display = 'flex';
      if (list) list.innerHTML = '';
      return;
    }

    if (empty) empty.style.display = 'none';
    if (list) {
      list.innerHTML = remote.map(c => {
        const name = c.displayName || c.username || c.contactUserId || 'Unknown';
        const username = c.username || c.contactUserId || '';
        const online = c.isOnline ? '<span class="online-dot"></span>' : '';
        return `<div class="contact-item" data-user-id="${escapeHtml(c.contactUserId || '')}" data-name="${escapeHtml(name)}">
          <div class="contact-avatar">${escapeHtml(name.charAt(0).toUpperCase())}${online}</div>
          <div class="contact-info"><div class="contact-name">${escapeHtml(name)}</div><div class="contact-username">@${escapeHtml(username)}</div></div>
          <div class="contact-actions">
            <button class="icon-btn contact-chat" title="Message"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></button>
            <button class="icon-btn contact-call" title="Call"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg></button>
          </div>
        </div>`;
      }).join('');

      list.querySelectorAll('.contact-chat').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const item = e.target.closest('.contact-item');
          switchTab('messages');
          openChat(item.dataset.userId, item.dataset.name);
        });
      });
      list.querySelectorAll('.contact-call').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const item = e.target.closest('.contact-item');
          startCallWith(item.dataset.name);
        });
      });
    }
  } catch (err) {
    console.error('[Contacts v3] Load failed:', err);
    if (empty) {
      empty.style.display = 'flex';
      empty.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width: 48px; height: 48px; color: var(--danger); margin-bottom: 16px;">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <p style="color: var(--text-secondary); font-size: 14px; margin-bottom: 8px;">Failed to load contacts</p>
        <button class="btn-secondary" onclick="loadContacts()" style="margin-top: 8px;">Retry</button>
        <button class="btn-secondary" onclick="showModal('modalAddContact')" style="margin-top: 8px;">Add Contact</button>`;
    }
    if (list) list.innerHTML = '';
  }
}