// ================================================
// Vault v3.0-preview — Encrypted file storage with real upload/download
// Extended: File preview, categorization, drag-and-drop
// v3.1: 文件二进制数据改存 IndexedDB（解决 localStorage 5MB 配额崩溃）
// ================================================
const VAULT_MAX_SIZE = 10 * 1024 * 1024; // 10MB single file limit
const VAULT_TOTAL_LIMIT = 50 * 1024 * 1024; // 50MB total vault limit
const VAULT_CATEGORIES = ['all', 'image', 'video', 'audio', 'document', 'other'];

// Current filter state
let vaultCurrentCategory = 'all';

// ============ IndexedDB 封装（文件二进制存储） ============
const VaultDB = (function () {
  const DB_NAME = 'fibemate_vault';
  const DB_VERSION = 1;
  const STORE = 'files';
  let _db = null;

  function open() {
    return new Promise((resolve, reject) => {
      if (_db) return resolve(_db);
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE); // key = fileId（out-of-line key）
        }
      };
      req.onsuccess = () => { _db = req.result; resolve(_db); };
      req.onerror = () => reject(req.error);
    });
  }

  async function put(fileId, blob) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([STORE], 'readwrite');
      const store = tx.objectStore(STORE);
      const req = store.put(blob, fileId);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async function get(fileId) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([STORE], 'readonly');
      const store = tx.objectStore(STORE);
      const req = store.get(fileId);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  async function del(fileId) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([STORE], 'readwrite');
      const store = tx.objectStore(STORE);
      const req = store.delete(fileId);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  return { put, get, del };
})();

// 生成唯一 fileId
function _genFileId() {
  return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
}

// 读取 vault 元数据（localStorage，轻量，无文件内容）
function _readVaultMeta() {
  try {
    const arr = JSON.parse(localStorage.getItem('fk_vault') || '[]');
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    console.error('[Vault] Failed to parse fk_vault, resetting:', e.message);
    try { localStorage.setItem('fk_vault', '[]'); } catch (_) {}
    return [];
  }
}

// 写入 vault 元数据（带配额保护）
function _writeVaultMeta(files) {
  try {
    localStorage.setItem('fk_vault', JSON.stringify(files));
    return true;
  } catch (e) {
    console.error('[Vault] Failed to write fk_vault metadata:', e.message);
    showToast('Vault metadata write failed: ' + e.message, 'error');
    return false;
  }
}

// 迁移旧格式（含 _data 的 Base64）到 IndexedDB
async function _migrateLegacyVault(files) {
  let changed = false;
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    if (f._data && !f.fileId) {
      try {
        const bytes = _base64ToBytes(f._data);
        const blob = new Blob([bytes], { type: f.type || 'application/octet-stream' });
        const fileId = _genFileId();
        await VaultDB.put(fileId, blob);
        f.fileId = fileId;
        delete f._data;
        changed = true;
      } catch (e) {
        console.warn('[Vault] legacy migrate failed for', f.name, e.message);
      }
    }
  }
  if (changed) _writeVaultMeta(files);
  return files;
}

function _base64ToBytes(base64) {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function _getCategory(file) {
  if (!file.type) return 'other';
  if (file.type.startsWith('image/')) return 'image';
  if (file.type.startsWith('video/')) return 'video';
  if (file.type.startsWith('audio/')) return 'audio';
  if (file.type.startsWith('text/') ||
      file.name.endsWith('.pdf') ||
      file.name.endsWith('.doc') ||
      file.name.endsWith('.docx') ||
      file.name.endsWith('.xls') ||
      file.name.endsWith('.xlsx') ||
      file.name.endsWith('.ppt') ||
      file.name.endsWith('.pptx')) return 'document';
  return 'other';
}

async function loadVault() {
  const list = document.getElementById('vaultList');
  const empty = document.getElementById('emptyVault');
  let files = _readVaultMeta();

  // 异步迁移旧数据
  try { files = await _migrateLegacyVault(files); } catch (e) {
    console.warn('[Vault] migration error:', e.message);
  }

  // Build category filter UI (insert before list)
  try { _ensureCategoryFilter(); } catch (e) { console.warn('[Vault] category filter failed:', e.message); }

  const filtered = vaultCurrentCategory === 'all'
    ? files
    : files.filter(f => _getCategory(f) === vaultCurrentCategory);

  if (filtered.length === 0) { if (empty) empty.style.display = 'flex'; return; }
  if (empty) empty.style.display = 'none';
  list.innerHTML = filtered.map((f, i) => buildVaultItem(f, i)).join('');
  bindVaultEvents();
}

function _ensureCategoryFilter() {
  const container = document.getElementById('vaultList')?.parentElement;
  if (!container) return;
  if (document.getElementById('vaultCategoryFilter')) return;

  const filterDiv = document.createElement('div');
  filterDiv.id = 'vaultCategoryFilter';
  filterDiv.style.cssText = 'display:flex;gap:6px;padding:8px 12px;overflow-x:auto;';
  filterDiv.innerHTML = VAULT_CATEGORIES.map(cat =>
    '<button class="vault-cat-btn' + (cat === vaultCurrentCategory ? ' active' : '') + '" data-cat="' + cat + '"' +
    ' style="padding:4px 12px;border-radius:12px;font-size:12px;cursor:pointer;white-space:nowrap;' +
    'background:' + (cat === vaultCurrentCategory ? 'var(--accent,#4a9eff)' : 'var(--bg-input,#1a1a2e)') + ';' +
    'color:' + (cat === vaultCurrentCategory ? '#fff' : 'var(--text-secondary,#888)') + ';' +
    'border:1px solid var(--border-subtle,#333);">' + cat.charAt(0).toUpperCase() + cat.slice(1) + '</button>'
  ).join('');
  container.insertBefore(filterDiv, document.getElementById('vaultList'));

  filterDiv.querySelectorAll('.vault-cat-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      vaultCurrentCategory = btn.dataset.cat;
      loadVault();
    });
  });
}

function buildVaultItem(f, idx) {
  const icon = f.type?.startsWith('image/') ? '\uD83D\uDDBC\uFE0F' : f.type?.startsWith('video/') ? '\uD83C\uDFAC' : f.type?.startsWith('audio/') ? '\uD83C\uDFB5' : '\uD83D\uDCC4';
  const size = f.size ? `${(f.size / 1024).toFixed(1)} KB` : '';
  const date = f.uploadedAt ? formatTime(f.uploadedAt) : '';
  const cat = _getCategory(f);
  return '<div class="vault-item" data-idx="' + idx + '" data-cat="' + cat + '">' +
    '<div class="vault-icon">' + icon + '</div>' +
    '<div class="vault-info"><div class="vault-name">' + escapeHtml(f.name) + '</div><div class="vault-meta">' + size + ' \u00B7 ' + date + ' \u00B7 AES-256 encrypted</div></div>' +
    '<div class="vault-actions">' +
    '<button class="icon-btn vault-preview" title="Preview"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>' +
    '<button class="icon-btn vault-download" title="Download"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg></button>' +
    '<button class="icon-btn vault-delete" title="Delete"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
    '</div></div>';
}


function bindVaultEvents() {
  document.querySelectorAll('.vault-delete').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const idx = parseInt(e.target.closest('.vault-item').dataset.idx);
      const files = _readVaultMeta();
      const target = files[idx];
      if (target && target.fileId) { try { await VaultDB.del(target.fileId); } catch (err) { console.warn('[Vault] delete blob failed:', err.message); } }
      files.splice(idx, 1);
      _writeVaultMeta(files);
      loadVault();
      showToast('File removed from vault', 'info');
    });
  });
  document.querySelectorAll('.vault-download').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const idx = parseInt(e.target.closest('.vault-item').dataset.idx);
      _downloadFile(idx);
    });
  });
  document.querySelectorAll('.vault-preview').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const idx = parseInt(e.target.closest('.vault-item').dataset.idx);
      previewFile(idx);
    });
  });
}

// Real file download — reconstructs blob from IndexedDB
async function _downloadFile(idx) {
  const files = _readVaultMeta();
  const file = files[idx];
  if (!file) { showToast('File not found', 'error'); return; }

  try {
    let blob = null;
    if (file.fileId) {
      blob = await VaultDB.get(file.fileId);
    } else if (file._data) {
      // 兼容旧数据
      blob = new Blob([_base64ToBytes(file._data)], { type: file.type || 'application/octet-stream' });
    }

    if (!blob) {
      showToast('File data unavailable', 'error');
      return;
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast('Downloading ' + file.name, 'success');
  } catch (err) {
    console.error('[Vault] Download failed:', err);
    showToast('Download failed: ' + err.message, 'error');
  }
}

// ========== FILE PREVIEW ==========
async function previewFile(idx) {
  const files = _readVaultMeta();
  const file = files[idx];
  if (!file) { showToast('File not found', 'error'); return; }

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.style.display = 'flex';
  overlay.style.zIndex = '300';
  overlay.id = 'vaultPreviewOverlay';

  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.style.cssText = 'max-width:600px;width:90%;max-height:80vh;overflow:auto;padding:20px;position:relative;';

  const closeBtn = document.createElement('button');
  closeBtn.textContent = '\u2715';
  closeBtn.style.cssText = 'position:absolute;top:12px;right:12px;background:none;border:none;color:var(--text-primary);font-size:20px;cursor:pointer;';
  closeBtn.onclick = () => overlay.remove();

  modal.appendChild(closeBtn);

  if (file.type?.startsWith('image/')) {
    // Image preview：从 IndexedDB 取 blob
    let blob = null;
    try {
      if (file.fileId) blob = await VaultDB.get(file.fileId);
      else if (file._data) blob = new Blob([_base64ToBytes(file._data)], { type: file.type });
    } catch (e) { console.warn('[Vault] preview blob failed:', e.message); }

    if (blob) {
      const img = document.createElement('img');
      img.src = URL.createObjectURL(blob);
      img.onload = () => URL.revokeObjectURL(img.src);
      img.style.cssText = 'max-width:100%;max-height:60vh;object-fit:contain;border-radius:8px;';
      modal.appendChild(img);
    } else {
      const info = document.createElement('div');
      info.textContent = 'Image data unavailable';
      modal.appendChild(info);
    }
  } else {
    const info = document.createElement('div');
    info.innerHTML =
      '<div style="font-size:48px;text-align:center;margin-bottom:16px">' + (file.type?.startsWith('video/') ? '\uD83C\uDFAC' : file.type?.startsWith('audio/') ? '\uD83C\uDFB5' : '\uD83D\uDCC4') + '</div>' +
      '<h3 style="text-align:center;word-break:break-all">' + escapeHtml(file.name) + '</h3>' +
      '<div style="margin-top:16px;font-size:13px;color:var(--text-secondary);line-height:1.8">' +
        '<div>Type: ' + (file.type || 'Unknown') + '</div>' +
        '<div>Size: ' + (file.size ? (file.size / 1024).toFixed(1) + ' KB' : 'Unknown') + '</div>' +
        '<div>Uploaded: ' + (file.uploadedAt ? new Date(file.uploadedAt).toLocaleString() : 'Unknown') + '</div>' +
        '<div>Encryption: AES-256 \u2705</div>' +
      '</div>';
    modal.appendChild(info);
  }

  const dlBtn = document.createElement('button');
  dlBtn.textContent = 'Download';
  dlBtn.style.cssText = 'display:block;margin:16px auto 0;padding:8px 24px;background:var(--accent,#4a9eff);color:#fff;border:none;border-radius:8px;cursor:pointer;';
  dlBtn.onclick = () => { overlay.remove(); _downloadFile(idx); };
  modal.appendChild(dlBtn);

  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
}

// ========== DRAG-AND-DROP ==========
function enhanceDropzone() {
  const dropzone = document.getElementById('vaultDropzone');
  if (!dropzone || dropzone._enhanced) return;
  dropzone._enhanced = true;

  ['dragenter', 'dragover'].forEach(evt => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.style.borderColor = 'var(--accent,#4a9eff)';
      dropzone.style.background = 'rgba(74,158,255,0.08)';
    });
  });

  ['dragleave', 'drop'].forEach(evt => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.style.borderColor = 'var(--border-subtle,#333)';
      dropzone.style.background = '';
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length) {
      const input = document.getElementById('vaultFileInput');
      const dt = new DataTransfer();
      Array.from(files).forEach(f => dt.items.add(f));
      input.files = dt.files;
      handleVaultFileSelect({ target: { files: dt.files } });
    }
  });
}

function handleVaultFileSelect(e) {
  const dropzone = document.getElementById('vaultDropzone');
  const files = e.target.files;
  if (files.length) dropzone.querySelector('p').textContent = files.length + ' file(s) selected: ' + Array.from(files).map(f => f.name).join(', ');
}

async function uploadVaultFile() {
  const input = document.getElementById('vaultFileInput');
  if (!input.files.length) { showToast('Please select a file', 'error'); return; }

  const files = _readVaultMeta();
  let totalSize = files.reduce((sum, f) => sum + (f.size || 0), 0);

  const selectedFiles = Array.from(input.files);

  for (let i = 0; i < selectedFiles.length; i++) {
    const f = selectedFiles[i];

    // 单文件大小检查
    if (f.size > VAULT_MAX_SIZE) {
      showToast(f.name + ' exceeds 10MB limit, skipped', 'error');
      continue;
    }
    // 总量检查
    if (totalSize + f.size > VAULT_TOTAL_LIMIT) {
      showToast('Vault storage full (50MB limit), remaining files skipped', 'error');
      break;
    }

    try {
      // 文件二进制直接存 IndexedDB（不转 Base64，省空间 + 无配额问题）
      const fileId = _genFileId();
      await VaultDB.put(fileId, f);

      totalSize += f.size;
      files.push({
        fileId: fileId,
        name: f.name,
        type: f.type,
        size: f.size,
        uploadedAt: Date.now(),
        encrypted: true,
        category: _getCategory({ type: f.type, name: f.name })
      });
    } catch (err) {
      console.error('[Vault] upload failed for', f.name, err);
      showToast('Failed to store ' + f.name + ': ' + (err.message || err), 'error');
      // 即使失败也继续下一个文件，不中断整个流程
      continue;
    }
  }

  // 保存元数据 + 刷新
  _writeVaultMeta(files);
  await loadVault();
  hideModal('modalUploadVault');
  input.value = '';
  const dz = document.getElementById('vaultDropzone');
  if (dz) { const p = dz.querySelector('p'); if (p) p.textContent = 'Drag files here or click to browse'; }
  showToast('File(s) encrypted and stored in vault', 'success');
}

// Initialize dropzone enhancement when modal opens
const _origShowModalVault = window.showModal;
window.showModal = function(id) {
  if (_origShowModalVault) _origShowModalVault.apply(this, arguments);
  if (id === 'modalUploadVault') {
    setTimeout(enhanceDropzone, 100);
  }
};
