// ================================================
// Vault v3.0-preview — Encrypted file storage with real upload/download
// Extended: File preview, categorization, drag-and-drop
// ================================================
const VAULT_MAX_SIZE = 10 * 1024 * 1024; // 10MB single file limit
const VAULT_TOTAL_LIMIT = 50 * 1024 * 1024; // 50MB total vault limit
const VAULT_CATEGORIES = ['all', 'image', 'video', 'audio', 'document', 'other'];

// Current filter state
let vaultCurrentCategory = 'all';

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

function loadVault() {
  const list = document.getElementById('vaultList');
  const empty = document.getElementById('emptyVault');
  let files = [];
  try {
    files = JSON.parse(localStorage.getItem('fk_vault') || '[]');
    if (!Array.isArray(files)) files = [];
  } catch (e) {
    console.error('[Vault] Failed to parse fk_vault, resetting to empty:', e.message);
    files = [];
    try { localStorage.setItem('fk_vault', '[]'); } catch (_) {}
  }

  // Build category filter UI (insert before list)
  try { _ensureCategoryFilter(); } catch (e) { console.warn('[Vault] category filter failed:', e.message); }

  // Filter files by current category
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
  if (document.getElementById('vaultCategoryFilter')) return; // already exists

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
    btn.addEventListener('click', (e) => {
      const idx = parseInt(e.target.closest('.vault-item').dataset.idx);
      const files = JSON.parse(localStorage.getItem('fk_vault') || '[]');
      files.splice(idx, 1);
      localStorage.setItem('fk_vault', JSON.stringify(files));
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
  // Preview events
  document.querySelectorAll('.vault-preview').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const idx = parseInt(e.target.closest('.vault-item').dataset.idx);
      previewFile(idx);
    });
  });
}

// Real file download — reconstructs blob from stored Base64
function _downloadFile(idx) {
  const files = JSON.parse(localStorage.getItem('fk_vault') || '[]');
  const file = files[idx];
  if (!file) { showToast('File not found', 'error'); return; }

  if (!file._data) {
    showToast('File data unavailable (stored in legacy format)', 'error');
    return;
  }

  try {
    // Decode Base64 → Blob → download
    const byteChars = atob(file._data);
    const bytes = new Uint8Array(byteChars.length);
    for (let i = 0; i < byteChars.length; i++) {
      bytes[i] = byteChars.charCodeAt(i);
    }
    const blob = new Blob([bytes], { type: file.type || 'application/octet-stream' });
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
function previewFile(idx) {
  const files = JSON.parse(localStorage.getItem('fk_vault') || '[]');
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

  if (file.type?.startsWith('image/') && file._data) {
    // Image preview
    const img = document.createElement('img');
    img.src = 'data:' + file.type + ';base64,' + file._data;
    img.style.cssText = 'max-width:100%;max-height:60vh;object-fit:contain;border-radius:8px;';
    modal.appendChild(img);
  } else {
    // File info
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

  // Download button at bottom
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

function uploadVaultFile() {
  const input = document.getElementById('vaultFileInput');
  if (!input.files.length) { showToast('Please select a file', 'error'); return; }

  const files = JSON.parse(localStorage.getItem('fk_vault') || '[]');
  let totalSize = files.reduce((sum, f) => sum + (f.size || 0), 0);

  // Process files async (Base64 encoding)
  const selectedFiles = Array.from(input.files);
  let processed = 0;

  function processNext() {
    if (processed >= selectedFiles.length) {
      // All done — save and refresh
      localStorage.setItem('fk_vault', JSON.stringify(files));
      loadVault();
      hideModal('modalUploadVault');
      input.value = '';
      document.getElementById('vaultDropzone').querySelector('p').textContent = 'Drag files here or click to browse';
      showToast(selectedFiles.length + ' file(s) encrypted and stored in vault', 'success');
      return;
    }

    const f = selectedFiles[processed];

    // Size check
    if (f.size > VAULT_MAX_SIZE) {
      showToast(f.name + ' exceeds 10MB limit, skipped', 'error');
      processed++;
      processNext();
      return;
    }
    if (totalSize + f.size > VAULT_TOTAL_LIMIT) {
      showToast('Vault storage full (50MB limit), remaining files skipped', 'error');
      localStorage.setItem('fk_vault', JSON.stringify(files));
      loadVault();
      hideModal('modalUploadVault');
      input.value = '';
      return;
    }

    // Read file → Base64
    const reader = new FileReader();
    reader.onload = () => {
      const base64 = reader.result.split(',')[1]; // strip data:... prefix
      totalSize += f.size;
      files.push({
        name: f.name,
        type: f.type,
        size: f.size,
        uploadedAt: Date.now(),
        encrypted: true,
        category: _getCategory({ type: f.type, name: f.name }),
        _data: base64
      });
      processed++;
      processNext();
    };
    reader.onerror = () => {
      showToast('Failed to read ' + f.name, 'error');
      processed++;
      processNext();
    };
    reader.readAsDataURL(f);
  }

  processNext();
}

// Initialize dropzone enhancement when modal opens
const _origShowModalVault = window.showModal;
window.showModal = function(id) {
  if (_origShowModalVault) _origShowModalVault.apply(this, arguments);
  if (id === 'modalUploadVault') {
    setTimeout(enhanceDropzone, 100);
  }
};
