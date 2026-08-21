// ================================================
// Key Management — 真实后端密钥（Tauri Rust KeyStore）
// ================================================
// 直接读 Rust 后端（ik_list / kem_list_keys / sm2_get_public），
// 不再使用假 demo 数据。后端不可用时才降级为明确标注的 demo。
//
// 密钥体系：
//   - X25519 身份密钥（ik_*）      — ik_list / ik_generate
//   - ML-KEM-768 后量子 KEM（纯 UUID）— kem_list_keys / kem_keygen
//   - SM2 国密密钥（sm2:*）        — sm2_generate / sm2_get_public

// localStorage 中活跃密钥 id 的键名（与 tauri-message-crypto-adapter / p2p-core 一致）
const IDENTITY_ID_KEY = 'fibemate_rust_identity_id';
const GM_KEY_ID_KEY = 'fibemate_gm_key_id';

function _invoke() {
  if (typeof window !== 'undefined' && window.__TAURI__?.core?.invoke) {
    return window.__TAURI__.core.invoke;
  }
  throw new Error('Tauri backend unavailable');
}

async function _safeInvoke(cmd, args) {
  try {
    return { ok: true, data: await _invoke()(cmd, args) };
  } catch (e) {
    return { ok: false, error: e };
  }
}

// 从 kem_list_keys 的原始列表里，把纯 UUID 判定为 ML-KEM，前缀为 ik_/sm2: 的排除
function _isMlKemId(keyId) {
  return !keyId.startsWith('ik_') && !keyId.startsWith('sm2:');
}
function _stripSm2Prefix(keyId) {
  return keyId.startsWith('sm2:') ? keyId.slice(4) : keyId;
}

async function getKeyInfo() {
  const keys = [];
  const activeIdentityId = localStorage.getItem(IDENTITY_ID_KEY) || null;
  const activeGmKeyId = localStorage.getItem(GM_KEY_ID_KEY) || null;

  // ── 1. X25519 身份密钥（ik_list） ──────────────────────────
  const ikRes = await _safeInvoke('ik_list', {});
  if (ikRes.ok && Array.isArray(ikRes.data?.identities)) {
    for (const ik of ikRes.data.identities) {
      keys.push({
        id: 'identity:' + ik.identity_id,
        type: 'Identity Key',
        algo: 'X25519 (X3DH)',
        active: ik.identity_id === activeIdentityId,
        fingerprint: ik.fingerprint,
        publicKeyHex: ik.public_key_hex,
        created: '—',
        uses: ik.identity_id === activeIdentityId ? 'Active' : 'Archived'
      });
    }
  }

  // ── 2. ML-KEM-768 后量子 KEM（kem_list_keys 过滤纯 UUID）────
  const kemRes = await _safeInvoke('kem_list_keys', {});
  if (kemRes.ok && Array.isArray(kemRes.data)) {
    for (const k of kemRes.data) {
      if (!_isMlKemId(k.key_id)) continue;
      keys.push({
        id: 'kem:' + k.key_id,
        type: 'Post-Quantum KEM',
        algo: 'ML-KEM-768',
        active: false, // ML-KEM 无单独活跃标记
        fingerprint: k.fingerprint,
        publicKeyHex: k.public_key,
        created: '—',
        uses: 'Standby'
      });
    }
  }

  // ── 3. SM2 国密密钥（sm2_get_public 逐条取真实公钥）────────
  const sm2Res = await _safeInvoke('kem_list_keys', {});
  if (sm2Res.ok && Array.isArray(sm2Res.data)) {
    const sm2Ids = sm2Res.data
      .filter(k => k.key_id.startsWith('sm2:'))
      .map(k => _stripSm2Prefix(k.key_id));
    for (const sm2Id of sm2Ids) {
      const pubRes = await _safeInvoke('sm2_get_public', { keyId: sm2Id });
      const pubHex = pubRes.ok ? pubRes.data?.public_key_hex : null;
      keys.push({
        id: 'sm2:' + sm2Id,
        type: 'SM2 Key',
        algo: 'SM2 (GB/T 32918)',
        active: sm2Id === activeGmKeyId,
        fingerprint: pubHex ? _fingerprintFromHex(pubHex) : ('SM2-' + sm2Id.slice(0, 8)),
        publicKeyHex: pubHex,
        created: '—',
        uses: sm2Id === activeGmKeyId ? 'Active' : 'Archived'
      });
    }
  }

  if (keys.length === 0) {
    // 后端完全不可达时的明确降级（标注 DEMO，不再是静默假数据）
    return [
      { id: 'demo', type: 'No keys', algo: 'Backend offline', active: false, fingerprint: 'Connect to Tauri backend to list real keys', created: '—', uses: '—', _demo: true }
    ];
  }

  return keys;
}

// 从 130 字符未压缩 SM2 公钥 hex 派生可读指纹（截取 SHA 不可用时的降级）
function _fingerprintFromHex(hex) {
  if (!hex) return '—';
  const clean = hex.startsWith('04') ? hex.slice(2) : hex;
  const parts = [];
  for (let i = 0; i < 16 && i * 2 < clean.length; i++) {
    parts.push(clean.slice(i * 2, i * 2 + 2).toUpperCase());
  }
  return parts.join(' ');
}

async function renderKeyManagement() {
  const container = document.getElementById('keyCards');
  if (!container) return;

  let keys;
  try {
    keys = await getKeyInfo();
  } catch (e) {
    keys = [{ id: 'err', type: 'Error', algo: 'Failed to read keys', active: false, fingerprint: e.message, created: '—', uses: '—' }];
  }

  container.innerHTML = keys.map(k => `
    <div class="key-row">
      <div class="key-row-top">
        <span class="key-name">${k.type}</span>
        <span class="key-algo">${k.algo}</span>
        <span class="key-spacer"></span>
        <span class="key-status ${k.active ? 'active' : 'inactive'}">${k.active ? 'Active' : (k.uses === 'Standby' ? 'Standby' : 'Rotated')}</span>
      </div>
      <div class="key-fingerprint"><code>${k.fingerprint}</code></div>
      <div class="key-meta">
        <span>Created ${k.created}</span>
        <span>·</span>
        <span>Uses ${k.uses}</span>
      </div>
    </div>
  `).join('');
}

async function rotateKeys() {
  const rotated = [];
  const errors = [];

  // ── 轮换 X25519 身份密钥 ─────────────────────────────────
  const ikRes = await _safeInvoke('ik_generate', { identityId: null });
  if (ikRes.ok) {
    const newId = ikRes.data.identity_id;
    localStorage.setItem(IDENTITY_ID_KEY, newId);
    rotated.push('Identity (X25519)');
  } else {
    errors.push('Identity: ' + (ikRes.error?.message || ikRes.error));
  }

  // ── 轮换 ML-KEM-768 ──────────────────────────────────────
  const kemRes = await _safeInvoke('kem_keygen', {});
  if (kemRes.ok) {
    rotated.push('ML-KEM-768');
  } else {
    errors.push('ML-KEM: ' + (kemRes.error?.message || kemRes.error));
  }

  // ── 轮换 SM2 ─────────────────────────────────────────────
  const sm2Res = await _safeInvoke('sm2_generate', {});
  if (sm2Res.ok) {
    localStorage.setItem(GM_KEY_ID_KEY, sm2Res.data.key_id);
    rotated.push('SM2');
  } else {
    errors.push('SM2: ' + (sm2Res.error?.message || sm2Res.error));
  }

  if (rotated.length > 0) {
    showToast(`Rotated ${rotated.join(', ')} — new key pairs generated in Rust KeyStore`, 'success');
  }
  if (errors.length > 0) {
    showToast('Some keys failed: ' + errors.join('; '), 'warning');
  }

  await renderKeyManagement();
}

async function exportPublicKeys() {
  const keys = await getKeyInfo();
  const lines = [
    'FIBEMATE Public Key Export',
    'Generated: ' + new Date().toISOString(),
    '',
    ...keys.map(k => `${k.type} (${k.algo})${k.active ? ' [ACTIVE]' : ''}\n  Fingerprint: ${k.fingerprint}\n  Public Key: ${k.publicKeyHex || '(hidden)'}`)
  ];
  const text = lines.join('\n\n');

  // 优先用 Tauri dialog 保存；不可用时回退浏览器下载
  try {
    if (window.__TAURI__?.plugin?.dialog?.save) {
      const path = await window.__TAURI__.plugin.dialog.save({
        defaultPath: 'fibemate-public-keys.txt',
        filters: [{ name: 'Text', extensions: ['txt'] }]
      });
      if (path) {
        await window.__TAURI__.plugin.fs.writeTextFile(path, text);
        showToast('Public keys saved to ' + path, 'success');
        return;
      }
      // 用户取消
      return;
    }
  } catch (e) {
    console.warn('[Keys] dialog save failed, fallback to download:', e.message);
  }

  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'fibemate-public-keys.txt';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast('Public keys exported to fibemate-public-keys.txt (check your Downloads folder)', 'success');
}
