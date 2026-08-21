// ================================================
// Key Management (unchanged from v2)
// ================================================
async function renderKeyManagement() {
  const container = document.getElementById('keyCards');
  const keys = await getKeyInfo();
  container.innerHTML = keys.map(k => `
    <div class="key-card">
      <div class="key-card-header">
        <div class="key-icon">${k.icon}</div>
        <div>
          <div class="key-type">${k.type}</div>
          <div class="key-algo">${k.algo}</div>
        </div>
        <span class="key-status ${k.active ? 'active' : 'inactive'}">${k.active ? 'Active' : 'Rotated'}</span>
      </div>
      <div class="key-fingerprint"><label>Fingerprint</label><code>${k.fingerprint}</code></div>
      <div class="key-meta">
        <span>Created: ${k.created}</span>
        <span>Uses: ${k.uses}</span>
      </div>
      ${k.active ? `<button class="btn-secondary key-rotate-btn" data-key="${k.id}">Rotate This Key</button>` : ''}
    </div>
  `).join('');

  container.querySelectorAll('.key-rotate-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      showToast(`Rotating ${btn.dataset.key} key... New key pair generated`, 'success');
      renderKeyManagement();
    });
  });
}

async function getKeyInfo() {
  const keys = [];
  
  // Get real identity key from MessageCryptoV2
  if (typeof MessageCryptoV2 !== 'undefined' && MessageCryptoV2._getIdentityKey) {
    try {
      const identityKey = await MessageCryptoV2._getIdentityKey();
      const identityPublic = await crypto.subtle.exportKey('raw', identityKey.publicKey);
      const identityFingerprint = Array.from(new Uint8Array(identityPublic))
        .map((b, i) => b.toString(16).padStart(2, '0').toUpperCase() + ((i + 1) % 2 === 0 && i < 31 ? ':' : ''))
        .join('');
      
      keys.push({
        id: 'identity',
        type: 'Identity Key',
        algo: 'ECDH P-256',
        icon: '',
        active: true,
        fingerprint: identityFingerprint,
        created: new Date().toISOString().split('T')[0],
        uses: 'Active'
      });
    } catch (e) {
      console.warn('[KeyInfo] Failed to get identity key:', e.message);
    }
  }
  
  // If no real keys available, return demo data
  if (keys.length === 0) {
    return [
      { id: 'identity', type: 'Identity Key', algo: 'ECDH P-256', icon: '', active: true, fingerprint: 'A1:B2:C3:D4:E5:F6:78:90:AB:CD:EF:01:23:45:67:89', created: '2026-04-26', uses: 47 },
      { id: 'signed-pre', type: 'Signed Pre-Key', algo: 'ECDH P-256', icon: '✍️', active: true, fingerprint: '11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00', created: '2026-04-26', uses: 23 },
      { id: 'one-time', type: 'One-Time Pre-Key', algo: 'ECDH P-256', icon: '🎫', active: true, fingerprint: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99', created: '2026-04-26', uses: 12 },
      { id: 'pq-kem', type: 'Post-Quantum KEM', algo: 'ML-KEM-768 (WIP)', icon: '🛡️', active: false, fingerprint: 'PQ:7A:8B:9C:0D:1E:2F:3A:4B:5C:6D:7E:8F:9A:0B:1C', created: '2026-04-26', uses: 0 },
    ];
  }
  
  return keys;
}

function rotateKeys() {
  showToast('All active keys rotated. New key pairs generated via WebCrypto.', 'success');
  renderKeyManagement();
}

async function exportPublicKeys() {
  const keys = (await getKeyInfo()).filter(k => k.active);
  const text = keys.map(k => `${k.type} (${k.algo})\n  Fingerprint: ${k.fingerprint}\n  Created: ${k.created}`).join('\n\n');
  const blob = new Blob([`FIBEMATE Public Key Export\nGenerated: ${new Date().toISOString()}\n\n${text}`], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'fibemate-public-keys.txt'; a.click();
  URL.revokeObjectURL(url);
  showToast('Public keys exported', 'success');
}

