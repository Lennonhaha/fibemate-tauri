/**
 * Key Manager Module
 * Manages all cryptographic keys with secure storage
 * Replaces direct localStorage access for private keys
 */

class KeyManager {
  constructor() {
    this.storage = new SecureKeyStorage();
    this.migration = new KeyStorageMigration();
    this.initialized = false;
  }

  async init() {
    if (this.initialized) return;
    
    await this.storage.init();
    await this.migration.migrateIfNeeded();
    this.initialized = true;
  }

  async getDevicePassword() {
    // Prompt for device password when needed
    return new Promise((resolve) => {
      // Check if we already have a session password
      if (window.__devicePassword) {
        resolve(window.__devicePassword);
        return;
      }

      // Create password prompt modal
      const modal = document.createElement('div');
      modal.id = 'password-prompt-modal';
      modal.innerHTML = `
        <div class="password-overlay">
          <div class="password-dialog">
            <h2>Unlock Keys</h2>
            <p>Enter your device password to access private keys:</p>
            <div class="form-group">
              <input type="password" id="device-password-input" placeholder="Device password" autofocus>
            </div>
            <div id="password-error" class="error-message"></div>
            <div class="password-actions">
              <button id="password-submit" class="btn-primary">Unlock</button>
            </div>
          </div>
        </div>
      `;

      const style = document.createElement('style');
      style.textContent = `
        .password-overlay {
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background: rgba(0, 0, 0, 0.8);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 10000;
        }
        .password-dialog {
          background: #1a1a2e;
          padding: 2rem;
          border-radius: 12px;
          width: 90%;
          max-width: 350px;
          color: #fff;
        }
        .password-dialog h2 {
          margin-top: 0;
          color: #00d4aa;
        }
        .form-group {
          margin: 1rem 0;
        }
        .form-group input {
          width: 100%;
          padding: 0.75rem;
          border: 1px solid #333;
          border-radius: 6px;
          background: #16213e;
          color: #fff;
          box-sizing: border-box;
        }
        .error-message {
          color: #ff4757;
          font-size: 0.85rem;
          margin: 0.5rem 0;
          min-height: 1.2rem;
        }
        .password-actions {
          margin-top: 1.5rem;
          text-align: right;
        }
        .btn-primary {
          background: #00d4aa;
          color: #1a1a2e;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 6px;
          cursor: pointer;
          font-weight: bold;
        }
      `;

      document.head.appendChild(style);
      document.body.appendChild(modal);

      const submitBtn = document.getElementById('password-submit');
      const passwordInput = document.getElementById('device-password-input');
      const errorDiv = document.getElementById('password-error');

      const handleSubmit = () => {
        const password = passwordInput.value;
        if (!password) {
          errorDiv.textContent = 'Please enter password';
          return;
        }

        // Store in session (memory only)
        window.__devicePassword = password;
        
        modal.remove();
        style.remove();
        resolve(password);
      };

      submitBtn.addEventListener('click', handleSubmit);
      passwordInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleSubmit();
      });

      passwordInput.focus();
    });
  }

  async getIdentityKey() {
    const password = await this.getDevicePassword();
    return this.storage.decryptPrivateKey('fk_identityKey', password);
  }

  async getSignedPreKey() {
    const password = await this.getDevicePassword();
    return this.storage.decryptPrivateKey('fk_signedPreKey', password);
  }

  async getOneTimePreKeys() {
    const password = await this.getDevicePassword();
    return this.storage.decryptPrivateKey('fk_oneTimePreKeys', password);
  }

  async storeIdentityKey(keyPair, password) {
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    await this.storage.encryptPrivateKey('fk_identityKey', privateKeyJwk, password);
  }

  async storeSignedPreKey(keyPair, password) {
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    await this.storage.encryptPrivateKey('fk_signedPreKey', privateKeyJwk, password);
  }

  async storeOneTimePreKeys(keys, password) {
    const jwks = [];
    for (const keyPair of keys) {
      const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
      jwks.push(jwk);
    }
    await this.storage.encryptPrivateKey('fk_oneTimePreKeys', jwks, password);
  }

  clearSessionPassword() {
    delete window.__devicePassword;
  }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = KeyManager;
}
