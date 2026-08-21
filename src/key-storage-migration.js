/**
 * Key Storage Migration Script
 * Migrates plaintext keys from localStorage to encrypted IndexedDB storage
 * Run once on app startup to migrate existing keys
 */

class KeyStorageMigration {
  constructor() {
    this.storage = new SecureKeyStorage();
    this.migrated = false;
  }

  async checkMigrationNeeded() {
    await this.storage.init();
    
    // Check if any plaintext keys exist in localStorage
    const plaintextKeys = [
      'fk_identityKey',
      'fk_signedPreKey', 
      'fk_oneTimePreKeys'
    ];

    for (const keyName of plaintextKeys) {
      if (localStorage.getItem(keyName)) {
        return true;
      }
    }

    // Also check if encrypted keys exist (migration already done)
    const hasEncryptedIdentity = await this.storage.hasKey('fk_identityKey');
    return !hasEncryptedIdentity;
  }

  async showMigrationDialog() {
    return new Promise((resolve) => {
      // Create modal dialog
      const modal = document.createElement('div');
      modal.id = 'key-migration-modal';
      modal.innerHTML = `
        <div class="migration-overlay">
          <div class="migration-dialog">
            <h2>Security Upgrade Required</h2>
            <p>Your private keys need to be encrypted for better security.</p>
            <p>Please set a device password to protect your keys.</p>
            <div class="form-group">
              <label>Device Password:</label>
              <input type="password" id="migration-password" placeholder="Enter password" minlength="8">
            </div>
            <div class="form-group">
              <label>Confirm Password:</label>
              <input type="password" id="migration-password-confirm" placeholder="Confirm password">
            </div>
            <div id="migration-error" class="error-message"></div>
            <div class="migration-actions">
              <button id="migration-submit" class="btn-primary">Encrypt Keys</button>
            </div>
          </div>
        </div>
      `;

      // Add styles
      const style = document.createElement('style');
      style.textContent = `
        .migration-overlay {
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
        .migration-dialog {
          background: #1a1a2e;
          padding: 2rem;
          border-radius: 12px;
          width: 90%;
          max-width: 400px;
          color: #fff;
        }
        .migration-dialog h2 {
          margin-top: 0;
          color: #00d4aa;
        }
        .form-group {
          margin: 1rem 0;
        }
        .form-group label {
          display: block;
          margin-bottom: 0.5rem;
          font-size: 0.9rem;
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
        .migration-actions {
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
        .btn-primary:hover {
          background: #00b894;
        }
      `;

      document.head.appendChild(style);
      document.body.appendChild(modal);

      // Handle submit
      const submitBtn = document.getElementById('migration-submit');
      const passwordInput = document.getElementById('migration-password');
      const confirmInput = document.getElementById('migration-password-confirm');
      const errorDiv = document.getElementById('migration-error');

      submitBtn.addEventListener('click', async () => {
        const password = passwordInput.value;
        const confirm = confirmInput.value;

        if (password.length < 8) {
          errorDiv.textContent = 'Password must be at least 8 characters';
          return;
        }

        if (password !== confirm) {
          errorDiv.textContent = 'Passwords do not match';
          return;
        }

        try {
          submitBtn.disabled = true;
          submitBtn.textContent = 'Encrypting...';

          const migrated = await this.storage.migrateFromLocalStorage(password);
          
          // Remove modal
          modal.remove();
          style.remove();
          
          resolve({ success: true, migrated });
        } catch (error) {
          errorDiv.textContent = 'Migration failed: ' + error.message;
          submitBtn.disabled = false;
          submitBtn.textContent = 'Encrypt Keys';
        }
      });

      // Handle enter key
      confirmInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          submitBtn.click();
        }
      });
    });
  }

  async migrateIfNeeded() {
    const needsMigration = await this.checkMigrationNeeded();
    
    if (needsMigration) {
      const result = await this.showMigrationDialog();
      if (result.success) {
        this.migrated = true;
        console.log('Key migration completed:', result.migrated);
        return result;
      }
    } else {
      this.migrated = true;
      return { success: true, migrated: [] };
    }
  }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = KeyStorageMigration;
}
