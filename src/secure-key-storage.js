/**
 * Secure Key Storage Module
 * Encrypts private keys with user device password before storing in IndexedDB
 * Uses PBKDF2 + AES-GCM-256
 */

class SecureKeyStorage {
  constructor() {
    this.dbName = 'fibemate_secure_keys';
    this.dbVersion = 1;
    this.storeName = 'keys';
    this.db = null;
  }

  async init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.dbVersion);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName, { keyPath: 'name' });
        }
      };
    });
  }

  async deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    const baseKey = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async encryptPrivateKey(name, privateKeyJwk, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const key = await this.deriveKey(password, salt);
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(JSON.stringify(privateKeyJwk));
    
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      plaintext
    );

    const encryptedData = {
      name: name,
      salt: Array.from(salt),
      iv: Array.from(iv),
      ciphertext: Array.from(new Uint8Array(ciphertext)),
      createdAt: Date.now()
    };

    await this.storeEncryptedKey(encryptedData);
    return encryptedData;
  }

  async decryptPrivateKey(name, password) {
    const encryptedData = await this.getEncryptedKey(name);
    if (!encryptedData) {
      throw new Error(`No encrypted key found for: ${name}`);
    }

    const salt = new Uint8Array(encryptedData.salt);
    const iv = new Uint8Array(encryptedData.iv);
    const ciphertext = new Uint8Array(encryptedData.ciphertext);

    const key = await this.deriveKey(password, salt);
    
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        ciphertext
      );

      const decoder = new TextDecoder();
      const jwkString = decoder.decode(plaintext);
      return JSON.parse(jwkString);
    } catch (error) {
      throw new Error('Invalid password or corrupted key data');
    }
  }

  async storeEncryptedKey(encryptedData) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.put(encryptedData);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async getEncryptedKey(name) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readonly');
      const store = transaction.objectStore(this.storeName);
      const request = store.get(name);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async deleteKey(name) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.delete(name);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async hasKey(name) {
    const result = await this.getEncryptedKey(name);
    return !!result;
  }

  async migrateFromLocalStorage(password) {
    const keysToMigrate = [
      'fk_identityKey',
      'fk_signedPreKey',
      'fk_oneTimePreKeys'
    ];

    const migrated = [];
    for (const keyName of keysToMigrate) {
      const stored = localStorage.getItem(keyName);
      if (stored) {
        try {
          const jwk = JSON.parse(stored);
          await this.encryptPrivateKey(keyName, jwk, password);
          localStorage.removeItem(keyName);
          migrated.push(keyName);
        } catch (error) {
          console.error(`Failed to migrate ${keyName}:`, error);
        }
      }
    }
    return migrated;
  }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecureKeyStorage;
}
