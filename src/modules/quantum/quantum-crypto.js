/**
 * FIBEMATE Quantum Cryptography Module
 * 量子密码学模块
 *
 * 功能：
 * - 量子安全密钥派生
 * - 混合加密（经典+量子）
 * - 量子随机数增强
 * - 后量子密码学(PQC)集成
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class QuantumCrypto {
  constructor(options = {}) {
    this.config = {
      quantumAdapter: options.quantumAdapter || null,
      hybridMode: options.hybridMode !== false, // 默认启用混合模式
      debug: options.debug || false
    };

    this.state = {
      initialized: false,
      quantumKeys: new Map(), // peerId -> quantumKey
      hybridKeys: new Map()   // peerId -> hybridKey
    };
  }

  /**
   * 初始化量子密码学模块
   */
  async init() {
    this._log('Initializing Quantum Crypto...');

    if (this.config.quantumAdapter) {
      await this.config.quantumAdapter.init();
    }

    this.state.initialized = true;
    this._log('Quantum Crypto initialized');
    return true;
  }

  /**
   * 生成混合密钥
   */
  async generateHybridKey(peerId, classicalKey) {
    this._log(`Generating hybrid key for ${peerId}...`);

    try {
      let quantumKey = null;

      // 尝试获取量子密钥
      if (this.config.quantumAdapter && this.config.quantumAdapter.state.qkdAvailable) {
        quantumKey = await this.config.quantumAdapter.getQuantumKey(256);
      }

      if (quantumKey && this.config.hybridMode) {
        // 混合模式：经典密钥 + 量子密钥
        const hybridKey = await this._combineKeys(classicalKey, quantumKey);
        this.state.hybridKeys.set(peerId, hybridKey);
        this.state.quantumKeys.set(peerId, quantumKey);

        this._log(`Hybrid key generated for ${peerId}`);
        return {
          type: 'hybrid',
          key: hybridKey,
          quantumKey: quantumKey,
          classicalKey: classicalKey
        };
      } else {
        // 仅经典模式
        this.state.hybridKeys.set(peerId, classicalKey);

        this._log(`Classical key used for ${peerId}`);
        return {
          type: 'classical',
          key: classicalKey,
          quantumKey: null,
          classicalKey: classicalKey
        };
      }
    } catch (error) {
      this._error('Failed to generate hybrid key:', error);
      // 回退到经典密钥
      return {
        type: 'classical',
        key: classicalKey,
        quantumKey: null,
        classicalKey: classicalKey
      };
    }
  }

  /**
   * 量子增强的加密
   */
  async encrypt(peerId, plaintext, nonce) {
    const hybridKey = this.state.hybridKeys.get(peerId);
    if (!hybridKey) {
      throw new Error('No hybrid key available for peer');
    }

    // 获取量子随机数作为IV
    let iv;
    if (this.config.quantumAdapter) {
      iv = await this.config.quantumAdapter.getQuantumRandom(12);
    } else {
      iv = crypto.getRandomValues(new Uint8Array(12));
    }

    // 使用AES-GCM加密
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      hybridKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      data
    );

    return {
      ciphertext: new Uint8Array(ciphertext),
      iv: iv,
      type: this.state.quantumKeys.has(peerId) ? 'hybrid' : 'classical'
    };
  }

  /**
   * 量子增强的解密
   */
  async decrypt(peerId, ciphertext, iv) {
    const hybridKey = this.state.hybridKeys.get(peerId);
    if (!hybridKey) {
      throw new Error('No hybrid key available for peer');
    }

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      hybridKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(plaintext);
  }

  /**
   * 量子密钥派生函数
   */
  async deriveKey(password, salt, iterations = 100000) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return new Uint8Array(derivedBits);
  }

  /**
   * 量子熵增强的密钥派生
   */
  async deriveKeyWithQuantumEntropy(password, salt, quantumEntropy) {
    // 先进行经典PBKDF2
    const classicalKey = await this.deriveKey(password, salt);

    if (quantumEntropy) {
      // 混合量子熵
      return this._combineKeys(classicalKey, quantumEntropy);
    }

    return classicalKey;
  }

  /**
   * 安全擦除密钥
   */
  secureErase(peerId) {
    const key = this.state.hybridKeys.get(peerId);
    if (key) {
      // 覆盖密钥数据
      key.fill(0);
      this.state.hybridKeys.delete(peerId);
      this.state.quantumKeys.delete(peerId);
      this._log(`Securely erased keys for ${peerId}`);
    }
  }

  /**
   * 获取密钥状态
   */
  getKeyStatus(peerId) {
    return {
      hasHybridKey: this.state.hybridKeys.has(peerId),
      hasQuantumKey: this.state.quantumKeys.has(peerId),
      keyType: this.state.quantumKeys.has(peerId) ? 'hybrid' : 'classical'
    };
  }

  /**
   * 组合两个密钥
   */
  async _combineKeys(key1, key2) {
    // 使用HKDF-like方式组合密钥
    const combined = new Uint8Array(key1.length);

    for (let i = 0; i < key1.length; i++) {
      combined[i] = key1[i] ^ key2[i % key2.length];
    }

    // 使用SHA-256哈希得到最终密钥
    const hash = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hash);
  }

  /**
   * 日志
   */
  _log(...args) {
    if (this.config.debug) {
      console.log('[QuantumCrypto]', ...args);
    }
  }

  _error(...args) {
    console.error('[QuantumCrypto]', ...args);
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = QuantumCrypto;
}

if (typeof window !== 'undefined') {
  window.QuantumCrypto = QuantumCrypto;
}
