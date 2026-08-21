/**
 * FIBEMATE Quantum Integration Module
 * 量子集成模块 - 统一入口
 *
 * 功能：
 * - 自动检测量子网络可用性
 * - 管理量子适配器和密码学模块
 * - 与FIBEMATE核心集成
 * - 提供量子增强的API
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class QuantumIntegration {
  constructor(fibemateCore, options = {}) {
    this.core = fibemateCore;
    this.config = {
      autoDetect: options.autoDetect !== false,
      autoEnable: options.autoEnable !== false,
      qkdEndpoint: options.qkdEndpoint || null,
      qrngEndpoint: options.qrngEndpoint || null,
      debug: options.debug || false
    };

    this.state = {
      initialized: false,
      quantumAvailable: false,
      active: false
    };

    this.adapter = null;
    this.crypto = null;
  }

  /**
   * 初始化量子集成
   */
  async init() {
    this._log('Initializing Quantum Integration...');

    // 创建量子适配器
    this.adapter = new QuantumAdapter({
      qkdEndpoint: this.config.qkdEndpoint,
      qrngEndpoint: this.config.qrngEndpoint,
      debug: this.config.debug
    });

    // 创建量子密码学模块
    this.crypto = new QuantumCrypto({
      quantumAdapter: this.adapter,
      hybridMode: true,
      debug: this.config.debug
    });

    // 初始化
    const adapterReady = await this.adapter.init();
    await this.crypto.init();

    this.state.quantumAvailable = adapterReady;
    this.state.initialized = true;

    if (this.config.autoEnable && this.state.quantumAvailable) {
      await this.enable();
    }

    this._log(`Quantum Integration initialized: available=${this.state.quantumAvailable}`);
    return this.state.quantumAvailable;
  }

  /**
   * 启用量子增强
   */
  async enable() {
    if (!this.state.quantumAvailable) {
      this._warn('Quantum not available, cannot enable');
      return false;
    }

    this.state.active = true;
    this._log('Quantum enhancement enabled');

    // 触发事件
    this._emit('quantumEnabled');

    return true;
  }

  /**
   * 禁用量子增强
   */
  disable() {
    this.state.active = false;
    this._log('Quantum enhancement disabled');
    this._emit('quantumDisabled');
  }

  /**
   * 销毁
   */
  destroy() {
    if (this.adapter) {
      this.adapter.destroy();
    }
    this.state.active = false;
    this.state.initialized = false;
    this._log('Quantum Integration destroyed');
  }

  /**
   * 获取状态
   */
  getStatus() {
    return {
      initialized: this.state.initialized,
      quantumAvailable: this.state.quantumAvailable,
      active: this.state.active,
      qkdAvailable: this.adapter ? this.adapter.state.qkdAvailable : false,
      qrngAvailable: this.adapter ? this.adapter.state.qrngAvailable : false
    };
  }

  /**
   * 量子增强的密钥交换
   */
  async enhanceKeyExchange(peerId, classicalKey) {
    if (!this.state.active) {
      return { type: 'classical', key: classicalKey };
    }

    try {
      const result = await this.crypto.generateHybridKey(peerId, classicalKey);
      this._log(`Key exchange enhanced for ${peerId}: ${result.type}`);
      return result;
    } catch (error) {
      this._error('Key enhancement failed:', error);
      return { type: 'classical', key: classicalKey };
    }
  }

  /**
   * 量子增强的加密
   */
  async encrypt(peerId, plaintext, nonce) {
    if (!this.state.active) {
      throw new Error('Quantum enhancement not active');
    }

    return this.crypto.encrypt(peerId, plaintext, nonce);
  }

  /**
   * 量子增强的解密
   */
  async decrypt(peerId, ciphertext, iv) {
    if (!this.state.active) {
      throw new Error('Quantum enhancement not active');
    }

    return this.crypto.decrypt(peerId, ciphertext, iv);
  }

  /**
   * 获取量子随机数
   */
  async getQuantumRandom(length = 32) {
    if (!this.adapter) {
      // 回退到Web Crypto
      const random = new Uint8Array(length);
      crypto.getRandomValues(random);
      return random;
    }

    return this.adapter.getQuantumRandom(length);
  }

  /**
   * 安全擦除所有量子密钥
   */
  secureEraseAll() {
    if (this.crypto) {
      for (const peerId of this.crypto.state.hybridKeys.keys()) {
        this.crypto.secureErase(peerId);
      }
    }
    this._log('All quantum keys securely erased');
  }

  /**
   * 发射事件
   */
  _emit(eventName, data = null) {
    const event = new CustomEvent(eventName, { detail: data });
    window.dispatchEvent(event);

    if (this.core && this.core.emit) {
      this.core.emit(eventName, data);
    }
  }

  /**
   * 日志
   */
  _log(...args) {
    if (this.config.debug) {
      console.log('[QuantumIntegration]', ...args);
    }
  }

  _warn(...args) {
    console.warn('[QuantumIntegration]', ...args);
  }

  _error(...args) {
    console.error('[QuantumIntegration]', ...args);
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = QuantumIntegration;
}

if (typeof window !== 'undefined') {
  window.QuantumIntegration = QuantumIntegration;
}
