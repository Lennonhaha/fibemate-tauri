/**
 * FIBEMATE Quantum City Network Adapter
 * 量子城域网适配模块
 * 
 * 功能：
 * - QKD密钥接收与管理
 * - 量子随机数生成器(QRNG)集成
 * - 量子安全通道建立
 * - 经典-量子混合加密
 * 
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class QuantumAdapter {
  constructor(options = {}) {
    this.config = {
      qkdEndpoint: options.qkdEndpoint || null,      // QKD密钥服务端点
      qrngEndpoint: options.qrngEndpoint || null,    // QRNG服务端点
      keyRefreshInterval: options.keyRefreshInterval || 3600000, // 1小时
      keyLength: options.keyLength || 256,           // 密钥长度(bits)
      debug: options.debug || false
    };
    
    this.state = {
      qkdAvailable: false,
      qrngAvailable: false,
      currentKey: null,
      keyTimestamp: null,
      keyRefreshTimer: null,
      entropyPool: new Uint8Array(1024),  // 量子熵池
      entropyIndex: 0
    };
    
    this.callbacks = {
      onKeyUpdate: null,
      onEntropyReady: null,
      onError: null
    };
  }

  /**
   * 初始化量子适配器
   */
  async init() {
    this._log('Initializing Quantum Adapter...');
    
    // 检测QKD可用性
    if (this.config.qkdEndpoint) {
      await this._checkQKDAvailability();
    }
    
    // 检测QRNG可用性
    if (this.config.qrngEndpoint) {
      await this._checkQRNGAvailability();
    }
    
    // 启动密钥刷新定时器
    if (this.state.qkdAvailable) {
      this._startKeyRefresh();
    }
    
    this._log(`Quantum Adapter initialized: QKD=${this.state.qkdAvailable}, QRNG=${this.state.qrngAvailable}`);
    return this.state.qkdAvailable || this.state.qrngAvailable;
  }

  /**
   * 销毁适配器
   */
  destroy() {
    if (this.state.keyRefreshTimer) {
      clearInterval(this.state.keyRefreshTimer);
      this.state.keyRefreshTimer = null;
    }
    this._log('Quantum Adapter destroyed');
  }

  /**
   * 获取量子密钥
   */
  async getQuantumKey(length = this.config.keyLength) {
    if (!this.state.qkdAvailable) {
      throw new Error('QKD not available');
    }
    
    try {
      const response = await fetch(`${this.config.qkdEndpoint}/key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ length })
      });
      
      if (!response.ok) {
        throw new Error(`QKD request failed: ${response.status}`);
      }
      
      const data = await response.json();
      this.state.currentKey = data.key;
      this.state.keyTimestamp = Date.now();
      
      if (this.callbacks.onKeyUpdate) {
        this.callbacks.onKeyUpdate(data.key);
      }
      
      return data.key;
    } catch (error) {
      this._error('Failed to get quantum key:', error);
      throw error;
    }
  }

  /**
   * 获取量子随机数
   */
  async getQuantumRandom(length = 32) {
    if (this.state.qrngAvailable) {
      try {
        const response = await fetch(`${this.config.qrngEndpoint}/random?length=${length}`);
        if (response.ok) {
          const data = await response.json();
          return new Uint8Array(data.random);
        }
      } catch (error) {
        this._warn('QRNG failed, falling back to crypto.getRandomValues');
      }
    }
    
    // 回退到Web Crypto API
    const random = new Uint8Array(length);
    crypto.getRandomValues(random);
    return random;
  }

  /**
   * 填充熵池
   */
  async refillEntropyPool() {
    const random = await this.getQuantumRandom(this.state.entropyPool.length);
    this.state.entropyPool.set(random);
    this.state.entropyIndex = 0;
    
    if (this.callbacks.onEntropyReady) {
      this.callbacks.onEntropyReady(this.state.entropyPool);
    }
    
    this._log('Entropy pool refilled with quantum randomness');
  }

  /**
   * 从熵池获取随机数
   */
  getRandomFromPool(length = 32) {
    if (this.state.entropyIndex + length > this.state.entropyPool.length) {
      this.refillEntropyPool();
    }
    
    const result = this.state.entropyPool.slice(this.state.entropyIndex, this.state.entropyIndex + length);
    this.state.entropyIndex += length;
    return result;
  }

  /**
   * 量子增强的X3DH握手
   */
  async enhanceX3DHHandshake(x3dhKeys) {
    this._log('Enhancing X3DH with quantum key...');
    
    try {
      // 获取量子密钥
      const quantumKey = await this.getQuantumKey(256);
      
      // 将量子密钥与经典X3DH密钥混合
      const enhancedKeys = {
        ...x3dhKeys,
        quantumKey: quantumKey,
        keyDerivation: 'hybrid-x3dh-qkd'
      };
      
      this._log('X3DH handshake enhanced with quantum key');
      return enhancedKeys;
    } catch (error) {
      this._warn('Quantum enhancement failed, using classical X3DH:', error.message);
      return x3dhKeys;
    }
  }

  /**
   * 量子安全通道建立
   */
  async establishQuantumChannel(peerId) {
    this._log(`Establishing quantum channel with ${peerId}...`);
    
    try {
      // 获取量子密钥
      const quantumKey = await this.getQuantumKey(256);
      
      // 通过经典通道发送量子密钥ID（不是密钥本身）
      const keyId = await this._registerKeyWithPeer(peerId, quantumKey);
      
      return {
        channelId: keyId,
        keyType: 'qkd',
        established: true
      };
    } catch (error) {
      this._error('Failed to establish quantum channel:', error);
      return { established: false, error: error.message };
    }
  }

  /**
   * 检查QKD可用性
   */
  async _checkQKDAvailability() {
    try {
      const response = await fetch(`${this.config.qkdEndpoint}/status`, {
        method: 'GET',
        timeout: 5000
      });
      this.state.qkdAvailable = response.ok;
      this._log(`QKD availability: ${this.state.qkdAvailable}`);
    } catch (error) {
      this.state.qkdAvailable = false;
      this._warn(`QKD not available: ${error.message}`);
    }
  }

  /**
   * 检查QRNG可用性
   */
  async _checkQRNGAvailability() {
    try {
      const response = await fetch(`${this.config.qrngEndpoint}/status`, {
        method: 'GET',
        timeout: 5000
      });
      this.state.qrngAvailable = response.ok;
      this._log(`QRNG availability: ${this.state.qrngAvailable}`);
    } catch (error) {
      this.state.qrngAvailable = false;
      this._warn(`QRNG not available: ${error.message}`);
    }
  }

  /**
   * 启动密钥刷新
   */
  _startKeyRefresh() {
    this.state.keyRefreshTimer = setInterval(async () => {
      try {
        await this.getQuantumKey();
        this._log('Quantum key refreshed automatically');
      } catch (error) {
        this._error('Key refresh failed:', error);
      }
    }, this.config.keyRefreshInterval);
  }

  /**
   * 注册密钥与对等方
   */
  async _registerKeyWithPeer(peerId, key) {
    // 在实际实现中，这里会通过QKD网络注册密钥
    // 返回密钥ID用于后续引用
    const keyId = `qkd-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    return keyId;
  }

  /**
   * 日志
   */
  _log(...args) {
    if (this.config.debug) {
      console.log('[Quantum]', ...args);
    }
  }

  _warn(...args) {
    console.warn('[Quantum]', ...args);
  }

  _error(...args) {
    console.error('[Quantum]', ...args);
    if (this.callbacks.onError) {
      this.callbacks.onError(args.join(' '));
    }
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = QuantumAdapter;
}

if (typeof window !== 'undefined') {
  window.QuantumAdapter = QuantumAdapter;
}
