/**
 * FIBEMATE 5G-A Integration Module
 * 5G-A集成模块 - 统一入口
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class FiveGIntegration {
  constructor(fibemateCore, options = {}) {
    this.core = fibemateCore;
    this.config = {
      autoDetect: options.autoDetect !== false,
      autoEnable: options.autoEnable !== false,
      edgeEndpoints: options.edgeEndpoints || [],
      debug: options.debug || false
    };

    this.state = {
      initialized: false,
      active: false,
      is5GAvailable: false,
      is5GA: false
    };

    this.adapter = null;
    this.optimization = null;
  }

  /**
   * 初始化5G-A集成
   */
  async init() {
    this._log('Initializing 5G-A Integration...');

    // 创建适配器
    this.adapter = new FiveGAdapter({
      edgeEndpoints: this.config.edgeEndpoints,
      debug: this.config.debug
    });

    // 初始化适配器
    const adapterReady = await this.adapter.init();

    // 创建优化模块
    this.optimization = new FiveGOptimization(this.adapter, {
      debug: this.config.debug
    });
    await this.optimization.init();

    this.state.is5GAvailable = adapterReady;
    this.state.is5GA = this.adapter.state.is5GA;
    this.state.initialized = true;

    if (this.config.autoEnable && this.state.is5GAvailable) {
      await this.enable();
    }

    this._log(`5G-A Integration initialized: 5G=${this.state.is5GAvailable}, 5G-A=${this.state.is5GA}`);
    return this.state.is5GAvailable;
  }

  /**
   * 启用5G-A优化
   */
  async enable() {
    if (!this.state.is5GAvailable) {
      this._warn('5G not available, cannot enable');
      return false;
    }

    this.state.active = true;
    this._log('5G-A optimization enabled');
    this._emit('5gEnabled', { is5GA: this.state.is5GA });
    return true;
  }

  /**
   * 禁用
   */
  disable() {
    this.state.active = false;
    this._log('5G-A optimization disabled');
    this._emit('5gDisabled');
  }

  /**
   * 销毁
   */
  destroy() {
    if (this.adapter) {
      this.adapter.destroy();
    }
    if (this.optimization) {
      this.optimization.destroy();
    }
    this.state.active = false;
    this.state.initialized = false;
    this._log('5G-A Integration destroyed');
  }

  /**
   * 获取状态
   */
  getStatus() {
    return {
      initialized: this.state.initialized,
      active: this.state.active,
      is5GAvailable: this.state.is5GAvailable,
      is5GA: this.state.is5GA,
      adapter: this.adapter ? this.adapter.getStatus() : null
    };
  }

  /**
   * 优化消息发送
   */
  async optimizeMessageSend(message, priority = 'normal') {
    if (!this.state.active) {
      return { strategy: 'normal', message };
    }

    return this.optimization.optimizeMessageSend(message, priority);
  }

  /**
   * 优化媒体传输
   */
  async optimizeMediaTransfer(file, type = 'auto') {
    if (!this.state.active) {
      return { strategy: 'normal', file };
    }

    return this.optimization.optimizeMediaTransfer(file, type);
  }

  /**
   * 边缘计算卸载
   */
  async offloadToEdge(taskType, data) {
    if (!this.state.active) {
      return { offloaded: false, reason: '5G-A not active' };
    }

    return this.optimization.offloadToEdge(taskType, data);
  }

  /**
   * 获取自适应码率
   */
  getAdaptiveBitrate() {
    if (!this.optimization) {
      return { video: 1000, audio: 128 };
    }
    return this.optimization.getAdaptiveBitrate();
  }

  /**
   * 预测性预取
   */
  async predictivePrefetch(contactList) {
    if (!this.state.active) {
      return;
    }

    return this.optimization.predictivePrefetch(contactList);
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
      console.log('[5G-Integration]', ...args);
    }
  }

  _warn(...args) {
    console.warn('[5G-Integration]', ...args);
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FiveGIntegration;
}

if (typeof window !== 'undefined') {
  window.FiveGIntegration = FiveGIntegration;
}
