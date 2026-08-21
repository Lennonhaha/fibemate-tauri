/**
 * FIBEMATE Satellite Integration
 * 卫星网络适配集成模块 - 统一入口
 * 
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

// 引入依赖（实际使用时通过script标签或import）
// import { NetworkDetector } from './network-detector.js';
// import { SatelliteMode } from './satellite-mode.js';
// import { ForwardErrorCorrection } from './fec.js';
// import { RapidReconnect } from './rapid-reconnect.js';

class SatelliteIntegration {
  constructor(fibemateCore, options = {}) {
    this.core = fibemateCore;
    this.options = {
      autoDetect: options.autoDetect !== false,  // 默认自动检测
      autoSwitch: options.autoSwitch !== false,  // 默认自动切换
      debug: options.debug || false,
      ...options
    };
    
    // 子模块
    this.detector = null;
    this.satelliteMode = null;
    this.fec = null;
    this.reconnect = null;
    
    // 状态
    this.isInitialized = false;
    this.currentMode = 'normal';  // 'normal' | 'satellite'
    
    this.log('SatelliteIntegration created');
  }

  /**
   * 初始化
   */
  init() {
    if (this.isInitialized) {
      return;
    }
    
    this.log('Initializing satellite integration...');
    
    // 1. 初始化网络检测器
    this.detector = new NetworkDetector({
      debug: this.options.debug
    });
    
    // 2. 初始化卫星模式
    this.satelliteMode = new SatelliteMode(this.core, {
      debug: this.options.debug
    });
    
    // 3. 初始化FEC
    this.fec = new ForwardErrorCorrection({
      redundancy: 0.3,
      debug: this.options.debug
    });
    
    // 4. 初始化快速重连
    this.reconnect = new RapidReconnect({
      maxAttempts: 10,
      baseInterval: 1000,
      debug: this.options.debug
    });
    
    // 5. 设置网络变化监听
    if (this.options.autoDetect) {
      this.setupNetworkMonitoring();
    }
    
    // 6. 设置WebSocket事件
    this.setupWebSocketHandlers();
    
    this.isInitialized = true;
    this.log('Satellite integration initialized');
    
    // 触发初始化完成事件
    this.core.emit('satelliteIntegrationReady', {
      autoDetect: this.options.autoDetect,
      autoSwitch: this.options.autoSwitch
    });
  }

  /**
   * 设置网络监测
   */
  setupNetworkMonitoring() {
    this.log('Setting up network monitoring...');
    
    // 监听网络类型变化
    this.detector.addListener((newType, oldType) => {
      this.log(`Network changed: ${oldType} -> ${newType}`);
      
      if (this.options.autoSwitch) {
        this.handleNetworkChange(newType);
      }
      
      // 触发事件
      this.core.emit('networkChanged', {
        newType,
        oldType,
        timestamp: Date.now()
      });
    });
    
    // 开始监测
    this.detector.startMonitoring();
    
    // 立即检测一次
    this.detector.detect().then(type => {
      this.log(`Initial network type: ${type}`);
      if (this.options.autoSwitch) {
        this.handleNetworkChange(type);
      }
    });
  }

  /**
   * 处理网络变化
   * @param {string} networkType
   */
  handleNetworkChange(networkType) {
    const isSatellite = networkType === 'satellite';
    const isOffline = networkType === 'offline';
    
    if (isOffline) {
      this.log('Network offline, entering offline mode...');
      this.enterOfflineMode();
      return;
    }
    
    if (isSatellite && this.currentMode !== 'satellite') {
      this.log('Satellite network detected, switching to satellite mode...');
      this.enterSatelliteMode();
    } else if (!isSatellite && this.currentMode === 'satellite') {
      this.log('Non-satellite network detected, switching to normal mode...');
      this.enterNormalMode();
    }
  }

  /**
   * 进入卫星模式
   */
  enterSatelliteMode() {
    if (this.currentMode === 'satellite') {
      return;
    }
    
    this.currentMode = 'satellite';
    
    // 激活卫星模式
    this.satelliteMode.apply();
    
    // 启用FEC
    this.core.setPacketEncoder((data) => {
      return this.fec.encode(data);
    });
    
    this.core.setPacketDecoder((packets, total) => {
      return this.fec.decode(packets, total);
    });
    
    this.log('Entered satellite mode');
    
    this.core.emit('satelliteModeEntered', {
      timestamp: Date.now(),
      config: this.satelliteMode.getInfo()
    });
  }

  /**
   * 进入普通模式
   */
  enterNormalMode() {
    if (this.currentMode === 'normal') {
      return;
    }
    
    this.currentMode = 'normal';
    
    // 停用卫星模式
    this.satelliteMode.deactivate();
    
    // 禁用FEC
    this.core.setPacketEncoder(null);
    this.core.setPacketDecoder(null);
    
    this.log('Entered normal mode');
    
    this.core.emit('normalModeEntered', {
      timestamp: Date.now()
    });
  }

  /**
   * 进入离线模式
   */
  enterOfflineMode() {
    this.core.emit('offlineModeEntered', {
      timestamp: Date.now()
    });
  }

  /**
   * 设置WebSocket处理器
   */
  setupWebSocketHandlers() {
    // WebSocket断开时自动重连
    this.core.on('websocketClose', (event) => {
      this.log('WebSocket closed, initiating rapid reconnect...');
      
      this.reconnect.reconnect(async () => {
        const ws = await this.core.createWebSocket();
        
        // 等待连接建立
        await new Promise((resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error('WebSocket connection timeout'));
          }, 10000);
          
          ws.onopen = () => {
            clearTimeout(timeout);
            resolve();
          };
          
          ws.onerror = (error) => {
            clearTimeout(timeout);
            reject(error);
          };
        });
        
        return ws;
      }).then(() => {
        this.log('WebSocket reconnected successfully');
      }).catch((error) => {
        this.log('WebSocket reconnection failed:', error.message);
      });
    });
  }

  /**
   * 手动切换模式
   * @param {string} mode - 'satellite' | 'normal'
   */
  switchMode(mode) {
    if (mode === 'satellite') {
      this.enterSatelliteMode();
    } else if (mode === 'normal') {
      this.enterNormalMode();
    } else {
      throw new Error(`Unknown mode: ${mode}`);
    }
  }

  /**
   * 获取当前状态
   * @returns {Object}
   */
  getStatus() {
    return {
      isInitialized: this.isInitialized,
      currentMode: this.currentMode,
      networkType: this.detector ? this.detector.currentType : 'unknown',
      detector: this.detector ? this.detector.getInfo() : null,
      satelliteMode: this.satelliteMode ? this.satelliteMode.getInfo() : null,
      fec: this.fec ? this.fec.getStats() : null,
      reconnect: this.reconnect ? this.reconnect.getStats() : null
    };
  }

  /**
   * 销毁
   */
  destroy() {
    this.log('Destroying satellite integration...');
    
    if (this.detector) {
      this.detector.stopMonitoring();
    }
    
    if (this.satelliteMode) {
      this.satelliteMode.deactivate();
    }
    
    this.isInitialized = false;
    this.currentMode = 'normal';
    
    this.log('Satellite integration destroyed');
  }

  /**
   * 日志
   * @param {...any} args
   */
  log(...args) {
    if (this.options.debug) {
      console.log('[SatelliteIntegration]', ...args);
    }
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SatelliteIntegration;
}

if (typeof window !== 'undefined') {
  window.SatelliteIntegration = SatelliteIntegration;
}
