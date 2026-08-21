/**
 * FIBEMATE Network Detector
 * 检测当前网络类型（5G/4G/WiFi/卫星）并触发模式切换
 * 
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class NetworkDetector {
  constructor(options = {}) {
    // Network Information API
    this.connection = navigator.connection || 
                      navigator.mozConnection || 
                      navigator.webkitConnection;
    
    // 当前网络类型
    this.currentType = 'unknown';
    this.previousType = 'unknown';
    
    // 性能指标
    this.metrics = {
      rttSamples: [],
      packetLoss: 0,
      jitter: 0,
      bandwidth: 0
    };
    
    // 配置
    this.config = {
      checkInterval: options.checkInterval || 5000,      // 检测间隔（毫秒）
      rttSamples: options.rttSamples || 5,               // RTT采样次数
      rttTimeout: options.rttTimeout || 3000,            // RTT超时时间
      satelliteRTTThreshold: options.satelliteRTTThreshold || 200,  // 卫星RTT阈值
      5gRTTThreshold: options['5gRTTThreshold'] || 50,   // 5G RTT阈值
      packetLossThreshold: options.packetLossThreshold || 10,       // 丢包率阈值
      debug: options.debug || false
    };
    
    // 状态
    this.isMonitoring = false;
    this.monitorInterval = null;
    this.listeners = [];
    
    // 绑定方法
    this.detect = this.detect.bind(this);
    this.startMonitoring = this.startMonitoring.bind(this);
    this.stopMonitoring = this.stopMonitoring.bind(this);
    
    // 初始化
    this.init();
  }

  /**
   * 初始化
   */
  init() {
    // 监听网络变化事件
    if (this.connection) {
      this.connection.addEventListener('change', this.handleNetworkChange.bind(this));
    }
    
    // 监听在线/离线事件
    window.addEventListener('online', () => this.handleOnlineStatus(true));
    window.addEventListener('offline', () => this.handleOnlineStatus(false));
    
    this.log('NetworkDetector initialized');
  }

  /**
   * 检测当前网络类型
   * @returns {Promise<string>} 网络类型: '5g' | '4g' | 'wifi' | 'satellite' | 'slow-2g' | 'unknown'
   */
  async detect() {
    this.log('Starting network detection...');
    
    // 方法1: Network Information API（快速但不够准确）
    const infoType = this.detectFromNetworkInfo();
    this.log(`Network Info API result: ${infoType}`);
    
    // 方法2: RTT探测（更准确）
    const rtt = await this.measureRTT();
    this.log(`RTT measurement: ${rtt}ms`);
    
    // 方法3: 丢包率探测
    const packetLoss = await this.measurePacketLoss();
    this.log(`Packet loss: ${packetLoss}%`);
    
    // 综合判断
    const type = this.classifyNetwork(infoType, rtt, packetLoss);
    this.log(`Final classification: ${type}`);
    
    // 更新指标
    this.metrics.rttSamples.push(rtt);
    if (this.metrics.rttSamples.length > 10) {
      this.metrics.rttSamples.shift();
    }
    this.metrics.packetLoss = packetLoss;
    
    return type;
  }

  /**
   * 从 Network Information API 检测
   * @returns {string}
   */
  detectFromNetworkInfo() {
    if (!this.connection) {
      return 'unknown';
    }
    
    const type = this.connection.effectiveType;  // '4g', '3g', '2g', 'slow-2g'
    const downlink = this.connection.downlink;   // Mbps
    const rtt = this.connection.rtt;             // ms (Chrome only)
    
    this.log(`Network Info: type=${type}, downlink=${downlink}Mbps, rtt=${rtt}ms`);
    
    // 根据下行带宽判断
    if (downlink > 100) {
      return '5g';
    } else if (downlink > 20) {
      return '4g';
    } else if (downlink > 5) {
      return '3g';
    } else if (downlink > 0) {
      return 'slow-2g';
    }
    
    return type || 'unknown';
  }

  /**
   * 测量 RTT（往返时间）
   * @returns {Promise<number>} RTT毫秒数，失败返回Infinity
   */
  async measureRTT() {
    const samples = [];
    
    for (let i = 0; i < this.config.rttSamples; i++) {
      const start = performance.now();
      
      try {
        // 使用 HEAD 请求减少数据传输
        await fetch('/api/ping?t=' + Date.now(), {
          method: 'HEAD',
          cache: 'no-store',
          signal: AbortSignal.timeout(this.config.rttTimeout)
        });
        
        const rtt = performance.now() - start;
        samples.push(rtt);
        
      } catch (error) {
        this.log(`RTT sample ${i + 1} failed: ${error.message}`);
        samples.push(Infinity);
      }
      
      // 间隔100ms再测，避免突发
      if (i < this.config.rttSamples - 1) {
        await this.sleep(100);
      }
    }
    
    // 过滤掉失败的样本
    const validSamples = samples.filter(s => s !== Infinity);
    
    if (validSamples.length === 0) {
      return Infinity;
    }
    
    // 取中位数（避免异常值影响）
    validSamples.sort((a, b) => a - b);
    const median = validSamples[Math.floor(validSamples.length / 2)];
    
    return Math.round(median);
  }

  /**
   * 测量丢包率
   * @returns {Promise<number>} 丢包率百分比
   */
  async measurePacketLoss() {
    const packets = 10;  // 发送10个包
    let lost = 0;
    
    for (let i = 0; i < packets; i++) {
      try {
        await fetch('/api/ping', {
          method: 'HEAD',
          cache: 'no-store',
          signal: AbortSignal.timeout(2000)
        });
      } catch (error) {
        lost++;
      }
      
      // 间隔50ms
      if (i < packets - 1) {
        await this.sleep(50);
      }
    }
    
    return Math.round((lost / packets) * 100);
  }

  /**
   * 综合分类网络类型
   * @param {string} infoType - Network Info API结果
   * @param {number} rtt - RTT毫秒数
   * @param {number} packetLoss - 丢包率
   * @returns {string}
   */
  classifyNetwork(infoType, rtt, packetLoss) {
    // 离线状态
    if (!navigator.onLine) {
      return 'offline';
    }
    
    // RTT异常高 -> 卫星网络
    if (rtt > this.config.satelliteRTTThreshold) {
      return 'satellite';
    }
    
    // 高丢包率 + 中等延迟 -> 也可能是卫星
    if (packetLoss > this.config.packetLossThreshold && rtt > 100) {
      return 'satellite';
    }
    
    // RTT很低 -> 5G或光纤
    if (rtt < this.config['5gRTTThreshold']) {
      if (infoType === '5g' || infoType === '4g') {
        return '5g';
      }
      return 'wifi';  // 光纤WiFi也很快
    }
    
    // 根据Network Info类型
    switch (infoType) {
      case '5g':
        return '5g';
      case '4g':
        return rtt > 100 ? 'satellite' : '4g';
      case '3g':
        return '3g';
      case 'slow-2g':
        return 'slow-2g';
      default:
        // 无法确定，根据RTT判断
        if (rtt < 50) return 'wifi';
        if (rtt < 100) return '4g';
        return 'satellite';
    }
  }

  /**
   * 开始持续监测
   * @param {Function} callback - 网络类型变化时的回调
   */
  startMonitoring(callback) {
    if (this.isMonitoring) {
      this.log('Monitoring already started');
      return;
    }
    
    this.isMonitoring = true;
    
    // 添加回调
    if (callback) {
      this.listeners.push(callback);
    }
    
    // 立即执行一次检测
    this.detect().then(type => {
      this.currentType = type;
      this.notifyListeners(type);
    });
    
    // 定时检测
    this.monitorInterval = setInterval(async () => {
      const type = await this.detect();
      
      if (type !== this.currentType) {
        this.log(`Network changed: ${this.currentType} -> ${type}`);
        this.previousType = this.currentType;
        this.currentType = type;
        this.notifyListeners(type);
      }
    }, this.config.checkInterval);
    
    this.log(`Monitoring started (interval: ${this.config.checkInterval}ms)`);
  }

  /**
   * 停止监测
   */
  stopMonitoring() {
    if (!this.isMonitoring) {
      return;
    }
    
    this.isMonitoring = false;
    
    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
      this.monitorInterval = null;
    }
    
    this.log('Monitoring stopped');
  }

  /**
   * 添加监听器
   * @param {Function} callback
   */
  addListener(callback) {
    this.listeners.push(callback);
  }

  /**
   * 移除监听器
   * @param {Function} callback
   */
  removeListener(callback) {
    this.listeners = this.listeners.filter(l => l !== callback);
  }

  /**
   * 通知所有监听器
   * @param {string} type
   */
  notifyListeners(type) {
    this.listeners.forEach(callback => {
      try {
        callback(type, this.previousType);
      } catch (error) {
        console.error('Network listener error:', error);
      }
    });
  }

  /**
   * 处理网络变化事件
   */
  handleNetworkChange() {
    this.log('Network change event detected');
    
    // 延迟检测，等待网络稳定
    setTimeout(() => {
      this.detect().then(type => {
        if (type !== this.currentType) {
          this.previousType = this.currentType;
          this.currentType = type;
          this.notifyListeners(type);
        }
      });
    }, 1000);
  }

  /**
   * 处理在线状态变化
   * @param {boolean} isOnline
   */
  handleOnlineStatus(isOnline) {
    this.log(`Online status changed: ${isOnline}`);
    
    if (!isOnline) {
      this.previousType = this.currentType;
      this.currentType = 'offline';
      this.notifyListeners('offline');
    } else {
      // 恢复在线后重新检测
      setTimeout(() => {
        this.detect().then(type => {
          this.currentType = type;
          this.notifyListeners(type);
        });
      }, 2000);
    }
  }

  /**
   * 获取当前网络信息
   * @returns {Object}
   */
  getInfo() {
    return {
      type: this.currentType,
      previousType: this.previousType,
      metrics: { ...this.metrics },
      connection: this.connection ? {
        effectiveType: this.connection.effectiveType,
        downlink: this.connection.downlink,
        rtt: this.connection.rtt,
        saveData: this.connection.saveData
      } : null
    };
  }

  /**
   * 判断是否卫星网络
   * @returns {boolean}
   */
  isSatellite() {
    return this.currentType === 'satellite';
  }

  /**
   * 判断是否5G网络
   * @returns {boolean}
   */
  is5G() {
    return this.currentType === '5g';
  }

  /**
   * 判断是否高速网络
   * @returns {boolean}
   */
  isFast() {
    return ['5g', 'wifi'].includes(this.currentType);
  }

  /**
   * 日志输出
   * @param {...any} args
   */
  log(...args) {
    if (this.config.debug) {
      console.log('[NetworkDetector]', ...args);
    }
  }

  /**
   * 睡眠
   * @param {number} ms
   * @returns {Promise<void>}
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = NetworkDetector;
}

// 浏览器环境
if (typeof window !== 'undefined') {
  window.NetworkDetector = NetworkDetector;
}
