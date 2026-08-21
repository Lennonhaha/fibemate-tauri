/**
 * FIBEMATE Satellite Network Simulator
 * 卫星网络模拟器 - 用于测试卫星模式适配
 * 
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class SatelliteSimulator {
  constructor(options = {}) {
    // 卫星网络参数
    this.config = {
      // 延迟参数
      baseLatency: options.baseLatency || 150,        // 基础延迟 150ms
      jitter: options.jitter || 50,                   // 抖动 ±50ms
      
      // 丢包参数
      packetLoss: options.packetLoss || 0.05,         // 5%基础丢包
      burstLoss: options.burstLoss || 0.3,            // 突发丢包 30%
      
      // 切换参数
      handoverInterval: options.handoverInterval || 600000, // 10分钟切换
      handoverDuration: options.handoverDuration || 3000,   // 切换持续3秒
      
      // 带宽参数
      downlink: options.downlink || 100,              // 下行 100Mbps
      uplink: options.uplink || 10,                   // 上行 10Mbps
      
      // 模式
      mode: options.mode || 'satellite',              // 'satellite' | '5g' | 'wifi'
      
      debug: options.debug || false
    };
    
    // 状态
    this.isRunning = false;
    this.isHandover = false;
    this.startTime = 0;
    
    // 统计
    this.stats = {
      packetsSent: 0,
      packetsLost: 0,
      packetsDelayed: 0,
      handovers: 0,
      totalLatency: 0,
      avgLatency: 0
    };
    
    // 定时器
    this.timers = {};
    
    // 拦截器
    this.originalFetch = null;
    this.originalWebSocket = null;
    
    this.log('SatelliteSimulator created');
  }

  /**
   * 启动模拟
   */
  start() {
    if (this.isRunning) {
      return;
    }
    
    this.isRunning = true;
    this.startTime = Date.now();
    
    this.log(`Starting satellite simulation (${this.config.mode} mode)...`);
    
    // 拦截 fetch
    this.interceptFetch();
    
    // 拦截 WebSocket
    this.interceptWebSocket();
    
    // 启动切换模拟
    this.startHandoverSimulation();
    
    // 启动统计
    this.startStatsCollection();
    
    this.log('Satellite simulation started');
  }

  /**
   * 停止模拟
   */
  stop() {
    if (!this.isRunning) {
      return;
    }
    
    this.log('Stopping satellite simulation...');
    
    // 恢复原始 fetch
    if (this.originalFetch) {
      window.fetch = this.originalFetch;
      this.originalFetch = null;
    }
    
    // 恢复原始 WebSocket
    if (this.originalWebSocket) {
      window.WebSocket = this.originalWebSocket;
      this.originalWebSocket = null;
    }
    
    // 清除定时器
    this.clearAllTimers();
    
    this.isRunning = false;
    this.log('Satellite simulation stopped');
  }

  /**
   * 拦截 fetch
   */
  interceptFetch() {
    this.originalFetch = window.fetch;
    const simulator = this;
    
    window.fetch = async function(...args) {
      if (!simulator.isRunning) {
        return simulator.originalFetch.apply(this, args);
      }
      
      // 模拟延迟
      const latency = simulator.simulateLatency();
      await simulator.sleep(latency);
      
      // 模拟丢包
      if (simulator.simulatePacketLoss()) {
        simulator.stats.packetsLost++;
        throw new Error('Network request failed (simulated packet loss)');
      }
      
      simulator.stats.packetsSent++;
      simulator.stats.totalLatency += latency;
      
      // 调用原始 fetch
      return simulator.originalFetch.apply(this, args);
    };
    
    this.log('Fetch intercepted');
  }

  /**
   * 拦截 WebSocket
   */
  interceptWebSocket() {
    this.originalWebSocket = window.WebSocket;
    const simulator = this;
    
    window.WebSocket = function(...args) {
      const ws = new simulator.originalWebSocket(...args);
      
      // 拦截 send
      const originalSend = ws.send.bind(ws);
      ws.send = async function(data) {
        if (!simulator.isRunning) {
          return originalSend(data);
        }
        
        // 模拟延迟
        const latency = simulator.simulateLatency();
        await simulator.sleep(latency);
        
        // 模拟丢包
        if (simulator.simulatePacketLoss()) {
          simulator.stats.packetsLost++;
          return;
        }
        
        simulator.stats.packetsSent++;
        simulator.stats.totalLatency += latency;
        
        return originalSend(data);
      };
      
      return ws;
    };
    
    // 复制静态属性
    Object.setPrototypeOf(window.WebSocket, this.originalWebSocket);
    Object.keys(this.originalWebSocket).forEach(key => {
      if (!window.WebSocket[key]) {
        window.WebSocket[key] = this.originalWebSocket[key];
      }
    });
    
    this.log('WebSocket intercepted');
  }

  /**
   * 模拟延迟
   * @returns {number} 延迟毫秒数
   */
  simulateLatency() {
    const jitter = (Math.random() - 0.5) * 2 * this.config.jitter;
    const latency = Math.max(0, this.config.baseLatency + jitter);
    
    // 切换期间延迟更高
    if (this.isHandover) {
      return latency * 3;
    }
    
    return Math.round(latency);
  }

  /**
   * 模拟丢包
   * @returns {boolean} 是否丢包
   */
  simulatePacketLoss() {
    // 切换期间高丢包
    if (this.isHandover) {
      return Math.random() < this.config.burstLoss;
    }
    
    // 正常期间基础丢包
    return Math.random() < this.config.packetLoss;
  }

  /**
   * 启动切换模拟
   */
  startHandoverSimulation() {
    this.log(`Handover simulation: every ${this.config.handoverInterval}ms, duration ${this.config.handoverDuration}ms`);
    
    const scheduleHandover = () => {
      this.timers.handover = setTimeout(() => {
        this.simulateHandover();
        
        // 安排下一次切换
        if (this.isRunning) {
          scheduleHandover();
        }
      }, this.config.handoverInterval);
    };
    
    scheduleHandover();
  }

  /**
   * 模拟卫星切换
   */
  simulateHandover() {
    this.isHandover = true;
    this.stats.handovers++;
    
    this.log('=== SATELLITE HANDOVER STARTED ===', 'warning');
    this.log(`High latency (${this.config.baseLatency * 3}ms) and packet loss (${this.config.burstLoss * 100}%) for ${this.config.handoverDuration}ms`);
    
    // 触发事件
    if (window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('satelliteHandoverStart'));
    }
    
    // 切换结束
    setTimeout(() => {
      this.isHandover = false;
      this.log('=== SATELLITE HANDOVER COMPLETED ===');
      
      if (window.dispatchEvent) {
        window.dispatchEvent(new CustomEvent('satelliteHandoverEnd'));
      }
    }, this.config.handoverDuration);
  }

  /**
   * 启动统计收集
   */
  startStatsCollection() {
    this.timers.stats = setInterval(() => {
      const runtime = Date.now() - this.startTime;
      const minutes = Math.floor(runtime / 60000);
      
      if (this.stats.packetsSent > 0) {
        this.stats.avgLatency = this.stats.totalLatency / this.stats.packetsSent;
      }
      
      this.log(`Stats [${minutes}m]: sent=${this.stats.packetsSent}, lost=${this.stats.packetsLost}, ` +
               `loss=${(this.stats.packetsLost / Math.max(1, this.stats.packetsSent + this.stats.packetsLost) * 100).toFixed(1)}%, ` +
               `avgLatency=${this.stats.avgLatency.toFixed(0)}ms, handovers=${this.stats.handovers}`);
    }, 30000);  // 每30秒输出
  }

  /**
   * 清除所有定时器
   */
  clearAllTimers() {
    Object.values(this.timers).forEach(timer => {
      clearInterval(timer);
      clearTimeout(timer);
    });
    this.timers = {};
  }

  /**
   * 获取统计
   * @returns {Object}
   */
  getStats() {
    const total = this.stats.packetsSent + this.stats.packetsLost;
    
    return {
      ...this.stats,
      lossRate: total > 0 ? (this.stats.packetsLost / total * 100).toFixed(2) : 0,
      runtime: Date.now() - this.startTime,
      isRunning: this.isRunning,
      isHandover: this.isHandover,
      config: { ...this.config }
    };
  }

  /**
   * 设置模式
   * @param {string} mode - 'satellite' | '5g' | 'wifi'
   */
  setMode(mode) {
    this.config.mode = mode;
    
    switch (mode) {
      case 'satellite':
        this.config.baseLatency = 150;
        this.config.jitter = 50;
        this.config.packetLoss = 0.05;
        this.config.burstLoss = 0.3;
        this.config.downlink = 100;
        this.config.uplink = 10;
        break;
      case '5g':
        this.config.baseLatency = 20;
        this.config.jitter = 5;
        this.config.packetLoss = 0.001;
        this.config.burstLoss = 0.05;
        this.config.downlink = 1000;
        this.config.uplink = 100;
        break;
      case 'wifi':
        this.config.baseLatency = 10;
        this.config.jitter = 2;
        this.config.packetLoss = 0.001;
        this.config.burstLoss = 0.02;
        this.config.downlink = 500;
        this.config.uplink = 200;
        break;
    }
    
    this.log(`Mode switched to: ${mode}`);
  }

  /**
   * 睡眠
   * @param {number} ms
   * @returns {Promise<void>}
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * 日志
   * @param {...any} args
   */
  log(...args) {
    if (this.config.debug) {
      console.log('[SatelliteSimulator]', ...args);
    }
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SatelliteSimulator;
}

if (typeof window !== 'undefined') {
  window.SatelliteSimulator = SatelliteSimulator;
}
