/**
 * FIBEMATE Satellite Performance Monitor
 * 性能监控 - 收集卫星模式下的性能指标
 * 
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class SatellitePerformance {
  constructor(options = {}) {
    this.config = {
      sampleInterval: options.sampleInterval || 1000,    // 采样间隔
      reportInterval: options.reportInterval || 30000,   // 报告间隔
      maxSamples: options.maxSamples || 300,             // 最大样本数（5分钟）
      debug: options.debug || false
    };
    
    // 性能数据
    this.samples = {
      rtt: [],
      throughput: [],
      packetLoss: [],
      jitter: [],
      reconnectTime: [],
      handshakeTime: []
    };
    
    // 统计
    this.stats = {
      totalSamples: 0,
      startTime: null,
      lastReport: null
    };
    
    // 定时器
    this.timers = {};
    this.isRunning = false;
    
    // 监听器
    this.listeners = [];
  }

  /**
   * 启动监控
   */
  start() {
    if (this.isRunning) {
      return;
    }
    
    this.isRunning = true;
    this.stats.startTime = Date.now();
    
    this.log('Performance monitoring started');
    
    // 定期采样
    this.timers.sample = setInterval(() => {
      this.collectSample();
    }, this.config.sampleInterval);
    
    // 定期报告
    this.timers.report = setInterval(() => {
      this.generateReport();
    }, this.config.reportInterval);
  }

  /**
   * 停止监控
   */
  stop() {
    if (!this.isRunning) {
      return;
    }
    
    this.isRunning = false;
    
    Object.values(this.timers).forEach(timer => {
      clearInterval(timer);
    });
    this.timers = {};
    
    this.log('Performance monitoring stopped');
  }

  /**
   * 收集样本
   */
  async collectSample() {
    try {
      // 测量RTT
      const rtt = await this.measureRTT();
      
      // 计算抖动（与上一个样本的差值）
      const jitter = this.samples.rtt.length > 0 
        ? Math.abs(rtt - this.samples.rtt[this.samples.rtt.length - 1])
        : 0;
      
      // 添加到样本
      this.addSample('rtt', rtt);
      this.addSample('jitter', jitter);
      
      this.stats.totalSamples++;
      
    } catch (error) {
      this.log('Sample collection failed:', error.message);
    }
  }

  /**
   * 测量RTT
   * @returns {Promise<number>}
   */
  async measureRTT() {
    const start = performance.now();
    
    try {
      await fetch('/api/ping', {
        method: 'HEAD',
        cache: 'no-store',
        signal: AbortSignal.timeout(5000)
      });
      
      return performance.now() - start;
      
    } catch (error) {
      return Infinity;
    }
  }

  /**
   * 添加样本
   * @param {string} type
   * @param {number} value
   */
  addSample(type, value) {
    if (!this.samples[type]) {
      this.samples[type] = [];
    }
    
    this.samples[type].push({
      value,
      timestamp: Date.now()
    });
    
    // 限制样本数
    if (this.samples[type].length > this.config.maxSamples) {
      this.samples[type].shift();
    }
  }

  /**
   * 记录重连时间
   * @param {number} time
   */
  recordReconnectTime(time) {
    this.addSample('reconnectTime', time);
  }

  /**
   * 记录握手时间
   * @param {number} time
   */
  recordHandshakeTime(time) {
    this.addSample('handshakeTime', time);
  }

  /**
   * 记录吞吐量
   * @param {number} bytesPerSecond
   */
  recordThroughput(bytesPerSecond) {
    this.addSample('throughput', bytesPerSecond);
  }

  /**
   * 记录丢包
   * @param {number} lossRate
   */
  recordPacketLoss(lossRate) {
    this.addSample('packetLoss', lossRate);
  }

  /**
   * 生成报告
   * @returns {Object}
   */
  generateReport() {
    const report = {
      timestamp: Date.now(),
      runtime: Date.now() - this.stats.startTime,
      samples: this.stats.totalSamples,
      metrics: {}
    };
    
    // 计算各指标统计
    Object.keys(this.samples).forEach(type => {
      const values = this.samples[type]
        .filter(s => s.value !== Infinity)
        .map(s => s.value);
      
      if (values.length === 0) {
        report.metrics[type] = null;
        return;
      }
      
      values.sort((a, b) => a - b);
      
      const sum = values.reduce((a, b) => a + b, 0);
      const avg = sum / values.length;
      const min = values[0];
      const max = values[values.length - 1];
      const median = values[Math.floor(values.length / 2)];
      
      // 计算百分位数
      const p95 = values[Math.floor(values.length * 0.95)];
      const p99 = values[Math.floor(values.length * 0.99)];
      
      report.metrics[type] = {
        count: values.length,
        avg: Math.round(avg * 100) / 100,
        min: Math.round(min * 100) / 100,
        max: Math.round(max * 100) / 100,
        median: Math.round(median * 100) / 100,
        p95: Math.round(p95 * 100) / 100,
        p99: Math.round(p99 * 100) / 100
      };
    });
    
    this.stats.lastReport = report;
    
    // 触发报告事件
    this.notifyListeners(report);
    
    this.log('Performance report generated');
    
    return report;
  }

  /**
   * 获取最新报告
   * @returns {Object|null}
   */
  getLastReport() {
    return this.stats.lastReport;
  }

  /**
   * 添加监听器
   * @param {Function} callback
   */
  addListener(callback) {
    this.listeners.push(callback);
  }

  /**
   * 通知监听器
   * @param {Object} report
   */
  notifyListeners(report) {
    this.listeners.forEach(callback => {
      try {
        callback(report);
      } catch (error) {
        console.error('Performance listener error:', error);
      }
    });
  }

  /**
   * 获取原始样本
   * @param {string} type
   * @returns {Array}
   */
  getSamples(type) {
    return this.samples[type] || [];
  }

  /**
   * 导出数据（CSV格式）
   * @returns {string}
   */
  exportCSV() {
    const types = Object.keys(this.samples);
    if (types.length === 0) return '';
    
    let csv = 'timestamp,' + types.join(',') + '\n';
    
    // 找到最多样本数
    const maxLength = Math.max(...types.map(t => this.samples[t].length));
    
    for (let i = 0; i < maxLength; i++) {
      const timestamp = this.samples[types[0]][i]?.timestamp || '';
      const values = types.map(type => {
        const sample = this.samples[type][i];
        return sample ? sample.value : '';
      });
      
      csv += `${timestamp},${values.join(',')}\n`;
    }
    
    return csv;
  }

  /**
   * 日志
   * @param {...any} args
   */
  log(...args) {
    if (this.config.debug) {
      console.log('[SatellitePerformance]', ...args);
    }
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SatellitePerformance;
}

if (typeof window !== 'undefined') {
  window.SatellitePerformance = SatellitePerformance;
}
