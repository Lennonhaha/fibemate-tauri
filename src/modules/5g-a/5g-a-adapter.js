/**
 * FIBEMATE 5G-A Network Adapter
 * 5G-A网络适配模块
 *
 * 功能：
 * - 5G-A网络特性检测
 * - 网络切片管理
 * - 边缘计算节点发现
 * - 超低延迟优化
 * - 大带宽适配
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class FiveGAdapter {
  constructor(options = {}) {
    this.config = {
      edgeEndpoints: options.edgeEndpoints || [],  // 边缘计算节点
      sliceId: options.sliceId || null,            // 网络切片ID
      latencyTarget: options.latencyTarget || 10,  // 目标延迟(ms)
      bandwidthTarget: options.bandwidthTarget || 1000, // 目标带宽(Mbps)
      debug: options.debug || false
    };

    this.state = {
      is5GAvailable: false,
      is5GA: false,           // 是否为5G-A
      currentLatency: null,
      currentBandwidth: null,
      edgeNode: null,         // 当前边缘节点
      networkSlice: null,     // 当前网络切片
      latencyMode: 'normal'   // normal | low | ultra-low
    };

    this.callbacks = {
      onNetworkChange: null,
      onLatencyUpdate: null,
      onBandwidthUpdate: null
    };

    this.measurementTimer = null;
  }

  /**
   * 初始化5G-A适配器
   */
  async init() {
    this._log('Initializing 5G-A Adapter...');

    // 检测5G网络
    await this._detect5GNetwork();

    // 检测边缘计算节点
    await this._discoverEdgeNodes();

    // 启动网络质量监测
    this._startQualityMonitoring();

    this._log(`5G-A Adapter initialized: 5G=${this.state.is5GAvailable}, 5G-A=${this.state.is5GA}`);
    return this.state.is5GAvailable;
  }

  /**
   * 销毁适配器
   */
  destroy() {
    if (this.measurementTimer) {
      clearInterval(this.measurementTimer);
      this.measurementTimer = null;
    }
    this._log('5G-A Adapter destroyed');
  }

  /**
   * 检测5G网络
   */
  async _detect5GNetwork() {
    try {
      // 使用 Network Information API
      if ('connection' in navigator) {
        const connection = navigator.connection;
        
        if (connection.effectiveType) {
          this.state.is5GAvailable = connection.effectiveType === '4g' && 
                                    connection.downlink > 50;
          
          // 检测是否为5G-A (通过高带宽判断)
          if (connection.downlink > 1000) {
            this.state.is5GA = true;
          }

          this.state.currentBandwidth = connection.downlink;
        }

        // 监听网络变化
        connection.addEventListener('change', () => {
          this._handleNetworkChange();
        });
      }

      // 使用 Performance API 测量延迟
      await this._measureLatency();

    } catch (error) {
      this._warn('5G detection failed:', error.message);
      this.state.is5GAvailable = false;
    }
  }

  /**
   * 发现边缘计算节点
   */
  async _discoverEdgeNodes() {
    if (!this.config.edgeEndpoints.length) {
      this._log('No edge endpoints configured');
      return;
    }

    const results = [];

    for (const endpoint of this.config.edgeEndpoints) {
      try {
        const start = performance.now();
        const response = await fetch(`${endpoint}/health`, {
          method: 'GET',
          mode: 'no-cors',
          timeout: 2000
        });
        const latency = performance.now() - start;

        results.push({
          endpoint,
          latency,
          available: true
        });
      } catch (error) {
        results.push({
          endpoint,
          latency: Infinity,
          available: false
        });
      }
    }

    // 选择延迟最低的边缘节点
    const bestNode = results
      .filter(r => r.available)
      .sort((a, b) => a.latency - b.latency)[0];

    if (bestNode) {
      this.state.edgeNode = bestNode.endpoint;
      this._log(`Edge node selected: ${bestNode.endpoint} (${bestNode.latency.toFixed(1)}ms)`);
    }
  }

  /**
   * 测量网络延迟
   */
  async _measureLatency() {
    try {
      const start = performance.now();
      
      // 使用 fetch 测量 RTT
      await fetch('/api/health', {
        method: 'HEAD',
        cache: 'no-store'
      });

      const latency = performance.now() - start;
      this.state.currentLatency = latency;

      // 更新延迟模式
      if (latency < 5) {
        this.state.latencyMode = 'ultra-low';
      } else if (latency < 20) {
        this.state.latencyMode = 'low';
      } else {
        this.state.latencyMode = 'normal';
      }

      if (this.callbacks.onLatencyUpdate) {
        this.callbacks.onLatencyUpdate(latency);
      }

      return latency;
    } catch (error) {
      this._warn('Latency measurement failed:', error.message);
      return null;
    }
  }

  /**
   * 启动质量监测
   */
  _startQualityMonitoring() {
    this.measurementTimer = setInterval(async () => {
      await this._measureLatency();
      
      // 更新带宽信息
      if ('connection' in navigator) {
        const connection = navigator.connection;
        this.state.currentBandwidth = connection.downlink;
        
        if (this.callbacks.onBandwidthUpdate) {
          this.callbacks.onBandwidthUpdate(connection.downlink);
        }
      }
    }, 5000); // 每5秒测量一次
  }

  /**
   * 处理网络变化
   */
  _handleNetworkChange() {
    if ('connection' in navigator) {
      const connection = navigator.connection;
      
      this.state.is5GAvailable = connection.effectiveType === '4g' && 
                                connection.downlink > 50;
      this.state.is5GA = connection.downlink > 1000;
      this.state.currentBandwidth = connection.downlink;

      if (this.callbacks.onNetworkChange) {
        this.callbacks.onNetworkChange({
          is5G: this.state.is5GAvailable,
          is5GA: this.state.is5GA,
          bandwidth: connection.downlink
        });
      }

      this._log(`Network changed: ${connection.effectiveType}, ${connection.downlink}Mbps`);
    }
  }

  /**
   * 获取最优服务器地址
   */
  getOptimalEndpoint() {
    if (this.state.edgeNode) {
      return this.state.edgeNode;
    }
    return null; // 使用默认服务器
  }

  /**
   * 获取网络建议
   */
  getNetworkAdvice() {
    const advice = {
      useEdgeComputing: false,
      useLargePayload: false,
      useRealtime: false,
      compressionLevel: 'normal'
    };

    if (!this.state.is5GAvailable) {
      return advice;
    }

    // 5G-A 优化建议
    if (this.state.is5GA) {
      advice.useEdgeComputing = !!this.state.edgeNode;
      advice.useLargePayload = true;
      advice.useRealtime = this.state.latencyMode === 'ultra-low';
      advice.compressionLevel = 'none'; // 高带宽下不需要压缩
    } else {
      // 普通5G
      advice.useEdgeComputing = !!this.state.edgeNode;
      advice.useLargePayload = this.state.currentBandwidth > 100;
      advice.useRealtime = this.state.latencyMode === 'low';
      advice.compressionLevel = 'normal';
    }

    return advice;
  }

  /**
   * 获取状态
   */
  getStatus() {
    return {
      is5GAvailable: this.state.is5GAvailable,
      is5GA: this.state.is5GA,
      latency: this.state.currentLatency,
      bandwidth: this.state.currentBandwidth,
      latencyMode: this.state.latencyMode,
      edgeNode: this.state.edgeNode,
      networkSlice: this.state.networkSlice
    };
  }

  /**
   * 日志
   */
  _log(...args) {
    if (this.config.debug) {
      console.log('[5G-A]', ...args);
    }
  }

  _warn(...args) {
    console.warn('[5G-A]', ...args);
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FiveGAdapter;
}

if (typeof window !== 'undefined') {
  window.FiveGAdapter = FiveGAdapter;
}
