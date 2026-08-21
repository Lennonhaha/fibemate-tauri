/**
 * FIBEMATE Satellite Mode
 * 卫星网络适配模式 - 自动降配保证可用性
 * 
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class SatelliteMode {
  constructor(fibemateCore, options = {}) {
    this.core = fibemateCore;
    this.isActive = false;
    this.isHandover = false;
    
    // 卫星模式配置
    this.config = {
      // 混合网参数
      mixnetHops: options.mixnetHops || 2,           // 降为2跳（延迟可控）
      
      // FEC参数
      fecEnabled: options.fecEnabled !== false,      // 默认开启
      fecRedundancy: options.fecRedundancy || 0.3,   // 30%冗余
      
      // 连接参数
      heartbeatInterval: options.heartbeatInterval || 5000,   // 5秒心跳
      heartbeatTimeout: options.heartbeatTimeout || 15000,    // 15秒超时
      
      // 重连参数
      reconnectInterval: options.reconnectInterval || 1000,   // 1秒重试
      maxReconnectAttempts: options.maxReconnectAttempts || 10,
      
      // 缓冲参数
      messageBufferSize: options.messageBufferSize || 100,    // 缓冲100条
      
      // 流量控制
      coverTrafficInterval: options.coverTrafficInterval || 30000, // 30秒假包
      maxPacketSize: options.maxPacketSize || 1024,    // 限制包大小
      
      // 切换检测
      handoverRttThreshold: options.handoverRttThreshold || 500,  // 切换检测阈值
      handoverDuration: options.handoverDuration || 3000,         // 切换持续时间
      
      debug: options.debug || false
    };
    
    // 状态
    this.state = {
      bufferedMessages: [],
      isPaused: false,
      reconnectAttempts: 0,
      lastHeartbeat: Date.now(),
      stats: {
        messagesSent: 0,
        messagesBuffered: 0,
        reconnections: 0,
        handovers: 0
      }
    };
    
    // 定时器
    this.timers = {};
    
    // 绑定
    this.apply = this.apply.bind(this);
    this.enterHandover = this.enterHandover.bind(this);
    this.exitHandover = this.exitHandover.bind(this);
  }

  /**
   * 激活卫星模式
   */
  apply() {
    if (this.isActive) {
      this.log('Satellite mode already active');
      return;
    }
    
    this.isActive = true;
    this.log('Activating satellite mode...');
    
    // 1. 降低混合网跳数
    this.core.setMixnetHops(this.config.mixnetHops);
    this.log(`Mixnet hops reduced to ${this.config.mixnetHops}`);
    
    // 2. 开启FEC
    if (this.config.fecEnabled) {
      this.core.setFEC(true, this.config.fecRedundancy);
      this.log(`FEC enabled with ${this.config.fecRedundancy * 100}% redundancy`);
    }
    
    // 3. 调整心跳
    this.core.setHeartbeatInterval(this.config.heartbeatInterval);
    this.core.setHeartbeatTimeout(this.config.heartbeatTimeout);
    this.log(`Heartbeat: ${this.config.heartbeatInterval}ms interval, ${this.config.heartbeatTimeout}ms timeout`);
    
    // 4. 配置重连
    this.core.setReconnectPolicy({
      interval: this.config.reconnectInterval,
      maxAttempts: this.config.maxReconnectAttempts,
      backoffMultiplier: 2,
      maxBackoff: 30000
    });
    this.log(`Reconnect: ${this.config.reconnectInterval}ms interval, max ${this.config.maxReconnectAttempts} attempts`);
    
    // 5. 设置消息缓冲
    this.core.setMessageBufferSize(this.config.messageBufferSize);
    this.log(`Message buffer size: ${this.config.messageBufferSize}`);
    
    // 6. 调整覆盖流量
    this.core.setCoverTrafficInterval(this.config.coverTrafficInterval);
    this.log(`Cover traffic interval: ${this.config.coverTrafficInterval}ms`);
    
    // 7. 限制包大小
    this.core.setMaxPacketSize(this.config.maxPacketSize);
    this.log(`Max packet size: ${this.config.maxPacketSize} bytes`);
    
    // 8. 启动切换检测
    this.startHandoverDetection();
    
    // 9. 启动统计
    this.startStatsCollection();
    
    this.log('Satellite mode activated');
    
    // 触发事件
    this.core.emit('satelliteModeActivated', this.getInfo());
  }

  /**
   * 退出卫星模式
   */
  deactivate() {
    if (!this.isActive) {
      return;
    }
    
    this.log('Deactivating satellite mode...');
    
    // 恢复默认配置
    this.core.setMixnetHops(5);           // 恢复5跳
    this.core.setFEC(false);               // 关闭FEC
    this.core.setHeartbeatInterval(30000); // 恢复30秒心跳
    this.core.setHeartbeatTimeout(60000);  // 恢复60秒超时
    this.core.setReconnectPolicy({         // 恢复默认重连
      interval: 5000,
      maxAttempts: 5,
      backoffMultiplier: 2,
      maxBackoff: 60000
    });
    this.core.setMessageBufferSize(50);    // 恢复默认缓冲
    this.core.setCoverTrafficInterval(5000); // 恢复默认假包频率
    this.core.setMaxPacketSize(65536);      // 恢复默认包大小
    
    // 清除定时器
    this.clearAllTimers();
    
    // 刷新缓冲的消息
    this.flushBufferedMessages();
    
    this.isActive = false;
    this.log('Satellite mode deactivated');
    
    this.core.emit('satelliteModeDeactivated', this.getInfo());
  }

  /**
   * 进入卫星切换模式
   */
  enterHandover() {
    if (this.isHandover) {
      return;
    }
    
    this.isHandover = true;
    this.state.stats.handovers++;
    this.log('Entering satellite handover mode...');
    
    // 1. 暂停覆盖流量（节省带宽）
    this.core.pauseCoverTraffic();
    this.log('Cover traffic paused');
    
    // 2. 缓冲待发消息
    this.state.isPaused = true;
    this.log('Outgoing messages buffered');
    
    // 3. 发送保活包维持连接
    this.sendKeepAlive();
    this.keepAliveTimer = setInterval(() => {
      this.sendKeepAlive();
    }, 1000);
    
    // 4. 设置退出定时器
    this.timers.handoverExit = setTimeout(() => {
      this.exitHandover();
    }, this.config.handoverDuration);
    
    this.core.emit('satelliteHandoverStarted');
  }

  /**
   * 退出卫星切换模式
   */
  exitHandover() {
    if (!this.isHandover) {
      return;
    }
    
    this.log('Exiting satellite handover mode...');
    
    // 1. 恢复覆盖流量
    this.core.resumeCoverTraffic();
    this.log('Cover traffic resumed');
    
    // 2. 恢复消息发送
    this.state.isPaused = false;
    
    // 3. 刷新缓冲的消息
    this.flushBufferedMessages();
    
    // 4. 清除保活定时器
    if (this.keepAliveTimer) {
      clearInterval(this.keepAliveTimer);
      this.keepAliveTimer = null;
    }
    
    // 5. 清除退出定时器
    if (this.timers.handoverExit) {
      clearTimeout(this.timers.handoverExit);
      delete this.timers.handoverExit;
    }
    
    this.isHandover = false;
    this.log('Satellite handover completed');
    
    this.core.emit('satelliteHandoverCompleted');
  }

  /**
   * 启动切换检测
   */
  startHandoverDetection() {
    this.log('Starting handover detection...');
    
    // 定期检测RTT突变
    this.timers.handoverCheck = setInterval(async () => {
      if (this.isHandover) {
        return;
      }
      
      try {
        const start = performance.now();
        await fetch('/api/ping', {
          method: 'HEAD',
          signal: AbortSignal.timeout(5000)
        });
        const rtt = performance.now() - start;
        
        // RTT突然增大 -> 可能正在切换卫星
        if (rtt > this.config.handoverRttThreshold) {
          this.log(`High RTT detected: ${rtt}ms, entering handover mode`);
          this.enterHandover();
        }
        
      } catch (error) {
        // 请求失败 -> 可能正在切换
        this.log('Ping failed, entering handover mode');
        this.enterHandover();
      }
    }, 2000);  // 每2秒检测一次
  }

  /**
   * 发送保活包
   */
  sendKeepAlive() {
    try {
      this.core.sendKeepAlive();
      this.state.lastHeartbeat = Date.now();
    } catch (error) {
      this.log('Failed to send keep-alive:', error.message);
    }
  }

  /**
   * 缓冲消息
   * @param {Object} message
   */
  bufferMessage(message) {
    if (this.state.bufferedMessages.length >= this.config.messageBufferSize) {
      // 缓冲满了，丢弃最旧的消息
      this.state.bufferedMessages.shift();
    }
    
    this.state.bufferedMessages.push({
      ...message,
      bufferedAt: Date.now()
    });
    
    this.state.stats.messagesBuffered++;
    this.log(`Message buffered (${this.state.bufferedMessages.length}/${this.config.messageBufferSize})`);
  }

  /**
   * 刷新缓冲的消息
   */
  flushBufferedMessages() {
    if (this.state.bufferedMessages.length === 0) {
      return;
    }
    
    this.log(`Flushing ${this.state.bufferedMessages.length} buffered messages...`);
    
    const messages = [...this.state.bufferedMessages];
    this.state.bufferedMessages = [];
    
    // 批量发送
    messages.forEach(msg => {
      try {
        this.core.sendMessage(msg);
        this.state.stats.messagesSent++;
      } catch (error) {
        this.log('Failed to send buffered message:', error.message);
      }
    });
    
    this.log('Buffered messages flushed');
  }

  /**
   * 启动统计收集
   */
  startStatsCollection() {
    this.timers.stats = setInterval(() => {
      this.log('Satellite mode stats:', this.state.stats);
    }, 60000);  // 每分钟输出一次
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
    
    if (this.keepAliveTimer) {
      clearInterval(this.keepAliveTimer);
      this.keepAliveTimer = null;
    }
  }

  /**
   * 获取当前信息
   * @returns {Object}
   */
  getInfo() {
    return {
      isActive: this.isActive,
      isHandover: this.isHandover,
      config: { ...this.config },
      state: {
        bufferedMessages: this.state.bufferedMessages.length,
        isPaused: this.state.isPaused,
        reconnectAttempts: this.state.reconnectAttempts,
        lastHeartbeat: this.state.lastHeartbeat,
        stats: { ...this.state.stats }
      }
    };
  }

  /**
   * 日志输出
   * @param {...any} args
   */
  log(...args) {
    if (this.config.debug) {
      console.log('[SatelliteMode]', ...args);
    }
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SatelliteMode;
}

if (typeof window !== 'undefined') {
  window.SatelliteMode = SatelliteMode;
}
