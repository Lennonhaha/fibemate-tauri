/**
 * FIBEMATE Rapid Reconnect
 * 快速重连 - 卫星网络断线恢复
 * 
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class RapidReconnect {
  constructor(options = {}) {
    this.maxAttempts = options.maxAttempts || 10;
    this.baseInterval = options.baseInterval || 1000;
    this.maxInterval = options.maxInterval || 30000;
    this.backoffMultiplier = options.backoffMultiplier || 2;
    this.jitter = options.jitter || 0.1;  // 10%抖动
    
    // 状态
    this.attempts = 0;
    this.currentInterval = this.baseInterval;
    this.isReconnecting = false;
    this.shouldStop = false;
    
    // 统计
    this.stats = {
      totalAttempts: 0,
      successfulReconnects: 0,
      failedReconnects: 0,
      averageTime: 0,
      totalTime: 0
    };
    
    // 事件监听
    this.listeners = {
      start: [],
      attempt: [],
      success: [],
      failure: [],
      stop: []
    };
    
    // 绑定
    this.reconnect = this.reconnect.bind(this);
    this.stop = this.stop.bind(this);
    this.reset = this.reset.bind(this);
  }

  /**
   * 开始重连
   * @param {Function} connectFn - 返回Promise的连接函数
   * @param {Object} options - 重连选项
   * @returns {Promise<any>}
   */
  async reconnect(connectFn, options = {}) {
    if (this.isReconnecting) {
      throw new Error('Already reconnecting');
    }
    
    this.isReconnecting = true;
    this.shouldStop = false;
    this.attempts = 0;
    this.currentInterval = options.baseInterval || this.baseInterval;
    
    const startTime = Date.now();
    
    this.emit('start', { timestamp: startTime });
    
    while (this.attempts < this.maxAttempts && !this.shouldStop) {
      this.attempts++;
      this.stats.totalAttempts++;
      
      const attemptStart = Date.now();
      
      this.emit('attempt', {
        attempt: this.attempts,
        maxAttempts: this.maxAttempts,
        interval: this.currentInterval,
        timestamp: attemptStart
      });
      
      try {
        this.log(`Reconnection attempt ${this.attempts}/${this.maxAttempts}...`);
        
        const result = await this.executeWithTimeout(
          connectFn,
          options.timeout || 10000
        );
        
        // 成功！
        const attemptTime = Date.now() - attemptStart;
        const totalTime = Date.now() - startTime;
        
        this.stats.successfulReconnects++;
        this.stats.totalTime += totalTime;
        this.stats.averageTime = this.stats.totalTime / this.stats.successfulReconnects;
        
        this.log(`Reconnection successful after ${this.attempts} attempts (${totalTime}ms)`);
        
        this.emit('success', {
          attempts: this.attempts,
          attemptTime,
          totalTime,
          timestamp: Date.now()
        });
        
        this.isReconnecting = false;
        return result;
        
      } catch (error) {
        const attemptTime = Date.now() - attemptStart;
        
        this.log(`Attempt ${this.attempts} failed: ${error.message} (${attemptTime}ms)`);
        
        this.emit('attempt', {
          attempt: this.attempts,
          error: error.message,
          attemptTime,
          timestamp: Date.now()
        });
        
        if (this.attempts >= this.maxAttempts || this.shouldStop) {
          break;
        }
        
        // 计算下次重试间隔（指数退避 + 抖动）
        const jitterAmount = this.currentInterval * this.jitter * (Math.random() - 0.5);
        const waitTime = Math.round(this.currentInterval + jitterAmount);
        
        this.log(`Waiting ${waitTime}ms before next attempt...`);
        
        await this.sleep(waitTime);
        
        // 指数退避
        this.currentInterval = Math.min(
          this.currentInterval * this.backoffMultiplier,
          this.maxInterval
        );
      }
    }
    
    // 失败
    const totalTime = Date.now() - startTime;
    this.stats.failedReconnects++;
    
    this.log(`Reconnection failed after ${this.attempts} attempts (${totalTime}ms)`);
    
    this.emit('failure', {
      attempts: this.attempts,
      totalTime,
      timestamp: Date.now()
    });
    
    this.isReconnecting = false;
    throw new Error(`Failed to reconnect after ${this.attempts} attempts`);
  }

  /**
   * 执行带超时的函数
   * @param {Function} fn
   * @param {number} timeout
   * @returns {Promise<any>}
   */
  executeWithTimeout(fn, timeout) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Connection timeout after ${timeout}ms`));
      }, timeout);
      
      Promise.resolve(fn())
        .then(result => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timer);
          reject(error);
        });
    });
  }

  /**
   * 停止重连
   */
  stop() {
    if (!this.isReconnecting) {
      return;
    }
    
    this.log('Stopping reconnection...');
    this.shouldStop = true;
    
    this.emit('stop', {
      attempts: this.attempts,
      timestamp: Date.now()
    });
  }

  /**
   * 重置状态
   */
  reset() {
    this.attempts = 0;
    this.currentInterval = this.baseInterval;
    this.isReconnecting = false;
    this.shouldStop = false;
    
    this.log('State reset');
  }

  /**
   * 添加事件监听
   * @param {string} event - 'start' | 'attempt' | 'success' | 'failure' | 'stop'
   * @param {Function} callback
   */
  on(event, callback) {
    if (this.listeners[event]) {
      this.listeners[event].push(callback);
    }
  }

  /**
   * 移除事件监听
   * @param {string} event
   * @param {Function} callback
   */
  off(event, callback) {
    if (this.listeners[event]) {
      this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
    }
  }

  /**
   * 触发事件
   * @param {string} event
   * @param {Object} data
   */
  emit(event, data) {
    if (this.listeners[event]) {
      this.listeners[event].forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error('Reconnect listener error:', error);
        }
      });
    }
  }

  /**
   * 获取统计
   * @returns {Object}
   */
  getStats() {
    return {
      ...this.stats,
      currentState: {
        isReconnecting: this.isReconnecting,
        attempts: this.attempts,
        currentInterval: this.currentInterval
      }
    };
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
    console.log('[RapidReconnect]', ...args);
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = RapidReconnect;
}

if (typeof window !== 'undefined') {
  window.RapidReconnect = RapidReconnect;
}
