/**
 * FIBEMATE Satellite Test Runner
 * 真实环境测试 - 验证卫星网络适配功能
 * 
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class SatelliteTestRunner {
  constructor(options = {}) {
    this.config = {
      apiEndpoint: options.apiEndpoint || 'https://fibemate.net/api',
      wsEndpoint: options.wsEndpoint || 'wss://fibemate.net/ws',
      testDuration: options.testDuration || 60000,  // 1分钟
      debug: options.debug || true
    };
    
    this.results = {
      networkDetection: null,
      satelliteMode: null,
      fec: null,
      reconnect: null,
      performance: null
    };
    
    this.logs = [];
  }

  /**
   * 运行所有测试
   */
  async runAllTests() {
    console.log('🚀 Starting Satellite Adaptation Tests...\n');
    
    // 测试1: 网络检测
    await this.testNetworkDetection();
    
    // 测试2: 卫星模式切换
    await this.testSatelliteMode();
    
    // 测试3: FEC功能
    await this.testFEC();
    
    // 测试4: 快速重连
    await this.testReconnect();
    
    // 测试5: 性能监控
    await this.testPerformance();
    
    // 生成报告
    this.generateReport();
  }

  /**
   * 测试1: 网络检测
   */
  async testNetworkDetection() {
    console.log('📡 Test 1: Network Detection');
    
    if (typeof NetworkDetector === 'undefined') {
      this.fail('networkDetection', 'NetworkDetector not available');
      return;
    }
    
    const detector = new NetworkDetector({ debug: true });
    
    // 测试分类逻辑
    const tests = [
      { info: '5g', rtt: 30, loss: 0, expected: '5g' },
      { info: '4g', rtt: 80, loss: 1, expected: '4g' },
      { info: 'wifi', rtt: 15, loss: 0, expected: 'wifi' },
      { info: '4g', rtt: 250, loss: 8, expected: 'satellite' },
      { info: '4g', rtt: 300, loss: 2, expected: 'satellite' }
    ];
    
    let passed = 0;
    tests.forEach(test => {
      const result = detector.classifyNetwork(test.info, test.rtt, test.loss);
      const success = result === test.expected;
      if (success) passed++;
      
      console.log(`  ${success ? '✅' : '❌'} ${test.info}, RTT=${test.rtt}ms, loss=${test.loss}% => ${result} (expected: ${test.expected})`);
    });
    
    this.results.networkDetection = {
      passed,
      total: tests.length,
      success: passed === tests.length
    };
  }

  /**
   * 测试2: 卫星模式
   */
  async testSatelliteMode() {
    console.log('\n🛰️ Test 2: Satellite Mode');
    
    if (typeof SatelliteMode === 'undefined') {
      this.fail('satelliteMode', 'SatelliteMode not available');
      return;
    }
    
    const mockCore = createTestCore();
    const mode = new SatelliteMode(mockCore, { debug: true });
    
    // 测试激活
    mode.apply();
    
    const active = mode.isActive;
    const hopsCorrect = mockCore.hops === 2;
    const fecEnabled = mockCore.fecEnabled;
    
    console.log(`  ${active ? '✅' : '❌'} Mode activated`);
    console.log(`  ${hopsCorrect ? '✅' : '❌'} Hops set to 2 (actual: ${mockCore.hops})`);
    console.log(`  ${fecEnabled ? '✅' : '❌'} FEC enabled`);
    
    // 测试切换
    mode.enterHandover();
    const handoverActive = mode.isHandover;
    console.log(`  ${handoverActive ? '✅' : '❌'} Handover mode entered`);
    
    mode.exitHandover();
    const handoverEnded = !mode.isHandover;
    console.log(`  ${handoverEnded ? '✅' : '❌'} Handover mode exited`);
    
    // 测试停用
    mode.deactivate();
    const deactivated = !mode.isActive;
    const hopsRestored = mockCore.hops === 5;
    
    console.log(`  ${deactivated ? '✅' : '❌'} Mode deactivated`);
    console.log(`  ${hopsRestored ? '✅' : '❌'} Hops restored to 5 (actual: ${mockCore.hops})`);
    
    this.results.satelliteMode = {
      passed: [active, hopsCorrect, fecEnabled, handoverActive, handoverEnded, deactivated, hopsRestored].filter(Boolean).length,
      total: 7,
      success: active && hopsCorrect && fecEnabled && deactivated && hopsRestored
    };
  }

  /**
   * 测试3: FEC
   */
  async testFEC() {
    console.log('\n🔧 Test 3: Forward Error Correction');
    
    if (typeof ForwardErrorCorrection === 'undefined') {
      this.fail('fec', 'ForwardErrorCorrection not available');
      return;
    }
    
    const fec = new ForwardErrorCorrection({ redundancy: 0.3, debug: true });
    
    // 测试数据
    const testData = new TextEncoder().encode('FIBEMATE Satellite Test Message');
    
    // 编码
    const encoded = fec.encode(testData);
    const encodeSuccess = encoded.length > 0;
    console.log(`  ${encodeSuccess ? '✅' : '❌'} Encoding: ${encoded.length} packets`);
    
    // 无丢包解码
    const received1 = encoded.map(p => p);
    const result1 = fec.decode(received1, encoded.length);
    const decodeSuccess = result1.success;
    const dataMatch = decodeSuccess && new TextDecoder().decode(result1.data) === 'FIBEMATE Satellite Test Message';
    
    console.log(`  ${decodeSuccess ? '✅' : '❌'} Decoding without loss`);
    console.log(`  ${dataMatch ? '✅' : '❌'} Data integrity`);
    
    // 有丢包解码（丢一个数据包）
    const received2 = encoded.map((p, i) => i === 0 ? null : p);
    const result2 = fec.decode(received2, encoded.length);
    console.log(`  ${result2.success ? '✅' : '⚠️'} Decoding with 1 packet loss (recovered: ${result2.recovered})`);
    
    this.results.fec = {
      passed: [encodeSuccess, decodeSuccess, dataMatch].filter(Boolean).length,
      total: 3,
      success: encodeSuccess && decodeSuccess && dataMatch
    };
  }

  /**
   * 测试4: 快速重连
   */
  async testReconnect() {
    console.log('\n🔄 Test 4: Rapid Reconnect');
    
    if (typeof RapidReconnect === 'undefined') {
      this.fail('reconnect', 'RapidReconnect not available');
      return;
    }
    
    const reconnect = new RapidReconnect({
      maxAttempts: 3,
      baseInterval: 100,
      debug: true
    });
    
    let attempts = 0;
    const startTime = Date.now();
    
    try {
      await reconnect.reconnect(async () => {
        attempts++;
        if (attempts < 2) {
          throw new Error('Connection failed');
        }
        return { connected: true };
      });
      
      const success = attempts === 2;
      const time = Date.now() - startTime;
      
      console.log(`  ${success ? '✅' : '❌'} Reconnected after ${attempts} attempts`);
      console.log(`  ✅ Time: ${time}ms`);
      
      this.results.reconnect = {
        passed: success ? 2 : 0,
        total: 2,
        success,
        time
      };
    } catch (error) {
      console.log(`  ❌ Reconnect failed: ${error.message}`);
      this.results.reconnect = { passed: 0, total: 2, success: false };
    }
  }

  /**
   * 测试5: 性能监控
   */
  async testPerformance() {
    console.log('\n📊 Test 5: Performance Monitoring');
    
    if (typeof SatellitePerformance === 'undefined') {
      this.fail('performance', 'SatellitePerformance not available');
      return;
    }
    
    const perf = new SatellitePerformance({
      sampleInterval: 100,
      reportInterval: 500,
      debug: true
    });
    
    perf.start();
    
    // 模拟一些数据
    perf.recordReconnectTime(1500);
    perf.recordHandshakeTime(800);
    perf.recordThroughput(50000);
    perf.recordPacketLoss(5);
    
    // 等待报告
    await this.sleep(600);
    
    const report = perf.getLastReport();
    const hasReport = report !== null;
    
    console.log(`  ${hasReport ? '✅' : '❌'} Report generated`);
    
    if (hasReport) {
      console.log(`  📊 Samples: ${report.samples}`);
      console.log(`  📊 Runtime: ${report.runtime}ms`);
    }
    
    perf.stop();
    
    this.results.performance = {
      passed: hasReport ? 1 : 0,
      total: 1,
      success: hasReport
    };
  }

  /**
   * 生成测试报告
   */
  generateReport() {
    console.log('\n' + '='.repeat(50));
    console.log('📋 SATELLITE TEST REPORT');
    console.log('='.repeat(50));
    
    let totalPassed = 0;
    let totalTests = 0;
    
    Object.entries(this.results).forEach(([name, result]) => {
      if (!result) return;
      
      const icon = result.success ? '✅' : '❌';
      console.log(`${icon} ${name}: ${result.passed}/${result.total} passed`);
      
      totalPassed += result.passed;
      totalTests += result.total;
    });
    
    const rate = totalTests > 0 ? (totalPassed / totalTests * 100).toFixed(1) : 0;
    
    console.log('\n' + '-'.repeat(50));
    console.log(`Total: ${totalPassed}/${totalTests} (${rate}%)`);
    console.log('='.repeat(50));
    
    return {
      totalPassed,
      totalTests,
      rate,
      results: this.results
    };
  }

  /**
   * 失败辅助
   */
  fail(name, message) {
    console.log(`  ❌ ${message}`);
    this.results[name] = { passed: 0, total: 1, success: false, error: message };
  }

  /**
   * 睡眠
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * 创建测试用的 FIBEMATE Core
 */
function createTestCore() {
  return {
    hops: 5,
    fecEnabled: false,
    coverTrafficPaused: false,
    
    setMixnetHops(hops) { this.hops = hops; },
    setFEC(enabled) { this.fecEnabled = enabled; },
    setHeartbeatInterval() {},
    setHeartbeatTimeout() {},
    setReconnectPolicy() {},
    setMessageBufferSize() {},
    setCoverTrafficInterval() {},
    pauseCoverTraffic() { this.coverTrafficPaused = true; },
    resumeCoverTraffic() { this.coverTrafficPaused = false; },
    setMaxPacketSize() {},
    sendKeepAlive() {},
    emit() {},
    on() {},
    sendMessage() {},
    createWebSocket() { return {}; },
    setPacketEncoder() {},
    setPacketDecoder() {}
  };
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SatelliteTestRunner, createTestCore };
}

if (typeof window !== 'undefined') {
  window.SatelliteTestRunner = SatelliteTestRunner;
  window.createTestCore = createTestCore;
}
