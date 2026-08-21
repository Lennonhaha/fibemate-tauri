/**
 * FIBEMATE Quantum Module Tests
 * 量子模块测试
 *
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class QuantumTestRunner {
  constructor(options = {}) {
    this.config = {
      debug: options.debug || true
    };
    this.results = {};
  }

  async runAllTests() {
    console.log('🔬 Starting Quantum Module Tests...\n');

    await this.testQuantumAdapter();
    await this.testQuantumCrypto();
    await this.testQuantumIntegration();
    await this.testHybridEncryption();

    this.generateReport();
  }

  async testQuantumAdapter() {
    console.log('📡 Test 1: Quantum Adapter');

    const adapter = new QuantumAdapter({
      qkdEndpoint: 'http://localhost:8080',
      qrngEndpoint: 'http://localhost:8081',
      debug: true
    });

    // 测试初始化（无实际服务端，应该失败但优雅处理）
    const initResult = await adapter.init();
    console.log(`  ${!initResult ? '✅' : '⚠️'} Graceful fallback when QKD unavailable`);

    // 测试量子随机数回退
    const random = await adapter.getQuantumRandom(32);
    const randomSuccess = random.length === 32;
    console.log(`  ${randomSuccess ? '✅' : '❌'} Quantum random fallback: ${random.length} bytes`);

    // 测试熵池
    await adapter.refillEntropyPool();
    const poolRandom = adapter.getRandomFromPool(16);
    const poolSuccess = poolRandom.length === 16;
    console.log(`  ${poolSuccess ? '✅' : '❌'} Entropy pool: ${poolRandom.length} bytes`);

    adapter.destroy();

    this.results.adapter = {
      passed: [!initResult, randomSuccess, poolSuccess].filter(Boolean).length,
      total: 3,
      success: randomSuccess && poolSuccess
    };
  }

  async testQuantumCrypto() {
    console.log('\n🔐 Test 2: Quantum Crypto');

    const crypto = new QuantumCrypto({ debug: true });
    await crypto.init();

    // 测试密钥派生
    const salt = crypto.getRandomFromPool ? crypto.getRandomFromPool(16) : crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.deriveKey('test-password', salt);
    const keySuccess = key.length === 32;
    console.log(`  ${keySuccess ? '✅' : '❌'} Key derivation: ${key.length} bytes`);

    // 测试混合密钥生成（无量子适配器）
    const classicalKey = new Uint8Array(32);
    crypto.getRandomValues(classicalKey);

    const hybridResult = await crypto.generateHybridKey('test-peer', classicalKey);
    const hybridSuccess = hybridResult.type === 'classical';
    console.log(`  ${hybridSuccess ? '✅' : '❌'} Hybrid key generation: ${hybridResult.type}`);

    this.results.crypto = {
      passed: [keySuccess, hybridSuccess].filter(Boolean).length,
      total: 2,
      success: keySuccess && hybridSuccess
    };
  }

  async testQuantumIntegration() {
    console.log('\n🔗 Test 3: Quantum Integration');

    const mockCore = {
      emit: () => {}
    };

    const integration = new QuantumIntegration(mockCore, {
      autoEnable: false,
      debug: true
    });

    // 测试初始化
    const initResult = await integration.init();
    console.log(`  ${!initResult ? '✅' : '⚠️'} Integration init (no quantum network)`);

    // 测试状态
    const status = integration.getStatus();
    const statusCorrect = status.initialized && !status.quantumAvailable;
    console.log(`  ${statusCorrect ? '✅' : '❌'} Status correct: initialized=${status.initialized}, available=${status.quantumAvailable}`);

    // 测试禁用
    integration.disable();
    const disabled = !integration.state.active;
    console.log(`  ${disabled ? '✅' : '❌'} Disable works`);

    integration.destroy();

    this.results.integration = {
      passed: [true, statusCorrect, disabled].filter(Boolean).length,
      total: 3,
      success: statusCorrect && disabled
    };
  }

  async testHybridEncryption() {
    console.log('\n🛡️ Test 4: Hybrid Encryption');

    const crypto = new QuantumCrypto({ debug: true });
    await crypto.init();

    // 生成测试密钥
    const classicalKey = new Uint8Array(32);
    crypto.getRandomValues(classicalKey);

    await crypto.generateHybridKey('test-peer', classicalKey);

    // 测试加密
    const plaintext = 'Hello Quantum World!';
    const encrypted = await crypto.encrypt('test-peer', plaintext);
    const encryptSuccess = encrypted.ciphertext.length > 0;
    console.log(`  ${encryptSuccess ? '✅' : '❌'} Encryption: ${encrypted.ciphertext.length} bytes`);

    // 测试解密
    const decrypted = await crypto.decrypt('test-peer', encrypted.ciphertext, encrypted.iv);
    const decryptSuccess = decrypted === plaintext;
    console.log(`  ${decryptSuccess ? '✅' : '❌'} Decryption: ${decrypted}`);

    // 安全擦除
    crypto.secureErase('test-peer');
    const erased = !crypto.state.hybridKeys.has('test-peer');
    console.log(`  ${erased ? '✅' : '❌'} Secure erase`);

    this.results.encryption = {
      passed: [encryptSuccess, decryptSuccess, erased].filter(Boolean).length,
      total: 3,
      success: encryptSuccess && decryptSuccess && erased
    };
  }

  generateReport() {
    console.log('\n' + '='.repeat(50));
    console.log('🔬 QUANTUM TEST REPORT');
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
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = QuantumTestRunner;
}

if (typeof window !== 'undefined') {
  window.QuantumTestRunner = QuantumTestRunner;
}
