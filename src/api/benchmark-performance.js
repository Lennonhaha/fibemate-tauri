/**
 * Performance Benchmark Suite
 * For anonymous paper submission
 * Measures: encryption latency, memory usage, throughput
 */

const crypto = require('crypto');
const { performance } = require('perf_hooks');

// Simulated Double Ratchet parameters
const AES_KEY_SIZE = 32;
const IV_SIZE = 12;
const TAG_SIZE = 16;
const MAX_SKIP = 1000;

class BenchmarkSuite {
  constructor() {
    this.results = [];
  }

  /**
   * Measure AES-256-GCM encryption/decryption latency
   */
  async measureAesLatency(iterations = 1000) {
    const key = crypto.randomBytes(AES_KEY_SIZE);
    const message = Buffer.from('Hello, this is a test message for benchmarking');
    
    // Warmup
    for (let i = 0; i < 100; i++) {
      const iv = crypto.randomBytes(IV_SIZE);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
      const tag = cipher.getAuthTag();
    }

    // Measure encryption
    const encStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      const iv = crypto.randomBytes(IV_SIZE);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
      const tag = cipher.getAuthTag();
    }
    const encEnd = performance.now();
    const encLatency = (encEnd - encStart) / iterations;

    // Measure decryption
    const iv = crypto.randomBytes(IV_SIZE);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
    const tag = cipher.getAuthTag();

    const decStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    }
    const decEnd = performance.now();
    const decLatency = (decEnd - decStart) / iterations;

    return {
      operation: 'AES-256-GCM',
      iterations,
      encryptLatency: encLatency.toFixed(3),
      decryptLatency: decLatency.toFixed(3),
      messageSize: message.length
    };
  }

  /**
   * Measure HKDF key derivation latency
   */
  async measureHkdfLatency(iterations = 1000) {
    const ikm = crypto.randomBytes(32);
    const salt = crypto.randomBytes(32);
    const info = Buffer.from('X3DH-v1');

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
      const okm = crypto.createHmac('sha256', prk).update(info).update(Buffer.from([1])).digest();
    }
    const end = performance.now();
    const latency = (end - start) / iterations;

    return {
      operation: 'HKDF-SHA-256',
      iterations,
      latency: latency.toFixed(3)
    };
  }

  /**
   * Measure HMAC latency (for chain key derivation)
   */
  async measureHmacLatency(iterations = 1000) {
    const key = crypto.randomBytes(32);
    const data = crypto.randomBytes(32);

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const hmac = crypto.createHmac('sha256', key).update(data).digest();
    }
    const end = performance.now();
    const latency = (end - start) / iterations;

    return {
      operation: 'HMAC-SHA-256',
      iterations,
      latency: latency.toFixed(3)
    };
  }

  /**
   * Measure memory usage during burst messaging
   */
  async measureMemoryUsage(messageCount = 1000) {
    const initialMemory = process.memoryUsage();
    const keys = [];

    // Simulate storing message keys
    for (let i = 0; i < messageCount; i++) {
      keys.push(crypto.randomBytes(32));
    }

    const finalMemory = process.memoryUsage();
    const memoryIncrease = (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024;

    return {
      operation: 'Memory Usage',
      messageCount,
      memoryIncreaseMB: memoryIncrease.toFixed(2),
      avgBytesPerMessage: (memoryIncrease * 1024 * 1024 / messageCount).toFixed(2)
    };
  }

  /**
   * Measure throughput (messages per second)
   */
  async measureThroughput(durationMs = 1000) {
    const key = crypto.randomBytes(AES_KEY_SIZE);
    const message = Buffer.from('Test message');
    let count = 0;

    const start = performance.now();
    while (performance.now() - start < durationMs) {
      const iv = crypto.randomBytes(IV_SIZE);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
      const tag = cipher.getAuthTag();
      count++;
    }
    const elapsed = performance.now() - start;

    return {
      operation: 'Throughput',
      durationMs: elapsed.toFixed(0),
      messagesProcessed: count,
      messagesPerSecond: (count / (elapsed / 1000)).toFixed(0)
    };
  }

  /**
   * Run all benchmarks
   */
  async runAll() {
    console.log('=== Performance Benchmark Suite ===\n');
    console.log('Platform: Node.js', process.version);
    console.log('CPU:', process.arch);
    console.log('');

    const benchmarks = [
      await this.measureAesLatency(),
      await this.measureHkdfLatency(),
      await this.measureHmacLatency(),
      await this.measureMemoryUsage(),
      await this.measureThroughput()
    ];

    console.log('Results:');
    console.log('--------');
    benchmarks.forEach(b => {
      console.log(`\n${b.operation}:`);
      Object.entries(b).forEach(([key, value]) => {
        if (key !== 'operation') {
          console.log(`  ${key}: ${value}`);
        }
      });
    });

    // Summary table for paper
    console.log('\n=== Summary Table (for paper) ===');
    console.log('| Operation | Latency (ms) | Notes |');
    console.log('|-----------|--------------|-------|');
    console.log(`| AES-256-GCM Encrypt | ${benchmarks[0].encryptLatency} | ${benchmarks[0].messageSize}B message |`);
    console.log(`| AES-256-GCM Decrypt | ${benchmarks[0].decryptLatency} | ${benchmarks[0].messageSize}B message |`);
    console.log(`| HKDF-SHA-256 | ${benchmarks[1].latency} | Key derivation |`);
    console.log(`| HMAC-SHA-256 | ${benchmarks[2].latency} | Chain key step |`);
    console.log(`| Memory/1K msgs | ${benchmarks[3].memoryIncreaseMB} MB | Heap increase |`);
    console.log(`| Throughput | ${benchmarks[4].messagesPerSecond} msg/s | Single thread |`);

    return benchmarks;
  }
}

// Run if called directly
if (require.main === module) {
  const suite = new BenchmarkSuite();
  suite.runAll().catch(console.error);
}

module.exports = BenchmarkSuite;
