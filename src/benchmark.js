const crypto = require('crypto').webcrypto;
global.crypto = crypto;

const DoubleRatchet = require('./double-ratchet');

async function benchmark() {
  console.log('=== FIBEMATE Performance Benchmark ===\n');
  
  // 1. DH Key Generation
  console.log('1. DH Key Generation (P-256)');
  const start1 = Date.now();
  for (let i = 0; i < 100; i++) {
    await DoubleRatchet.generateDH();
  }
  const dur1 = Date.now() - start1;
  console.log('   100 keys in', dur1, 'ms');
  console.log('   Throughput:', (100 / (dur1 / 1000)).toFixed(0), 'ops/s\n');
  
  // 2. HKDF using WebCrypto directly
  console.log('2. HKDF-SHA-256 Key Derivation');
  const key = crypto.getRandomValues(new Uint8Array(32));
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const start2 = Date.now();
  for (let i = 0; i < 1000; i++) {
    const baseKey = await crypto.subtle.importKey('raw', key, 'HKDF', false, ['deriveBits']);
    await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('test') },
      baseKey, 256
    );
  }
  const dur2 = Date.now() - start2;
  console.log('   1000 derivations in', dur2, 'ms');
  console.log('   Latency:', (dur2 / 1000).toFixed(3), 'ms/op\n');
  
  // 3. AES-GCM Encrypt
  console.log('3. AES-256-GCM Encryption');
  const msgKey = crypto.getRandomValues(new Uint8Array(32));
  const plaintext = 'Test message for benchmarking';
  const aesKey = await crypto.subtle.importKey('raw', msgKey, 'AES-GCM', false, ['encrypt']);
  const start3 = Date.now();
  for (let i = 0; i < 1000; i++) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext));
  }
  const dur3 = Date.now() - start3;
  console.log('   1000 encryptions in', dur3, 'ms');
  console.log('   Latency:', (dur3 / 1000).toFixed(3), 'ms/op');
  console.log('   Throughput:', (1000 / (dur3 / 1000)).toFixed(0), 'ops/s\n');
  
  // 4. HMAC
  console.log('4. HMAC-SHA-256');
  const hmacKey = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), 
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const data = new Uint8Array([1]);
  const start4 = Date.now();
  for (let i = 0; i < 1000; i++) {
    await crypto.subtle.sign('HMAC', hmacKey, data);
  }
  const dur4 = Date.now() - start4;
  console.log('   1000 HMACs in', dur4, 'ms');
  console.log('   Latency:', (dur4 / 1000).toFixed(3), 'ms/op\n');
  
  // 5. SHA-256
  console.log('5. SHA-256 Hash');
  const hashData = new TextEncoder().encode('Test data for hashing');
  const start5 = Date.now();
  for (let i = 0; i < 1000; i++) {
    await crypto.subtle.digest('SHA-256', hashData);
  }
  const dur5 = Date.now() - start5;
  console.log('   1000 hashes in', dur5, 'ms');
  console.log('   Latency:', (dur5 / 1000).toFixed(3), 'ms/op\n');
  
  console.log('=== Benchmark Complete ===');
}

benchmark().catch(e => console.error('Error:', e.message));
