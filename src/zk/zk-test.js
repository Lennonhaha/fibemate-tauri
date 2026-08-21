/**
 * ZK Test Suite - Comprehensive tests for all ZK modules
 */

class ZKTestSuite {
  constructor() {
    this.results = [];
  }

  async runAll() {
    console.log('=== ZK Test Suite ===');
    
    await this.testSchnorr();
    await this.testBulletproofs();
    await this.testZKAuth();
    await this.testIntegration();
    
    this.printSummary();
  }

  async testSchnorr() {
    console.log('\n--- Schnorr Tests ---');
    
    try {
      const prover = new SchnorrProver();
      await prover.init();
      
      const p = BigInt('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245');
      const g = BigInt(2);
      const x = BigInt('1234567890123456789012345678901234567890123456789012345678901234');
      const y = g ** x % p;
      
      const proof = await prover.prove(x, { g, p, y });
      
      const verifier = new SchnorrVerifier();
      const valid = await verifier.verify(
        { t: proof.t.toString(16), s: proof.s.toString(16), c: proof.c.toString(16) },
        { g: g.toString(16), p: p.toString(16), y: y.toString(16) }
      );
      
      this.record('Schnorr Basic Proof', valid);
    } catch (e) {
      this.record('Schnorr Basic Proof', false, e.message);
    }
  }

  async testBulletproofs() {
    console.log('\n--- Bulletproofs Tests ---');
    
    try {
      const bp = new Bulletproofs(32);
      await bp.init();
      
      const v = BigInt(1000000);
      const gamma = bp._randomScalar();
      
      const commitment = bp.commit(v, gamma);
      const proof = await bp.proveRange(v, gamma);
      const valid = await bp.verifyRange(proof, commitment);
      
      this.record('Bulletproofs Range Proof', valid);
    } catch (e) {
      this.record('Bulletproofs Range Proof', false, e.message);
    }
  }

  async testZKAuth() {
    console.log('\n--- ZK Auth Tests ---');
    
    try {
      const zk = new ZKAuth();
      await zk.init();
      
      const proof = await zk.generateLoginProof('testuser', 'testpass123');
      const valid = await zk.verifyLoginProof(proof);
      
      this.record('ZK Auth Full Flow', valid);
    } catch (e) {
      this.record('ZK Auth Full Flow', false, e.message);
    }
  }

  async testIntegration() {
    console.log('\n--- Integration Tests ---');
    
    try {
      const zkInt = new ZKIntegration();
      await zkInt.init();
      
      const available = zkInt.isNewZKAvailable();
      this.record('ZK Integration Available', available);
    } catch (e) {
      this.record('ZK Integration Available', false, e.message);
    }
  }

  record(name, passed, error = null) {
    this.results.push({ name, passed, error });
    console.log(`  ${passed ? '✓' : '✗'} ${name}${error ? ' - ' + error : ''}`);
  }

  printSummary() {
    console.log('\n=== Summary ===');
    const passed = this.results.filter(r => r.passed).length;
    const total = this.results.length;
    console.log(`Passed: ${passed}/${total}`);
    
    if (passed === total) {
      console.log('All tests passed! ✓');
    } else {
      console.log('Some tests failed. Check details above.');
    }
  }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ZKTestSuite;
}
if (typeof window !== 'undefined') {
  window.ZKTestSuite = ZKTestSuite;
}
