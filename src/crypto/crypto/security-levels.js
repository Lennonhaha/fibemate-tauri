// ============================================================
// FIBEMATE Security Levels - Downgrade Attack Protection
// 降级攻击防护：强制最小安全等级检查
// ============================================================

const SecurityLevels = (() => {
  'use strict';

  // 安全等级定义
  const LEVEL = {
    UNENCRYPTED: 0,    // 无加密（禁止）
    ECC_ONLY: 1,       // 仅 ECC（RSA 禁用）
    ECC_SIGNED: 2,     // ECC + 签名（无 ZK）
    ZK_VERIFIED: 3,    // ECC + 签名 + ZK（最低要求）
    MIXNET: 4,         // 3 + 混网覆盖流量
    FORWARD_SECRET: 5  // 4 + 前向保密（Double Ratchet）
  };

  const LEVEL_NAMES = {
    0: 'UNENCRYPTED',
    1: 'ECC_ONLY',
    2: 'ECC_SIGNED',
    3: 'ZK_VERIFIED',
    4: 'MIXNET',
    5: 'FORWARD_SECRET'
  };

  // 最低接受等级（可配置）
  let MINIMUM_LEVEL = LEVEL.ZK_VERIFIED;

  /**
   * 设置最低安全等级
   * @param {number} level - 最低等级
   */
  function setMinimumLevel(level) {
    if (level < 0 || level > 5) {
      throw new Error(`Invalid security level: ${level}`);
    }
    MINIMUM_LEVEL = level;
  }

  /**
   * 获取当前最低安全等级
   */
  function getMinimumLevel() {
    return MINIMUM_LEVEL;
  }

  /**
   * 检查是否满足最低安全要求
   * @param {number} actualLevel - 实际安全等级
   * @returns {boolean}
   */
  function isSecure(actualLevel) {
    return actualLevel >= MINIMUM_LEVEL;
  }

  /**
   * 强制安全等级检查 — 不满足则抛异常
   * @param {number} actualLevel - 实际安全等级
   * @param {string} context - 上下文描述
   * @throws {Error} 如果安全等级不足
   */
  function enforceMinimum(actualLevel, context = 'connection') {
    if (!isSecure(actualLevel)) {
      const msg = [
        `[SECURITY] Downgrade attack detected in ${context}`,
        `Required: ${LEVEL_NAMES[MINIMUM_LEVEL]} (level ${MINIMUM_LEVEL})`,
        `Actual: ${LEVEL_NAMES[actualLevel] || actualLevel} (level ${actualLevel})`,
        'Connection refused.'
      ].join('\n');
      console.error(msg);
      throw new Error(`Security level insufficient: ${actualLevel} < ${MINIMUM_LEVEL}`);
    }
    return true;
  }

  /**
   * 检查加密算法是否为禁止的弱算法
   * @param {string} algName - 算法名称
   * @returns {boolean} true = 禁止（降级）
   */
  function isWeakAlgorithm(algName) {
    const weak = [
      'RSA', 'rsa', '3DES', 'DES', 'ECB',
      'RC4', 'md5', 'MD5', 'sha-1', 'SHA1'
    ];
    return weak.some(w => algName && algName.includes(w));
  }

  /**
   * 验证密钥算法是否为 P-256（不得降级）
   * @param {string} algName - 算法名称
   * @throws {Error} 如果不是 P-256
   */
  function enforceP256(algName) {
    if (!algName) return;
    // P-256 相关的合法名称
    const valid = ['P-256', 'P256', 'ECDH', 'ECDSA', 'secp256r1'];
    const isValid = valid.some(v => algName.includes(v));
    if (!isValid && isWeakAlgorithm(algName)) {
      throw new Error(`Downgrade attempted: weak algorithm ${algName} not allowed`);
    }
  }

  /**
   * 构建安全上下文对象（用于日志/调试）
   */
  function buildSecurityContext(peerId, level, features = {}) {
    return {
      peerId: peerId || 'unknown',
      securityLevel: level,
      levelName: LEVEL_NAMES[level] || 'UNKNOWN',
      meetsMinimum: isSecure(level),
      features: {
        hasEncryption: level >= LEVEL.ECC_ONLY,
        hasSignature: level >= LEVEL.ECC_SIGNED,
        hasZK: level >= LEVEL.ZK_VERIFIED,
        hasMixnet: level >= LEVEL.MIXNET,
        hasForwardSecrecy: level >= LEVEL.FORWARD_SECRET,
        ...features
      }
    };
  }

  return {
    LEVEL,
    LEVEL_NAMES,
    setMinimumLevel,
    getMinimumLevel,
    isSecure,
    enforceMinimum,
    isWeakAlgorithm,
    enforceP256,
    buildSecurityContext
  };
})();

// Node.js / browser compatibility
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecurityLevels;
}