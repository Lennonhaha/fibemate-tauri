// SM3 哈希函数 (GB/T 32905-2016)
// 256-bit 输出，类似 SHA-256 但使用不同的常数和变换函数

class SM3 {
  constructor() {
    this.digestSize = 256;
    // 初始哈希值
    this.IV = [
      0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
      0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ];
  }

  // 左循环移位
  static leftRotate(x, n) {
    return ((x << n) | (x >>> (32 - n))) >>> 0;
  }

  // 布尔函数 FF (0 ≤ j ≤ 15)
  static FF0(x, y, z) {
    return (x ^ y ^ z) >>> 0;
  }

  // 布尔函数 FF (16 ≤ j ≤ 63)
  static FF1(x, y, z) {
    return ((x & y) | (x & z) | (y & z)) >>> 0;
  }

  // 布尔函数 GG (0 ≤ j ≤ 15)
  static GG0(x, y, z) {
    return (x ^ y ^ z) >>> 0;
  }

  // 布尔函数 GG (16 ≤ j ≤ 63)
  static GG1(x, y, z) {
    return (((x & y) | ((~x) & z))) >>> 0;
  }

  // 置换函数 P0
  static P0(x) {
    return (x ^ SM3.leftRotate(x, 9) ^ SM3.leftRotate(x, 17)) >>> 0;
  }

  // 置换函数 P1
  static P1(x) {
    return (x ^ SM3.leftRotate(x, 15) ^ SM3.leftRotate(x, 23)) >>> 0;
  }

  // 消息扩展
  messageExpand(B) {
    const W = new Array(68);
    const W1 = new Array(64);

    // 将消息分成 16 个 32 位字
    for (let i = 0; i < 16; i++) {
      W[i] = ((B[i * 4] << 24) | (B[i * 4 + 1] << 16) | (B[i * 4 + 2] << 8) | B[i * 4 + 3]) >>> 0;
    }

    // 扩展到 68 个字
    for (let i = 16; i < 68; i++) {
      const t = W[i - 16] ^ W[i - 9] ^ SM3.leftRotate(W[i - 3], 15);
      W[i] = (SM3.P1(t) ^ SM3.leftRotate(W[i - 13], 7) ^ W[i - 6]) >>> 0;
    }

    // 计算 W'
    for (let i = 0; i < 64; i++) {
      W1[i] = (W[i] ^ W[i + 4]) >>> 0;
    }

    return { W, W1 };
  }

  // 压缩函数
  compress(V, block) {
    const { W, W1 } = this.messageExpand(block);

    let A = V[0];
    let B = V[1];
    let C = V[2];
    let D = V[3];
    let E = V[4];
    let F = V[5];
    let G = V[6];
    let H = V[7];

    const T1 = 0x79cc4519;
    const T2 = 0x7a879d8a;

    for (let j = 0; j < 64; j++) {
      const T = (j < 16) ? T1 : T2;
      const FF = (j < 16) ? SM3.FF0 : SM3.FF1;
      const GG = (j < 16) ? SM3.GG0 : SM3.GG1;

      const SS1 = SM3.leftRotate((SM3.leftRotate(A, 12) + E + SM3.leftRotate(T, j % 32)) & 0xFFFFFFFF, 7);
      const SS2 = (SS1 ^ SM3.leftRotate(A, 12)) >>> 0;
      const TT1 = (FF(A, B, C) + D + SS2 + W1[j]) >>> 0;
      const TT2 = (GG(E, F, G) + H + SS1 + W[j]) >>> 0;

      D = C;
      C = SM3.leftRotate(B, 9);
      B = A;
      A = TT1;
      H = G;
      G = SM3.leftRotate(F, 19);
      F = E;
      E = (TT2 ^ (TT2 << 9) ^ (TT2 << 17)) >>> 0;  // P0(TT2)
      E = (E ^ TT2) >>> 0;  // Actually, this should be P0(TT2)
      
      // Correct P0 implementation
      const P0_TT2 = (TT2 ^ SM3.leftRotate(TT2, 9) ^ SM3.leftRotate(TT2, 17)) >>> 0;
      E = P0_TT2;
    }

    return [
      (V[0] ^ A) >>> 0,
      (V[1] ^ B) >>> 0,
      (V[2] ^ C) >>> 0,
      (V[3] ^ D) >>> 0,
      (V[4] ^ E) >>> 0,
      (V[5] ^ F) >>> 0,
      (V[6] ^ G) >>> 0,
      (V[7] ^ H) >>> 0
    ];
  }

  // 填充消息
  pad(message) {
    const len = message.length;
    const bitLen = len * 8;
    
    // 计算填充长度
    const padLen = (len % 64 < 56) ? (56 - len % 64) : (120 - len % 64);
    
    // 创建填充后的消息
    const padded = new Uint8Array(len + padLen + 8);
    padded.set(message);
    
    // 添加填充位
    padded[len] = 0x80;
    
    // 添加长度 (64 位大端序)
    const view = new DataView(padded.buffer);
    view.setBigUint64(padded.length - 8, BigInt(bitLen), false);

    return padded;
  }

  // 同步哈希（无依赖异步操作）
  hashSync(message) {
    const padded = this.pad(message);
    let V = [...this.IV];
    for (let i = 0; i < padded.length; i += 64) {
      const block = padded.slice(i, i + 64);
      V = this.compress(V, block);
    }
    const result = new Uint8Array(32);
    const view = new DataView(result.buffer);
    for (let i = 0; i < 8; i++) {
      view.setUint32(i * 4, V[i], false);
    }
    return result;
  }

  // 哈希函数主入口
  async hash(message) {
    return this.hashSync(message);
  }
}

// 导出 (适用于浏览器环境)
if (typeof window !== 'undefined') {
  window.SM3 = SM3;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SM3;
}
