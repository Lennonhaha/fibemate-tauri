// SPDX-License-Identifier: GPL-3.0-only
/**
 * WebSocket Message Padding Layer — TLS 1.3 流量随机填充（前端版）
 * 与后端 /opt/fibemate-full/src/crypto/ws-padding.js 完全一致
 *
 * 格式: [1B flags][2B originalLen][N-byte payload][M-byte random padding]
 *   flags: bit0=compressed, bit1=cover_traffic, bits2-7=RESERVED
 */
(function (global) {
  const BLOCK_SIZES = [256, 512, 1024, 2048, 4096];
  const MIN_BLOCK = 256;
  const MAX_BLOCK = 4096;
  const BLOCK_WEIGHTS = [0.35, 0.30, 0.20, 0.10, 0.05];

  function weightedRandomBlock() {
    const r = Math.random();
    let acc = 0;
    for (let i = 0; i < BLOCK_WEIGHTS.length; i++) {
      acc += BLOCK_WEIGHTS[i];
      if (r <= acc) return BLOCK_SIZES[i];
    }
    return MAX_BLOCK;
  }

  // 前端随机字节（WebCrypto 优先，回退 Math.random）
  function randomBytes(n) {
    const buf = new Uint8Array(n);
    if (global.crypto && global.crypto.getRandomValues) {
      global.crypto.getRandomValues(buf);
    } else {
      for (let i = 0; i < n; i++) buf[i] = Math.floor(Math.random() * 256);
    }
    return buf;
  }

  class WsPadding {
    static pad(payload, opts = {}) {
      const raw = typeof payload === 'string' ? new TextEncoder().encode(payload) : new Uint8Array(payload);
      const originalLen = raw.length;

      let targetSize = weightedRandomBlock();
      const headerSize = 3;
      while (targetSize < originalLen + headerSize && targetSize < MAX_BLOCK) {
        const idx = BLOCK_SIZES.indexOf(targetSize);
        targetSize = BLOCK_SIZES[Math.min(idx + 1, BLOCK_SIZES.length - 1)];
      }
      // 超长消息（> MAX_BLOCK）：不填到固定块，按实际长度 + 最少填充
      if (originalLen + headerSize > targetSize) {
        targetSize = originalLen + headerSize;
      }

      let flags = 0x00;
      if (opts.isCover) flags |= 0x02;

      const out = new Uint8Array(targetSize);
      out[0] = flags;
      // 2B originalLen big-endian
      out[1] = (originalLen >> 8) & 0xff;
      out[2] = originalLen & 0xff;
      out.set(raw, headerSize);
      const paddingLen = targetSize - headerSize - originalLen;
      if (paddingLen > 0) {
        out.set(randomBytes(paddingLen), headerSize + originalLen);
      }
      return out;
    }

    static unpad(padded) {
      let buf;
      if (padded instanceof Uint8Array) buf = padded;
      else if (padded instanceof ArrayBuffer) buf = new Uint8Array(padded);
      else if (ArrayBuffer.isView(padded)) buf = new Uint8Array(padded.buffer, padded.byteOffset, padded.byteLength);
      else buf = new Uint8Array(padded);

      if (buf.length < 3) {
        return { payload: buf, isCover: false, originalLen: buf.length };
      }
      const flags = buf[0];
      const originalLen = (buf[1] << 8) | buf[2];
      const isCover = !!(flags & 0x02);
      const payload = buf.subarray(3, 3 + originalLen);
      return { payload, isCover, originalLen };
    }

    static generateCover() {
      const fakeSize = Math.floor(Math.random() * 128) + 32;
      const fakePayload = randomBytes(fakeSize);
      return WsPadding.pad(fakePayload, { isCover: true });
    }
  }

  global.WsPadding = WsPadding;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { WsPadding, BLOCK_SIZES };
  }
})(typeof window !== 'undefined' ? window : globalThis);
