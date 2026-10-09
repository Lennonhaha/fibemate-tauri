// SPDX-License-Identifier: GPL-3.0-only
/**
 * WebSocket Message Padding Layer — TLS 1.3 流量随机填充
 *
 * 目标: 所有 WebSocket 消息统一大小，消除流量指纹
 * 策略:
 * 1. 随机块大小 (256B, 512B, 1KB, 2KB, 4KB)
 * 2. 填充用加密随机字节(不可区分子密文)
 * 3. 对上层完全透明
 * 4. 服务端 & 客户端共用同一模块
 *
 * 格式: [1B flags][2B originalLen][N-byte payload][M-byte random padding]
 * flags: bit0=compressed, bit1=cover_traffic, bit2=extended_len(4B len), bits3-7=RESERVED
 *
 * 环境兼容: 纯 Web API —— Node 19+ / 浏览器 / Tauri WebView 通用
 * - 无 require('crypto')
 * - 无 Buffer
 * - 无 module.exports 强制依赖
 */

const BLOCK_SIZES = [256, 512, 1024, 2048, 4096];
const MIN_BLOCK = 256;
const MAX_BLOCK = 4096;

// Weight distribution: prefer smaller sizes to reduce bandwidth waste
const BLOCK_WEIGHTS = [0.35, 0.30, 0.20, 0.10, 0.05];

// ── 环境兼容层 ──────────────────────────────────────────────

const _crypto = (typeof globalThis !== 'undefined' && globalThis.crypto)
  ? globalThis.crypto
  : (() => { throw new Error('ws-padding: no globalThis.crypto available'); })();

function randomBytes(n) {
  const buf = new Uint8Array(n);
  _crypto.getRandomValues(buf);
  return buf;
}

function toUint8(payload) {
  if (payload instanceof Uint8Array) return payload;
  if (typeof payload === 'string') return new TextEncoder().encode(payload);
  if (Array.isArray(payload)) return new Uint8Array(payload);
  if (payload instanceof ArrayBuffer) return new Uint8Array(payload);
  if (ArrayBuffer.isView(payload)) return new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength);
  throw new TypeError('ws-padding: unsupported payload type: ' + typeof payload);
}

function concatUint8(chunks) {
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

// ── 主逻辑 ──────────────────────────────────────────────────

function weightedRandomBlock() {
  const r = Math.random();
  let acc = 0;
  for (let i = 0; i < BLOCK_WEIGHTS.length; i++) {
    acc += BLOCK_WEIGHTS[i];
    if (r <= acc) return BLOCK_SIZES[i];
  }
  return MAX_BLOCK;
}

class WsPadding {
  static pad(payload, opts = {}) {
    const raw = toUint8(payload);
    const originalLen = raw.length;

    // 大消息（> 64KB）：16 位长度字段放不下，改用扩展头（flags bit2 = EXT，4 字节长度）
    const ext = originalLen > 0xFFFF;
    const headerSize = ext ? 5 : 3;

    let flags = 0x00;
    if (opts.isCover) flags |= 0x02;
    if (ext) flags |= 0x04;

    const header = new Uint8Array(headerSize);
    header[0] = flags;
    if (ext) {
      header[1] = (originalLen >>> 24) & 0xFF;
      header[2] = (originalLen >>> 16) & 0xFF;
      header[3] = (originalLen >>> 8) & 0xFF;
      header[4] = originalLen & 0xFF;
    } else {
      header[1] = (originalLen >>> 8) & 0xFF;
      header[2] = originalLen & 0xFF;
    }

    // 大消息本就不需要补 pad（远超块大小）
    let paddingLen = 0;
    if (!ext) {
      let targetSize = weightedRandomBlock();
      while (targetSize < originalLen + headerSize && targetSize < MAX_BLOCK) {
        const idx = BLOCK_SIZES.indexOf(targetSize);
        targetSize = BLOCK_SIZES[Math.min(idx + 1, BLOCK_SIZES.length - 1)];
      }
      paddingLen = targetSize - headerSize - originalLen;
    }
    const padding = paddingLen > 0 ? randomBytes(paddingLen) : new Uint8Array(0);

    return concatUint8([header, raw, padding]);
  }

  static unpad(padded) {
    if (padded instanceof ArrayBuffer) padded = new Uint8Array(padded);
    if (padded.length < 3) {
      return { payload: padded, isCover: false, originalLen: padded.length };
    }
    const flags = padded[0];

    // 扩展头（flags bit2）：4 字节长度，支持 > 64KB
    if (flags & 0x04) {
      if (padded.length < 5) return { payload: padded, isCover: !!(flags & 0x02), originalLen: padded.length };
      const originalLen = (((padded[1] << 24) | (padded[2] << 16) | (padded[3] << 8) | padded[4]) >>> 0);
      // 越界：不是合法填充格式——原样返回全部字节（不丢头，避免二次错位）
      if (originalLen > padded.length - 5) {
        return { payload: padded, isCover: !!(flags & 0x02), originalLen: padded.length };
      }
      return { payload: padded.subarray(5, 5 + originalLen), isCover: !!(flags & 0x02), originalLen };
    }

    const originalLen = (padded[1] << 8) | padded[2];
    // 越界：输入非填充格式——原样返回（与服务器版对齐）
    if (originalLen > padded.length - 3) {
      return { payload: padded, isCover: false, originalLen: padded.length };
    }
    const isCover = !!(flags & 0x02);
    const payload = padded.subarray(3, 3 + originalLen);
    return { payload, isCover, originalLen };
  }

  static generateCover() {
    const fakeSize = Math.floor(Math.random() * 128) + 32;
    const fakePayload = randomBytes(fakeSize);
    return WsPadding.pad(fakePayload, { isCover: true });
  }
}

// ── 导出——三端兼容 ────────────────────────────────────────

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { WsPadding, BLOCK_SIZES };
}

if (typeof globalThis !== 'undefined') {
  globalThis.WsPadding = WsPadding;
  globalThis.WsPaddingBlockSizes = BLOCK_SIZES;
}