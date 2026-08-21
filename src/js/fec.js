/**
 * FIBEMATE Forward Error Correction (FEC)
 * 前向纠错 - 应对卫星网络高丢包率
 * 
 * @version 1.0.0
 * @author FIBEMATE Team
 * @since 2026-05-13
 */

class ForwardErrorCorrection {
  constructor(options = {}) {
    this.redundancy = options.redundancy || 0.3;        // 冗余比例
    this.maxPacketSize = options.maxPacketSize || 1024; // 最大包大小
    this.debug = options.debug || false;
    
    // 统计
    this.stats = {
      packetsEncoded: 0,
      packetsDecoded: 0,
      packetsRecovered: 0,
      packetsLost: 0,
      bytesOverhead: 0
    };
  }

  /**
   * 编码：为数据包添加冗余
   * @param {ArrayBuffer|Uint8Array} data - 原始数据
   * @returns {Array<Object>} 编码后的包组（含冗余包）
   */
  encode(data) {
    // 将数据分片
    const chunks = this.chunkData(data);
    const k = chunks.length;  // 原始包数
    
    if (k === 0) {
      return [];
    }
    
    // 计算冗余包数
    const n = Math.ceil(k * (1 + this.redundancy));
    const r = n - k;  // 冗余包数
    
    this.log(`Encoding: ${k} data chunks + ${r} redundant = ${n} total`);
    
    // 为每个数据包添加序号和校验
    const dataPackets = chunks.map((chunk, index) => ({
      type: 'data',
      index: index,
      total: k,
      redundancy: r,
      data: chunk,
      checksum: this.calculateChecksum(chunk)
    }));
    
    // 生成冗余包（使用XOR简单冗余）
    const redundantPackets = this.generateRedundantPackets(dataPackets, r);
    
    // 合并所有包
    const allPackets = [...dataPackets, ...redundantPackets];
    
    // 更新统计
    this.stats.packetsEncoded += k;
    this.stats.bytesOverhead += redundantPackets.reduce((sum, p) => sum + p.data.length, 0);
    
    return allPackets;
  }

  /**
   * 解码：恢复丢失的包
   * @param {Array<Object>} receivedPackets - 接收到的包（可能包含null表示丢失）
   * @param {number} totalPackets - 总包数（原始+冗余）
   * @returns {Object} 解码结果
   */
  decode(receivedPackets, totalPackets) {
    const k = Math.floor(totalPackets / (1 + this.redundancy));  // 原始包数
    const receivedCount = receivedPackets.filter(p => p !== null).length;
    const lostCount = totalPackets - receivedCount;
    
    this.log(`Decoding: ${receivedCount}/${totalPackets} received, ${lostCount} lost`);
    
    // 检查是否可恢复
    if (receivedCount < k) {
      this.log(`Cannot recover: need ${k}, have ${receivedCount}`);
      this.stats.packetsLost += lostCount;
      return {
        success: false,
        recovered: false,
        data: null,
        missingIndices: this.findMissingIndices(receivedPackets, totalPackets)
      };
    }
    
    // 分离数据包和冗余包
    const dataPackets = [];
    const redundantPackets = [];
    
    receivedPackets.forEach(packet => {
      if (!packet) return;
      
      if (packet.type === 'data') {
        dataPackets.push(packet);
      } else {
        redundantPackets.push(packet);
      }
    });
    
    // 找出丢失的数据包
    const missingDataIndices = [];
    for (let i = 0; i < k; i++) {
      if (!dataPackets.find(p => p.index === i)) {
        missingDataIndices.push(i);
      }
    }
    
    // 尝试恢复丢失的数据包
    let recoveredCount = 0;
    
    if (missingDataIndices.length > 0 && redundantPackets.length > 0) {
      recoveredCount = this.recoverLostPackets(
        dataPackets,
        redundantPackets,
        missingDataIndices
      );
    }
    
    // 按顺序重组数据
    const sortedPackets = dataPackets
      .concat(recoveredCount > 0 ? [] : [])  // 已恢复的包已加入dataPackets
      .sort((a, b) => a.index - b.index);
    
    // 验证完整性
    if (sortedPackets.length < k) {
      this.stats.packetsLost += (k - sortedPackets.length);
      return {
        success: false,
        recovered: recoveredCount > 0,
        data: null,
        missingIndices: missingDataIndices
      };
    }
    
    // 合并数据
    const recoveredData = this.mergeChunks(sortedPackets.map(p => p.data));
    
    // 更新统计
    this.stats.packetsDecoded += k;
    this.stats.packetsRecovered += recoveredCount;
    
    this.log(`Decode success: ${recoveredCount} packets recovered`);
    
    return {
      success: true,
      recovered: recoveredCount > 0,
      data: recoveredData,
      stats: {
        total: totalPackets,
        received: receivedCount,
        lost: lostCount,
        recovered: recoveredCount
      }
    };
  }

  /**
   * 将数据分片
   * @param {ArrayBuffer|Uint8Array} data
   * @returns {Array<Uint8Array>}
   */
  chunkData(data) {
    const uint8Array = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    const chunks = [];
    
    for (let i = 0; i < uint8Array.length; i += this.maxPacketSize) {
      chunks.push(uint8Array.slice(i, i + this.maxPacketSize));
    }
    
    return chunks;
  }

  /**
   * 合并数据片
   * @param {Array<Uint8Array>} chunks
   * @returns {ArrayBuffer}
   */
  mergeChunks(chunks) {
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    
    let offset = 0;
    chunks.forEach(chunk => {
      result.set(chunk, offset);
      offset += chunk.length;
    });
    
    return result.buffer;
  }

  /**
   * 生成冗余包
   * @param {Array<Object>} dataPackets
   * @param {number} redundancyCount
   * @returns {Array<Object>}
   */
  generateRedundantPackets(dataPackets, redundancyCount) {
    const redundantPackets = [];
    
    for (let i = 0; i < redundancyCount; i++) {
      // 使用XOR生成冗余
      const xorResult = this.xorPackets(dataPackets);
      
      redundantPackets.push({
        type: 'redundant',
        index: dataPackets.length + i,
        total: dataPackets.length,
        redundancy: redundancyCount,
        data: xorResult,
        checksum: this.calculateChecksum(xorResult),
        // 记录参与的原始包索引
        covers: dataPackets.map(p => p.index)
      });
    }
    
    return redundantPackets;
  }

  /**
   * XOR多个包
   * @param {Array<Object>} packets
   * @returns {Uint8Array}
   */
  xorPackets(packets) {
    if (packets.length === 0) {
      return new Uint8Array(0);
    }
    
    // 找到最大长度
    const maxLength = Math.max(...packets.map(p => p.data.length));
    const result = new Uint8Array(maxLength);
    
    // XOR所有包
    packets.forEach(packet => {
      for (let i = 0; i < packet.data.length; i++) {
        result[i] ^= packet.data[i];
      }
    });
    
    return result;
  }

  /**
   * 恢复丢失的包
   * @param {Array<Object>} dataPackets
   * @param {Array<Object>} redundantPackets
   * @param {Array<number>} missingIndices
   * @returns {number} 恢复成功的包数
   */
  recoverLostPackets(dataPackets, redundantPackets, missingIndices) {
    let recoveredCount = 0;
    
    // 简化实现：对于每个丢失的包，尝试用冗余包恢复
    // 实际生产环境应使用 Reed-Solomon 或 LDPC
    
    missingIndices.forEach(missingIndex => {
      // 找到包含该丢失包的冗余包
      const relevantRedundant = redundantPackets.find(r => 
        r.covers.includes(missingIndex)
      );
      
      if (!relevantRedundant) {
        return;
      }
      
      // 用冗余包 XOR 其他已知数据包来恢复
      const knownPackets = dataPackets.filter(p => 
        relevantRedundant.covers.includes(p.index)
      );
      
      if (knownPackets.length === relevantRedundant.covers.length - 1) {
        // 只有一个包丢失，可以恢复
        const recovered = this.xorPackets([
          relevantRedundant,
          ...knownPackets
        ]);
        
        // 创建恢复的数据包
        const recoveredPacket = {
          type: 'data',
          index: missingIndex,
          total: relevantRedundant.total,
          data: recovered,
          checksum: this.calculateChecksum(recovered),
          recovered: true
        };
        
        dataPackets.push(recoveredPacket);
        recoveredCount++;
        this.log(`Recovered packet ${missingIndex}`);
      }
    });
    
    return recoveredCount;
  }

  /**
   * 计算校验和
   * @param {Uint8Array} data
   * @returns {number}
   */
  calculateChecksum(data) {
    let sum = 0;
    for (let i = 0; i < data.length; i++) {
      sum = (sum + data[i]) % 65536;
    }
    return sum;
  }

  /**
   * 验证校验和
   * @param {Object} packet
   * @returns {boolean}
   */
  verifyChecksum(packet) {
    const calculated = this.calculateChecksum(packet.data);
    return calculated === packet.checksum;
  }

  /**
   * 找出丢失的索引
   * @param {Array<Object>} packets
   * @param {number} total
   * @returns {Array<number>}
   */
  findMissingIndices(packets, total) {
    const missing = [];
    const receivedIndices = new Set(
      packets.filter(p => p !== null).map(p => p.index)
    );
    
    for (let i = 0; i < total; i++) {
      if (!receivedIndices.has(i)) {
        missing.push(i);
      }
    }
    
    return missing;
  }

  /**
   * 获取统计信息
   * @returns {Object}
   */
  getStats() {
    return {
      ...this.stats,
      redundancy: this.redundancy,
      overheadRatio: this.stats.packetsEncoded > 0 
        ? (this.stats.bytesOverhead / (this.stats.packetsEncoded * this.maxPacketSize))
        : 0
    };
  }

  /**
   * 重置统计
   */
  resetStats() {
    this.stats = {
      packetsEncoded: 0,
      packetsDecoded: 0,
      packetsRecovered: 0,
      packetsLost: 0,
      bytesOverhead: 0
    };
  }

  /**
   * 日志输出
   * @param {...any} args
   */
  log(...args) {
    if (this.debug) {
      console.log('[FEC]', ...args);
    }
  }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ForwardErrorCorrection;
}

if (typeof window !== 'undefined') {
  window.ForwardErrorCorrection = ForwardErrorCorrection;
}
