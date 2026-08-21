# FIBEMATE 量子城域网适配模块

## 概述

量子城域网适配模块为 FIBEMATE 提供量子安全通信能力，包括：

- **QKD密钥管理**：从量子密钥分发网络获取密钥
- **量子随机数生成**：使用量子熵源生成真随机数
- **混合加密**：经典加密 + 量子密钥增强
- **后量子密码学集成**：为未来的量子计算威胁做准备

## 架构

```
QuantumIntegration (统一入口)
├── QuantumAdapter (量子适配器)
│   ├── QKD密钥获取
│   ├── QRNG随机数
│   └── 熵池管理
└── QuantumCrypto (量子密码学)
    ├── 混合密钥生成
    ├── 量子增强加密
    └── 安全密钥擦除
```

## 文件说明

| 文件 | 功能 |
|------|------|
| `quantum-adapter.js` | QKD/QRNG适配器 |
| `quantum-crypto.js` | 量子密码学实现 |
| `quantum-integration.js` | 统一集成入口 |
| `quantum-test.js` | 测试套件 |
| `quantum-README.md` | 本文档 |

## 快速开始

### 1. 初始化

```javascript
const quantum = new QuantumIntegration(fibemateCore, {
  qkdEndpoint: 'http://qkd-provider.example.com',
  qrngEndpoint: 'http://qrng-provider.example.com',
  autoEnable: true,
  debug: true
});

await quantum.init();
```

### 2. 增强密钥交换

```javascript
// 在X3DH握手时调用
const enhanced = await quantum.enhanceKeyExchange(peerId, classicalKey);
console.log('Key type:', enhanced.type); // 'hybrid' 或 'classical'
```

### 3. 量子加密

```javascript
const encrypted = await quantum.encrypt(peerId, plaintext);
const decrypted = await quantum.decrypt(peerId, encrypted.ciphertext, encrypted.iv);
```

### 4. 获取量子随机数

```javascript
const random = await quantum.getQuantumRandom(32);
```

## 配置选项

### QuantumIntegration

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `qkdEndpoint` | string | null | QKD服务URL |
| `qrngEndpoint` | string | null | QRNG服务URL |
| `autoDetect` | boolean | true | 自动检测量子网络 |
| `autoEnable` | boolean | true | 自动启用量子增强 |
| `debug` | boolean | false | 调试日志 |

### QuantumAdapter

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `keyRefreshInterval` | number | 3600000 | 密钥刷新间隔(ms) |
| `keyLength` | number | 256 | 密钥长度(bits) |

## 事件

- `quantumEnabled`: 量子增强已启用
- `quantumDisabled`: 量子增强已禁用

## 测试

```javascript
const runner = new QuantumTestRunner();
await runner.runAllTests();
```

## 量子网络提供商

### 国内量子网络

| 提供商 | 服务 | 覆盖城市 |
|--------|------|----------|
| 国盾量子 | QKD | 合肥、北京、上海 |
| 问天量子 | QKD/QRNG | 济南、武汉 |
| 启科量子 | 量子计算 | 珠海 |

### 国际服务

| 服务 | URL | 说明 |
|------|-----|------|
| ANU QRNG | https://qrng.anu.edu.au | 澳大利亚国立大学 |

## 注意事项

1. **QKD需要专用硬件**：实际部署需要量子密钥分发设备
2. **QRNG可通过API获取**：部分提供商提供在线量子随机数服务
3. **回退机制**：量子服务不可用时自动回退到经典加密
4. **密钥安全**：量子密钥使用后立即安全擦除

## 版本历史

- v1.0.0 (2026-05-13): 初始版本

## 参考

- [五网络融合战略](../../FIBEMATE_五网络融合战略.md)
- [卫星网络适配](../satellite/satellite-README.md)
