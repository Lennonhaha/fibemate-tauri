# FIBEMATE 5G-A 网络适配模块

## 概述

5G-A网络适配模块为 FIBEMATE 提供5G-A网络优化能力，包括：

- **网络特性检测**：自动检测5G/5G-A网络
- **网络切片管理**：支持网络切片选择
- **边缘计算**：边缘节点发现与任务卸载
- **超低延迟优化**：消息传输策略优化
- **大带宽适配**：媒体传输自适应

## 架构

```
FiveGIntegration (统一入口)
├── FiveGAdapter (网络适配器)
│   ├── 5G/5G-A检测
│   ├── 边缘节点发现
│   └── 网络质量监测
└── FiveGOptimization (优化模块)
    ├── 消息传输优化
    ├── 媒体自适应
    └── 边缘计算卸载
```

## 文件说明

| 文件 | 功能 |
|------|------|
| `5g-a-adapter.js` | 5G-A网络适配器 |
| `5g-a-optimization.js` | 网络优化模块 |
| `5g-a-integration.js` | 统一集成入口 |
| `5g-a-test.js` | 测试套件 |
| `5g-a-README.md` | 本文档 |

## 快速开始

### 1. 初始化

```javascript
const fiveG = new FiveGIntegration(fibemateCore, {
  edgeEndpoints: [
    'http://edge1.example.com',
    'http://edge2.example.com'
  ],
  autoEnable: true,
  debug: true
});

await fiveG.init();
```

### 2. 优化消息发送

```javascript
const result = await fiveG.optimizeMessageSend(message, 'high');
console.log('Strategy:', result.strategy);
```

### 3. 优化媒体传输

```javascript
const result = await fiveG.optimizeMediaTransfer(file, 'video');
console.log('Bitrate:', result.videoBitrate);
```

### 4. 边缘计算卸载

```javascript
const result = await fiveG.offloadToEdge('encryption', data);
if (result.offloaded) {
  console.log('Result:', result.result);
}
```

## 配置选项

### FiveGIntegration

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `edgeEndpoints` | array | [] | 边缘计算节点列表 |
| `autoDetect` | boolean | true | 自动检测5G网络 |
| `autoEnable` | boolean | true | 自动启用优化 |
| `debug` | boolean | false | 调试日志 |

### FiveGAdapter

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `latencyTarget` | number | 10 | 目标延迟(ms) |
| `bandwidthTarget` | number | 1000 | 目标带宽(Mbps) |

### FiveGOptimization

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enableEdgeOffload` | boolean | true | 启用边缘卸载 |
| `enableAdaptiveBitrate` | boolean | true | 启用自适应码率 |
| `enablePredictivePrefetch` | boolean | true | 启用预测性预取 |

## 事件

- `5gEnabled`: 5G优化已启用
- `5gDisabled`: 5G优化已禁用

## 测试

```javascript
const runner = new FiveGTestRunner();
await runner.runAllTests();
```

## 网络策略

### 5G-A 模式

- 延迟 < 5ms：直接发送，不压缩
- 带宽 > 1Gbps：原图传输，大文件分块
- 边缘计算：自动卸载计算任务

### 5G 模式

- 延迟 < 20ms：批量发送
- 带宽 100-1000Mbps：适度压缩
- 边缘计算：选择性卸载

### 普通网络

- 延迟 > 20ms：压缩后发送
- 带宽 < 100Mbps：高度压缩
- 边缘计算：禁用

## 注意事项

1. **Network Information API**：需要浏览器支持
2. **边缘节点**：需要配置实际的边缘计算节点
3. **回退机制**：非5G网络自动回退到普通模式
4. **电池优化**：5G-A模式下注意电池消耗

## 版本历史

- v1.0.0 (2026-05-13): 初始版本

## 参考

- [五网络融合战略](../../FIBEMATE_五网络融合战略.md)
- [卫星网络适配](../satellite/satellite-README.md)
- [量子城域网](../quantum/quantum-README.md)
