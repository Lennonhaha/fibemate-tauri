# FIBEMATE 卫星网络适配模块

## 概述

为 FIBEMATE 提供卫星网络环境下的自适应优化，确保在卫星互联网（国网/千帆）上的可用性。

## 核心特性

- **自动网络检测**: 识别 5G/4G/WiFi/卫星/离线网络
- **卫星模式**: 自动降配（2跳混合网、FEC、快速重连）
- **前向纠错**: 30%冗余，应对高丢包率
- **快速重连**: 指数退避，1秒起步
- **性能监控**: 实时收集 RTT、抖动、重连时间等指标

## 文件结构

```
satellite/
├── network-detector.js          # 网络类型检测
├── satellite-mode.js            # 卫星模式配置
├── fec.js                       # 前向纠错
├── rapid-reconnect.js           # 快速重连
├── satellite-integration.js     # 集成入口
├── satellite-simulator.js       # 网络模拟器
├── satellite-performance.js     # 性能监控
├── satellite-test.html          # 测试页面
└── satellite-integration.test.js # 单元测试
```

## 快速开始

### 方式1: 自动模式（推荐）

```javascript
import { SatelliteIntegration } from './satellite/satellite-integration.js';

const integration = new SatelliteIntegration(fibemateCore, {
  autoDetect: true,   // 自动检测网络类型
  autoSwitch: true,   // 自动切换模式
  debug: false
});

integration.init();

// 获取状态
console.log(integration.getStatus());

// 销毁
integration.destroy();
```

### 方式2: 手动控制

```javascript
import { NetworkDetector } from './satellite/network-detector.js';
import { SatelliteMode } from './satellite/satellite-mode.js';

const detector = new NetworkDetector();
const satelliteMode = new SatelliteMode(fibemateCore);

// 监听网络变化
detector.addListener((type) => {
  if (type === 'satellite') {
    satelliteMode.apply();
  } else {
    satelliteMode.deactivate();
  }
});

detector.startMonitoring();
```

## 卫星模式配置

```javascript
{
  mixnetHops: 2,           // 降为2跳（延迟可控）
  fecEnabled: true,        // 开启前向纠错
  fecRedundancy: 0.3,      // 30%冗余
  heartbeatInterval: 5000, // 5秒心跳
  heartbeatTimeout: 15000, // 15秒超时
  reconnectInterval: 1000, // 1秒重试
  maxReconnectAttempts: 10,
  messageBufferSize: 100,  // 缓冲100条消息
  coverTrafficInterval: 30000, // 30秒假包
  maxPacketSize: 1024      // 限制包大小
}
```

## 测试

### 单元测试

```bash
# Node.js 环境
node satellite-integration.test.js

# 浏览器环境
open satellite-test.html
```

### 模拟测试

```javascript
import { SatelliteSimulator } from './satellite/satellite-simulator.js';

const simulator = new SatelliteSimulator({
  mode: 'satellite',
  baseLatency: 150,
  jitter: 50,
  packetLoss: 0.05,
  handoverInterval: 60000  // 1分钟切换一次
});

simulator.start();

// 运行一段时间后查看统计
console.log(simulator.getStats());

simulator.stop();
```

### 性能监控

```javascript
import { SatellitePerformance } from './satellite/satellite-performance.js';

const perf = new SatellitePerformance({
  sampleInterval: 1000,   // 每秒采样
  reportInterval: 30000   // 每30秒报告
});

perf.start();

// 监听报告
perf.addListener((report) => {
  console.log('RTT avg:', report.metrics.rtt?.avg);
  console.log('Jitter avg:', report.metrics.jitter?.avg);
});

// 导出CSV
const csv = perf.exportCSV();
```

## 网络类型判定

| 网络类型 | RTT | 丢包率 | 特征 |
|----------|-----|--------|------|
| 5G | < 50ms | < 1% | 低延迟、高带宽 |
| 4G | 50-100ms | < 2% | 中等延迟 |
| WiFi | < 20ms | < 1% | 低延迟、稳定 |
| 卫星 | > 200ms | > 5% | 高延迟、高抖动 |
| 离线 | ∞ | 100% | 无连接 |

## 性能目标

| 指标 | 目标 | 测量方法 |
|------|------|----------|
| 端到端延迟 | < 3秒 | WebRTC getStats |
| 消息到达率 | > 95% | 发送100条统计 |
| 切换恢复时间 | < 5秒 | 断网重连计时 |
| 带宽占用 | < 50kbps | Chrome DevTools |

## 注意事项

1. **Network Information API**: 部分浏览器不支持，会降级到RTT探测
2. **FEC开销**: 30%冗余会增加带宽消耗，卫星模式下可接受
3. **心跳频率**: 卫星模式下5秒心跳，比普通模式更频繁
4. **切换检测**: RTT突变>500ms时触发切换模式

## 版本历史

- v1.0.0 (2026-05-13): 初始版本，包含基础适配功能

## 作者

FIBEMATE 开发团队
