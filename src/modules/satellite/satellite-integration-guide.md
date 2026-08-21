# FIBEMATE 卫星网络适配 - 集成指南

## 概述

本文档描述如何将卫星网络适配模块集成到 FIBEMATE 主应用。

## 集成步骤

### 1. 文件位置

将卫星模块放置在 `src/modules/satellite/` 目录：

```
src/modules/satellite/
├── network-detector.js          # 网络类型检测
├── satellite-mode.js            # 卫星模式配置
├── fec.js                       # 前向纠错
├── rapid-reconnect.js           # 快速重连
├── satellite-integration.js     # 统一集成入口
├── satellite-performance.js     # 性能监控
├── satellite-simulator.js       # 网络模拟器
├── satellite-test-runner.js     # 测试运行器
└── satellite-README.md          # 模块文档
```

### 2. HTML 引入

在 `main.html` 的 `<head>` 中添加：

```html
<!-- Satellite Network Adaptation -->
<script src="modules/satellite/network-detector.js" defer></script>
<script src="modules/satellite/satellite-mode.js" defer></script>
<script src="modules/satellite/fec.js" defer></script>
<script src="modules/satellite/rapid-reconnect.js" defer></script>
<script src="modules/satellite/satellite-integration.js" defer></script>
```

### 3. JavaScript 初始化

在 `main.js` 的 `DOMContentLoaded` 中添加：

```javascript
// P1: Initialize satellite network adaptation
initSatelliteAdaptation();
```

并定义初始化函数：

```javascript
function initSatelliteAdaptation() {
  if (typeof SatelliteIntegration === 'undefined') {
    console.warn('[Satellite] SatelliteIntegration not available');
    return;
  }

  const fibemateCore = createSatelliteCoreAdapter();
  const integration = new SatelliteIntegration(fibemateCore, {
    autoDetect: true,
    autoSwitch: true,
    debug: true
  });

  integration.init();
  window.satelliteIntegration = integration;
}
```

### 4. 核心适配器

创建 `createSatelliteCoreAdapter()` 函数桥接 FIBEMATE 核心功能：

```javascript
function createSatelliteCoreAdapter() {
  return {
    setMixnetHops(hops) { /* ... */ },
    setFEC(enabled, redundancy) { /* ... */ },
    setHeartbeatInterval(interval) { /* ... */ },
    setHeartbeatTimeout(timeout) { /* ... */ },
    // ... 其他方法
  };
}
```

### 5. 设置页面

在 `modules/settings.js` 中添加开关：

```javascript
<div class="setting-item">
  <div class="setting-info">
    <div class="setting-name">Satellite Mode</div>
    <div class="setting-desc">Auto-adapt for satellite networks</div>
  </div>
  <label class="toggle">
    <input type="checkbox" data-setting="satelliteMode" checked>
    <span class="toggle-slider"></span>
  </label>
</div>
```

### 6. WebSocket 集成

在 `modules/websocket.js` 中添加事件通知：

```javascript
STATE.ws.onopen = () => {
  // ... existing code ...
  if (window.satelliteIntegration) {
    window.satelliteIntegration.core.emit('websocketConnected');
  }
};

STATE.ws.onclose = (event) => {
  // ... existing code ...
  if (window.satelliteIntegration) {
    window.satelliteIntegration.core.emit('websocketClose', event);
  }
};
```

## 配置选项

### SatelliteIntegration 选项

```javascript
{
  autoDetect: true,    // 自动检测网络类型
  autoSwitch: true,    // 自动切换模式
  debug: false         // 调试日志
}
```

### 卫星模式配置

```javascript
{
  mixnetHops: 2,           // 混合网跳数
  fecEnabled: true,        // 启用FEC
  fecRedundancy: 0.3,      // FEC冗余比例
  heartbeatInterval: 5000, // 心跳间隔(ms)
  heartbeatTimeout: 15000, // 心跳超时(ms)
  reconnectInterval: 1000, // 重连间隔(ms)
  maxReconnectAttempts: 10 // 最大重连次数
}
```

## 事件

### 网络事件

- `networkChanged`: 网络类型变化
- `satelliteModeEntered`: 进入卫星模式
- `normalModeEntered`: 进入普通模式
- `offlineModeEntered`: 进入离线模式

### WebSocket 事件

- `websocketConnected`: WebSocket 连接成功
- `websocketClose`: WebSocket 连接断开

## 测试

### 运行测试

1. 打开 `satellite-test-page.html`
2. 点击"运行全部测试"
3. 查看测试结果和日志

### 测试覆盖

- 网络类型检测
- 卫星模式切换
- FEC 编码/解码
- 快速重连
- 性能监控

## 调试

### 控制台访问

```javascript
// 查看卫星集成状态
window.satelliteIntegration.getStatus();

// 手动切换模式
window.satelliteIntegration.switchMode('satellite');
window.satelliteIntegration.switchMode('normal');

// 查看网络信息
window.satelliteIntegration.detector.getInfo();
```

### 日志级别

设置 `debug: true` 启用详细日志：

```javascript
const integration = new SatelliteIntegration(core, { debug: true });
```

## 故障排除

### 模块未加载

检查浏览器控制台是否有 404 错误，确认文件路径正确。

### 自动检测不工作

检查 Network Information API 支持：

```javascript
console.log('Connection API:', navigator.connection);
```

### 卫星模式未激活

检查网络类型判定：

```javascript
window.satelliteIntegration.detector.detect().then(type => {
  console.log('Detected:', type);
});
```

## 版本历史

- v1.0.0 (2026-05-13): 初始版本

## 参考

- [卫星网络适配方案](../../FIBEMATE_P1_卫星网络适配方案.md)
- [五网络融合战略](../../FIBEMATE_五网络融合战略.md)
