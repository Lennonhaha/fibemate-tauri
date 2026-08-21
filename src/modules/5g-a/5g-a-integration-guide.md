# FIBEMATE 5G-A 网络适配 - 集成指南

## 概述

本文档描述如何将5G-A网络适配模块集成到 FIBEMATE 主应用。

## 集成步骤

### 1. 文件位置

将5G-A模块放置在 `src/modules/5g-a/` 目录：

```
src/modules/5g-a/
├── 5g-a-adapter.js          # 5G-A网络适配器
├── 5g-a-optimization.js     # 网络优化模块
├── 5g-a-integration.js      # 统一集成入口
├── 5g-a-test.js             # 测试套件
└── 5g-a-README.md           # 模块文档
```

### 2. HTML 引入

在 `main.html` 的 `<head>` 中添加：

```html
<!-- 5G-A Network -->
<script src="modules/5g-a/5g-a-adapter.js" defer></script>
<script src="modules/5g-a/5g-a-optimization.js" defer></script>
<script src="modules/5g-a/5g-a-integration.js" defer></script>
```

### 3. JavaScript 初始化

在 `main.js` 的 `DOMContentLoaded` 中添加：

```javascript
// P3: Initialize 5G-A network
init5GAdaptation();
```

并定义初始化函数：

```javascript
function init5GAdaptation() {
  if (typeof FiveGIntegration === 'undefined') {
    console.warn('[5G-A] FiveGIntegration not available');
    return;
  }

  const fibemateCore = create5GCoreAdapter();
  const fiveG = new FiveGIntegration(fibemateCore, {
    edgeEndpoints: [],  // 配置实际边缘节点
    autoDetect: true,
    autoEnable: true,
    debug: true
  });

  fiveG.init().then(available => {
    if (available) {
      console.log('[5G-A] 5G-A network adaptation initialized');
    } else {
      console.log('[5G-A] 5G network not available, using normal mode');
    }
  }).catch(err => {
    console.warn('[5G-A] Initialization failed:', err.message);
  });

  window.fiveGIntegration = fiveG;
}
```

### 4. 核心适配器

```javascript
function create5GCoreAdapter() {
  return {
    emit(event, data) {
      window.dispatchEvent(new CustomEvent(event, { detail: data }));
    },
    on(event, callback) {
      window.addEventListener(event, (e) => callback(e.detail));
    }
  };
}
```

### 5. 设置页面

在 `modules/settings.js` 中添加开关：

```javascript
<div class="setting-item">
  <div class="setting-info">
    <div class="setting-name">5G-A Optimization</div>
    <div class="setting-desc">Optimize for 5G-A networks (edge computing, low latency)</div>
  </div>
  <label class="toggle">
    <input type="checkbox" data-setting="5gMode" checked>
    <span class="toggle-slider"></span>
  </label>
</div>
```

### 6. 事件监听

```javascript
window.addEventListener('5gEnabled', (e) => {
  showToast('5G-A优化已启用', 'info');
});

window.addEventListener('5gDisabled', () => {
  showToast('5G-A优化已禁用', 'info');
});
```

## 配置选项

### FiveGIntegration

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `edgeEndpoints` | array | [] | 边缘计算节点列表 |
| `autoDetect` | boolean | true | 自动检测5G网络 |
| `autoEnable` | boolean | true | 自动启用优化 |
| `debug` | boolean | false | 调试日志 |

## 事件

- `5gEnabled`: 5G优化已启用
- `5gDisabled`: 5G优化已禁用

## 测试

```javascript
const runner = new FiveGTestRunner();
await runner.runAllTests();
```

## 调试

### 控制台访问

```javascript
// 查看5G集成状态
window.fiveGIntegration.getStatus();

// 手动启用/禁用
window.fiveGIntegration.enable();
window.fiveGIntegration.disable();

// 优化消息发送
window.fiveGIntegration.optimizeMessageSend('test', 'high');

// 获取自适应码率
window.fiveGIntegration.getAdaptiveBitrate();
```

## 故障排除

### 模块未加载

检查浏览器控制台是否有 404 错误，确认文件路径正确。

### 5G检测失败

Network Information API 可能不被所有浏览器支持，模块会自动回退到普通模式。

## 版本历史

- v1.0.0 (2026-05-13): 初始版本

## 参考

- [五网络融合战略](../../FIBEMATE_五网络融合战略.md)
- [卫星网络适配](../satellite/satellite-README.md)
- [量子城域网](../quantum/quantum-README.md)
