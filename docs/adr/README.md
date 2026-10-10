# Architecture Decision Records (ADR)

这里记录**已经生效**的架构决策：每条记「背景 → 决策 → 后果」。目的是让后来者（包括未来的自己）知道**为什么**是这样，而不只是**是什么**。

| # | 决策 | 状态 |
|---|---|---|
| [001](001-tauri-over-electron.md) | 桌面端用 Tauri 而非 Electron | Accepted |
| [002](002-hybrid-pq-key-agreement.md) | 握手用 X25519 + ML-KEM-768 混合 | Accepted |
| [003](003-double-ratchet.md) | 棘轮放在 Rust 侧，会话加密落盘 | Accepted |

新增一份：复制任一模板，编号递增，状态用 `Proposed` / `Accepted` / `Superseded`。
