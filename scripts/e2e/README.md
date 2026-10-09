# FIBEMATE E2E（CDP 驱动）

直接通过 Chrome DevTools Protocol 驱动**两个正在运行的 dev 实例**——无需人工点按。
把 WebView2 的远程调试端口开出来即可。

## 前置

| 实例 | identifier | dev 端口 | CDP 端口 | 账号 |
|---|---|---|---|---|
| A | `com.fibemate.app` | 1430 | 9222 | 009 `eb980664…` |
| B | `com.fibemate.liuxiu` | 1431 | 9223 | 007 `10ae1ef0…` |

启动（PowerShell，两个终端）：

```powershell
# A
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=9222"
npx tauri dev --no-watch --port 1430

# B
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=9223"
$env:CARGO_TARGET_DIR="src-tauri\target-liuxiu"
npx tauri dev --no-watch --port 1431 -c src-tauri\configs\tauri.liuxiu.dev.json
```

## 运行

```powershell
npm run e2e
```

- 结果：stdout 逐条 `PASS | <项> | <详情>` / `FAIL | …`
- 截图：`scripts/e2e/shots/`（已 gitignore）

## 已知：时序误报（待修）

`location.reload()` 后 app 需要 **~15s** 完成初始化才能设 `STATE.currentPeerId`。
立即设置会被初始化覆盖 → 被 `msg.from === STATE.currentPeerId` 守卫挡掉 → 表现为"收不到"的**假 FAIL**。
修时序属后续单独 commit（见 git log）；本目录为**归档版**，先把"能跑"钉住。

## 说明

- **Windows PowerShell 控制台默认 GBK**：stdout 里的中文标签会显示成乱码（文件与输出字节均为 UTF-8）。跑前 `chcp 65001` 可正常显示。
- 夹具值（uid、conversationId、端口）是本地调试固定值，硬编码在 `run-tests.js`；后续再泛化为环境变量。
- `ev-tap5.js` 是注入的棘轮埋点（记录 `[DEC]`/`messageNum`），供接收端断言使用。
