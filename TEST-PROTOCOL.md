# FIBEMATE E2EE 测试协议（TEST-PROTOCOL）

> 目标：让每次 E2EE 调试的**起点完全一致**。这场排查拖久的根因不是某个 bug，
> 而是**测试环境每次都不一样**（旧 exe / 同账号 / 旧代码 / session 残留）。
> 本协议把"可控环境"写死 —— 照做即可 10 分钟内复现已知好状态。

---

## 一、测试前必做（缺一不可）

| # | 检查项 | 期望 | 怎么查 |
|---|--------|------|--------|
| 1 | 进程 | 只有 `fibemate.exe` × 2，**禁止** `FIBEMATE-v3*` | `.\scripts\preflight.ps1` |
| 2 | dev 服务器 | `:1430` 与 `:1431` 都服务修复版 | preflight 脚本 [2] |
| 3 | 窗口来源 | 两端 `location.href` 分别 = `http://127.0.0.1:1430/main.html` / `:1431/main.html` | Console 预检 |
| 4 | 账号 | 两端 `fk_uid` **不同** | Console 预检 |
| 5 | 对话 | 两端 `STATE.currentPeerId` **互相指向对方** | Console 预检 |
| 6 | 会话状态 | 两端 rust 会话键数 = 0（清过 session） | Console 预检 |
| 7 | 代码版本 | 两端 `hybrid fix: true` + `protocol guard: true` | Console 预检 |

**任意一项不符 → 先停下修好，不要发消息。**

---

## 二、按需执行的两个脚本

### 预检（每个窗口 Console 粘一次）

见 `scripts/preflight.ps1` 输出末尾，或直接：

```js
(() => {
  const uid = localStorage.getItem("fk_uid");
  const map = JSON.parse(localStorage.getItem("fibemate_rust_sessions_" + uid) || "{}");
  console.log("[PREFLIGHT] href:", location.href);
  console.log("[PREFLIGHT] fk_uid:", uid);
  console.log("[PREFLIGHT] peer:", STATE.currentPeerId);
  console.log("[PREFLIGHT] sessions in map:", Object.keys(map));
  console.log("[PREFLIGHT] rust keys:", Object.keys(localStorage).filter(k => k.startsWith("fibemate_rust")).length);
  fetch("modules/websocket.js").then(r => r.text()).then(t => console.log("[PREFLIGHT] hybrid fix:", t.includes("_hybridBundleHex")));
  fetch("tauri-message-crypto-adapter.js").then(r => r.text()).then(t => console.log("[PREFLIGHT] protocol guard:", t.includes("existing.hybrid !== true")));
})();
```

### 重置会话（发首条消息前，两端各跑）

> ⚠️ **必须窄清：只删 `fibemate_rust_sessions_<uid>`，保留 `fibemate_rust_hybrid_<uid>`。**
> 删掉 hybrid 预钥缓存 → 重载时 `ensureHybridPreKey()` 会**重新生成**新 hybrid key，
> 而上传只在 `main.js` init 那次（与生成时序错位）→ **服务器 published bundle 陈旧**
> → 两端协商用不同 key → `AEAD decrypt failed`。
> **2026-10-09 实测教训：宽过滤器 `k.startsWith("fibemate_rust")` 正是下一次失败的制造者。**

```js
(async () => {
  const uid = localStorage.getItem("fk_uid");
  const map = JSON.parse(localStorage.getItem("fibemate_rust_sessions_" + uid) || "{}");
  for (const p of Object.keys(map)) { try { await MessageCryptoV2.deleteSession(p); } catch (e) { console.warn("del fail", p, e.message); } }
  localStorage.removeItem("fibemate_rust_sessions_" + uid);   // ★ 只删 session 映射
  const hyb = JSON.parse(localStorage.getItem("fibemate_rust_hybrid_" + uid) || "{}");
  console.log("[RESET] sessions cleared; hybridKeyId kept:", hyb.keyId || "NONE(!)");
  console.log("[RESET] rust keys left:", Object.keys(localStorage).filter(k => k.startsWith("fibemate_rust")).length);
})();
```

清完 **`Ctrl+Shift+R` 硬刷新**（不是 F5）。

### Bundle 重传 / 一致性自查（重传脚本，两端各跑）

> 何时跑：`server hybridKeyId ≠ local keyId`（见 §六），或重置后仍 `AEAD decrypt failed`。

```js
(async () => {
  const API = "https://fibemate.net/api";
  const uid = localStorage.getItem("fk_uid");
  const token = localStorage.getItem("fk_token");
  const b = await MessageCryptoV2.getMyPreKeyBundle();
  console.log("local _hybridKeyId:", b._hybridKeyId, "| bundleHex len:", (b._hybridBundleHex || "").length);
  const r = await fetch(`${API}/auth/update-keys`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
    body: JSON.stringify({
      publicKey: b.identityKey,
      identitySigningKey: b.identitySigningKey || null,
      signedPreKey: b.signedPreKey || b.identityKey,
      signedPreKeySignature: b.signedPreKeySignature || null,
      signedPrekey: b.signedPreKey || b.identityKey,
      prekeySignature: b.signedPreKeySignature || "",
      hybridKeyId: b._hybridKeyId || null,
      hybridBundleHex: b._hybridBundleHex || null,
      hybridMode: b._hybridMode || null
    })
  });
  console.log("upload:", r.status);
  const k = await (await fetch(`${API}/users/${uid}/keys`, { headers: { Authorization: "Bearer " + token } })).json();
  console.log("server:", k.hybridKeyId, "| local:", b._hybridKeyId, "| match:", k.hybridKeyId === b._hybridKeyId ? "OK ✅" : "MISMATCH ❌");
})();
```

**判据：两端 `match: OK ✅`。**

---

## 三、测试流程（严格单发起）

1. A 重置 → 硬刷新 → 预检 7 项全绿
2. B 重置 → 硬刷新 → 预检 7 项全绿
3. **只有 A 发第一条 `test-1`** —— 不要同时发
4. 等 B 出 `E2EE message decrypted`
5. B 回 `test-2`，看 A 出 `E2EE message decrypted`

---

## 四、成功判据（双向都要出现）

| 侧 | 关键日志 |
|----|----------|
| 发送端 | `[Send v7] Using hybrid PQ handshake` → `message_sent` |
| 接收端 | `[DR Adapter] Hybrid PQ session accept …` → `E2EE message decrypted` |
| 发送端 | `[WS v9] Session confirmed from hybrid_accept_rust` |
| 反向 | `E2EE message decrypted` |

---

## 五、服务端侧证据（判"投递 vs 解密"）

发一条后看服务端：

```
ssh fibemate "pm2 logs fibemate --lines 200 --nostream | grep -E 'SEND-LEN|ROUTE|MSG-FLOW'"
```

- `[SEND-LEN] to=<对端>` 出现 → **投递成功**，问题在接收端解密/渲染
- `[ROUTE] OFFLINE` 出现 → 接收端 socket 未注册
- **配送按 `to`(userId)，与 conversationId 无关**（`case 'message'` 里 `sendToUser(to,…)`）

---

## 六、常见坑

| 症状 | 根因 | 修法 |
|------|------|------|
| 改代码不生效 | `main.html` 普通 `<script>`，无 HMR | `Ctrl+Shift+R` 硬刷新 |
| 两个窗口同账号 | 共用 localStorage | 不同 Tauri identifier（`com.fibemate.app` / `com.fibemate.liuxiu`）|
| `Protocol mismatch` 反复 | 旧 session 残留 | 重置脚本 + 硬刷新 |
| `tauri.localhost` 出现 | 旧打包 exe 又启动 | `Stop-Process` 杀 / 重启 |
| `AEAD decrypt failed` | 协议错配（classical vs hybrid） | 看 `Protocol mismatch` 日志 |
| 清完 session 仍 `AEAD failed`；同协议 hybrid 却解不开 | **服务器 published bundle 陈旧**（本地 `hybridKeyId` ≠ 服务器） | 跑「Bundle 重传」脚本 → `match: OK ✅` |
| 接收端只出 `Reusing existing hybrid session`（无 `accept`） | session 没清干净——复用守卫（`existing.hybrid===true` + `sessionExists`）复用旧 session、丢弃新 init | 窄清 session（`deleteSession` 必跑，删 Rust 侧 → `sessionExists=false`） |
| 界面"收不到"但服务端有 `SEND-LEN` | 接收端解密失败，非投递 | 查接收端 `new_message` → `decrypted` |

---

## 七、双实例启动（参考）

| 实例 | 标识 | 端口 | 启动 |
|------|------|------|------|
| A | `com.fibemate.app` | 1430 | `npm run dev` |
| B | `com.fibemate.liuxiu` | 1431 | `$env:CARGO_TARGET_DIR="src-tauri\target-liuxiu"; npx tauri dev -c src-tauri\configs\tauri.liuxiu.dev.json` |

- 两个 dev server 端口不同（1430/1431）；Tauri dev 在 1430 被占时自动 +1。
- 两者加载**同一份**磁盘 `src/`（dev 不内嵌资源），所以改代码后**硬刷新即可**。
- 旧打包 exe 的 origin 是 `tauri.localhost` 且**资源内嵌**（永远是旧的），必须杀掉。


## 八、语音短消息「对面收不到」根因（2026-10-09 修复）

**症状**：语音能发出（发送端有本地预览气泡），对端**什么都不显示**（严重时连文字也收不到）。

**两层原因**：
1. `src/modules/websocket.js` 的 `new_message` 处理里**文字解密分支先跑**，把语音帧当文字 `Crypto.decrypt` 一次（消耗一个 DR 棘轮步）；随后 `msg.messageType==='voice'` 分支调 `VoiceMessage.handleIncomingVoiceMessage(msg)`，内部**第二次**解密同一帧 → Rust DR 返回 `MESSAGE_DROP` → `[DR Adapter] Silent-drop duplicate` → 返回 null → `if (!audioData) return` 静默返回。
   **修**：在文字解密分支**之前**先分派语音（websocket.js:121-127）：
   ```js
   if (msg.messageType === 'voice' && typeof VoiceMessage !== 'undefined') {
     VoiceMessage.handleIncomingVoiceMessage(msg);
     return;
   }
   ```
2. **两端 DR 棘轮错位**：一端离线积压（offline_messages）把接收链推前 → 连文字都报 `NULL(dup)`（`MESSAGE_DROP`）。
   **修**：窄清两端 session（见上「重置」），重载后 msgNum 从 0 重新计数即对齐。

**验证判据**：接收端 CDP 埋点 `[DEC]` 应显示 `OK:<len>`（**非** `NULL(dup)`）；消息列表出现 `{cls:"message received", voice:true, txt:"0:0X"}`。

**注意**：音频以 JSON 数字数组序列化（~4x 膨胀），2.4s≈12KB → 密文 88–98KB > 64KB，依赖 §七 的 WsPadding 扩展头。TODO：改 base64 可省 4x。
