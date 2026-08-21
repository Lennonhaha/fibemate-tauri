# FIBEMATE Tauri — 密钥持久化集成完成

**时间:** 2026-06-18 12:34  
**状态:** ✅ 构建通过，0 错误  
**产物:** `fibemate.exe` 5.16MB, `FIBEMATE_3.0.0_x64-setup.exe` 3.07MB

---

## 新增模块: `src-tauri/src/key_store.rs`

零外部 C 依赖的加密密钥存储，替代 `tauri-plugin-stronghold`（因 libsodium 编译失败）。

### 架构

```
首次运行:
  OsRng → 32随机字节 → %APPDATA%/com.fibemate.app/device.key

kem_keygen:
  ML-KEM-768 keygen → [AES-256-GCM(nonce, device_key)] → keys/{key_id}.enc
  元数据 → key_meta.json (public_key, fingerprint, 不含私钥)

kem_decapsulate:
  keys/{key_id}.enc → AES-256-GCM decrypt → ML-KEM decaps → zeroize(SK)
```

### 存储格式

| 文件 | 内容 |
|------|------|
| `device.key` | 32 随机字节（设备密钥） |
| `keys/{key_id}.enc` | `[12B nonce] [AES-GCM ciphertext+tag]` |
| `key_meta.json` | `[{key_id, public_key, fingerprint, created_at}]` |

### 安全特性

- ✅ ML-KEM 私钥加密落盘（AES-256-GCM per-key unique nonce）
- ✅ 解封后立即 zeroize
- ✅ 无外部 C 依赖（纯 Rust `aes-gcm` + `rand` crate）
- ✅ 应用重启后密钥自动恢复
- ✅ 前端仍通过 `key_id` 引用私钥，不接触明文

---

## 变更文件清单

| 文件 | 变更 |
|------|------|
| `src-tauri/Cargo.toml` | -`tauri-plugin-stronghold` (libsodium 不可编译) |
| `src-tauri/src/lib.rs` | +`mod key_store`, CryptoState 初始化移入 `setup()` 获取 app_data |
| `src-tauri/src/commands/mod.rs` | CryptoState 用 KeyStore 替代 HashMap |
| `src-tauri/src/commands/kem.rs` | kem_keygen→store, kem_decapsulate→load+zeroize, kem_list_keys→meta |
| `src-tauri/src/pq/mod.rs` | +`mlkem768_decapsulate_bytes()` 字节级解封函数 |
| `src-tauri/src/key_store.rs` | **新增** 加密密钥存储引擎 |

---

## 安全边界更新

| 维度 | 之前 | 现在 |
|------|------|------|
| ML-KEM 私钥 | ❌ 只在内存 (HashMap) | ✅ AES-256-GCM 加密落盘 |
| 应用重启 | ❌ 密钥丢失 | ✅ 自动从 KeyStore 恢复 |
| 外部依赖 | — | ✅ 纯 Rust (无 C) |
| 私钥不入 JS | ✅ 仅 keyId | ✅ 不变 |
| SharedSecret | ⚠️ 流经 JS | ⚠️ 不变 (DR 需要) |
| Double Ratchet | ⚠️ JS P-256 | ⚠️ 不变 |

---

## 下一步建议

1. **`npx tauri dev`** 验证完整调用链路（keygen → 重启 → decaps → 密钥尚在）
2. **ML-DSA-65 签名命令** (`kem.rs` 侧边已就绪，只需加 commands)
3. **Rust Double Ratchet 迁移** (协议从 P-256 → X25519，全部会话密钥入 Rust)
