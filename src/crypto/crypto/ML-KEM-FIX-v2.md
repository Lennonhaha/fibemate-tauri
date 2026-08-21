# ML-KEM-768 修复 v2

## 问题分析

修复 v1（深拷贝 matVecMulTimeDomain 和 vecAccTimeDomain 输入）未解决问题。

### 新发现的问题

在 `generateKeypair` 中：
1. `s_ntt` 被创建并 NTT 转换
2. `matVecMulTimeDomain(A, s_ntt, KYBER_K)` —— 修改了 `s_ntt`（在 v1 修复前）
3. `s_ntt` 被编码到 secretKey 中

这意味着 secretKey 中的 `s` 已经被破坏！

## 修复 v2

在 `generateKeypair` 中，调用 `matVecMulTimeDomain` 前深拷贝 `s_ntt`：

```javascript
const s_ntt = s_td.map(p => { const c = new Int16Array(p); ntt(c); return c; });
// Deep copy s_ntt for matVecMulTimeDomain to prevent modification
const s_ntt_copy = s_ntt.map(p => new Int16Array(Array.from(p)));
const t_ntt = matVecMulTimeDomain(A, s_ntt_copy, KYBER_K);
```

## 修改的文件

- `ml-kem-768.js`：`generateKeypair` 函数

## 测试文件

- `test-ml-kem-v2.html`：浏览器测试
- `test-ml-kem-node-v2.js`：Node.js 测试（被限制无法运行）

## 待验证

等待用户在浏览器中打开 `test-ml-kem-v2.html` 验证修复是否成功。
