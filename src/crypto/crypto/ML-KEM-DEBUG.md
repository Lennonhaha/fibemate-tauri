# ML-KEM-768 调试总结

## 当前状态
- 修复 v2 仍然失败（0/20 测试通过）
- 根本问题可能不在破坏性调用，而在 NTT 实现本身

## 怀疑的问题

### 1. NTT 矩阵定义错误
当前实现使用 DFT 矩阵定义：
```javascript
NTT_MATRIX[i][j] = omega^(i*j mod 512)
```

但 ML-KEM 使用的是**负循环卷积 NTT**，不是标准 DFT。正确的 NTT 应该使用：
- 基向量：omega^(2*i+1) 对于 i=0..127（128个基向量）
- 或者是 in-place Cooley-Tukey 算法

### 2. polyMul 与 NTT 不兼容
当前 `polyMul` 实现时域负循环卷积，但 NTT 实现是标准 DFT。这两者不兼容：
- 如果 NTT 是标准 DFT，则 NTT 域的乘法是点乘（point-wise）
- 如果 NTT 是负循环卷积 NTT，则 NTT 域的乘法是点乘，但基向量不同

### 3. 正确的 ML-KEM NTT
ML-KEM 使用 Kyber 的 NTT，其特点是：
- 将 256 点 NTT 分解为 128 点基向量
- 每个基向量处理 2 个系数
- NTT 公式：f_hat[i] = f[2*i] + omega^(2*br(i)+1) * f[2*i+1]
  其中 br(i) 是 bit-reversal

## 建议的修复

### 方案 A：完全重写 NTT
使用正确的 Kyber NTT 实现（in-place，128 点基向量）。

### 方案 B：使用时域实现（不用 NTT）
完全放弃 NTT，所有乘法使用时域 `polyMul`。
这会导致性能下降，但正确性更容易保证。

### 方案 C：使用已知正确的实现
参考官方 Kyber 实现或已验证的 JavaScript 实现。

## 下一步
1. 验证 NTT 矩阵定义（打开 verify-ntt.html）
2. 根据验证结果决定修复方案
3. 实施修复并重新测试
