# FIBEMATE — E2EE 测试前置检查
# 用法（仓库根目录）: powershell -ExecutionPolicy Bypass -File .\scripts\preflight.ps1
# 说明: 标记统一用 ASCII [OK]/[WARN]/[FAIL]，避免 PS 5.1 的 GBK 控制台把 emoji 渲染成乱码。

$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=== FIBEMATE PREFLIGHT ===" -ForegroundColor Cyan

# [1] 进程检查
Write-Host "`n[1] FIBEMATE processes:" -ForegroundColor Yellow
$all = Get-Process | Where-Object { $_.ProcessName -like "*fibemate*" -or $_.ProcessName -like "*FIBEMATE*" }
if ($all) { $all | Format-Table Id, ProcessName, StartTime -AutoSize } else { Write-Host "  (none running)" }

$oldExe = $all | Where-Object { $_.ProcessName -like "*FIBEMATE-v3*" }
if ($oldExe) {
  Write-Host "  [FAIL] old packaged exe running! PIDs: $($oldExe.Id -join ',')" -ForegroundColor Red
  Write-Host "         kill: Stop-Process -Id $($oldExe.Id -join ',') -Force" -ForegroundColor Red
} else {
  Write-Host "  [OK] no old packaged exe" -ForegroundColor Green
}

$dev = @($all | Where-Object { $_.ProcessName -eq 'fibemate' })
if ($dev.Count -eq 2) { Write-Host "  [OK] 2 dev instances running" -ForegroundColor Green }
else { Write-Host "  [WARN] dev instance count = $($dev.Count) (expect 2)" -ForegroundColor Yellow }

# [2] dev server 检查 —— 必须服务「修复版」代码
Write-Host "`n[2] dev servers (serving fixed code?):" -ForegroundColor Yellow
foreach ($p in 1430, 1431) {
  $ok = $false
  try {
    $r = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$p/modules/websocket.js" -TimeoutSec 3
    $ok = ($r.Content -match '_hybridBundleHex')
  } catch { $ok = $false }
  if ($ok) { Write-Host "  [OK] :$p serves hybrid-fixed code" -ForegroundColor Green }
  else { Write-Host "  [WARN] :$p unreachable OR stale (no _hybridBundleHex)" -ForegroundColor Yellow }
}

Write-Host "`n=== Paste this in EACH window's DevTools Console ===" -ForegroundColor Cyan
Write-Host @'
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
'@ -ForegroundColor White
