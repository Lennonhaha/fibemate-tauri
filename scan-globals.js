// 扫描 main.html 引用的非 module 脚本顶层全局声明，检测重名冲突
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, 'src', 'main.html'), 'utf8');

// 提取所有 script src（排除 type=module）
const scriptRe = /<script\s+([^>]*)>/g;
let m;
const scripts = [];
while ((m = scriptRe.exec(html)) !== null) {
  const attrs = m[1];
  if (/type\s*=\s*["']module["']/.test(attrs)) continue;
  const srcMatch = attrs.match(/src\s*=\s*["']([^"']+)["']/);
  if (!srcMatch) continue;
  scripts.push(srcMatch[1]);
}

console.log('=== 非 module 脚本清单 (' + scripts.length + ') ===');
scripts.forEach(s => console.log('  ' + s));

// 顶层声明正则：const/let/var/function/class，且位于行首（无缩进）
const declRe = /^(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?:=|;|,)/m;
const funcRe = /^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/m;
const classRe = /^class\s+([A-Za-z_$][\w$]*)\s*[{\s]/m;

const globals = {}; // name -> [files]

for (const s of scripts) {
  const full = path.join(__dirname, 'src', s);
  if (!fs.existsSync(full)) { console.log('  [MISSING] ' + s); continue; }
  const code = fs.readFileSync(full, 'utf8');
  const lines = code.split('\n');
  const found = new Set();
  for (const line of lines) {
    let mm;
    if ((mm = line.match(declRe))) found.add(mm[1]);
    else if ((mm = line.match(funcRe))) found.add(mm[1]);
    else if ((mm = line.match(classRe))) found.add(mm[1]);
  }
  for (const name of found) {
    if (!globals[name]) globals[name] = [];
    globals[name].push(s);
  }
}

console.log('\n=== 全局声明冲突（同名出现在多个文件）===');
let conflicts = 0;
for (const [name, files] of Object.entries(globals)) {
  if (files.length > 1) {
    conflicts++;
    console.log('  [' + name + ']');
    files.forEach(f => console.log('      - ' + f));
  }
}
if (conflicts === 0) console.log('  (无冲突)');
console.log('\n总声明数: ' + Object.keys(globals).length + ', 冲突数: ' + conflicts);
