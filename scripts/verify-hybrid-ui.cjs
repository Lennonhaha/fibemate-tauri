/**
 * Verify hybrid PQ handshake is VISIBLE in the Tauri chat UI.
 *
 * Covers the 3 changes made for PQ session visibility:
 *  1. adapter getSessionStatus() exposes hybrid / pqMode / pq curve
 *  2. chat.js openChat() renders PQ-E2EE status bar for hybrid sessions
 *  3. e2ee-display.js detail panel + status use session-level hybrid proof
 *
 * Run: node verify-hybrid-ui.cjs   (from scripts/)
 */
'use strict';

const path = require('path');
const fs = require('fs');

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS ' + name); }
  else { fail++; console.log('  FAIL ' + name + (extra ? ' — ' + extra : '')); }
}

const adapterSrc = fs.readFileSync(path.resolve(__dirname, '../src/tauri-message-crypto-adapter.js'), 'utf8');
const chatSrc = fs.readFileSync(path.resolve(__dirname, '../src/modules/chat.js'), 'utf8');
const e2eeSrc = fs.readFileSync(path.resolve(__dirname, '../src/modules/e2ee-display.js'), 'utf8');

console.log('== §1 adapter.getSessionStatus exposes hybrid session ==');
const gssStart = adapterSrc.indexOf('async getSessionStatus(peerId)');
const gssEnd = adapterSrc.indexOf('// ═══', gssStart);
const gssBody = adapterSrc.slice(gssStart, gssEnd > gssStart ? gssEnd : gssStart + 1200);
ok('getSessionStatus sets hybrid flag', /hybrid:\s*isHybrid/.test(gssBody));
ok('getSessionStatus sets pqMode', /pqMode:\s*isHybrid \? \(sessionInfo\.pqMode \|\| 'x25519\+mlkem768'\) : null/.test(gssBody));
ok('getSessionStatus sets pq', /pq:\s*isHybrid \? 'ml-kem-768' : null/.test(gssBody));
ok('getSessionStatus hybrid curve label', /curve:\s*isHybrid \? 'X25519 \+ ML-KEM-768' : 'X25519'/.test(gssBody));

console.log('== §2 chat.js openChat renders PQ-E2EE for hybrid sessions ==');
const ocStart = chatSrc.indexOf('async function openChat(userId, name)');
const ocBody = chatSrc.slice(ocStart, ocStart + 2200);
ok('chat.js has isPQ detection', /const isPQ = !!\(status\.hybrid \|\| status\.pqMode\)/.test(ocBody));
ok('chat.js uses pq css class when hybrid', /e2eeBar\.className = isPQ \? 'e2ee-status-bar pq' : 'e2ee-status-bar secure'/.test(ocBody));
ok('chat.js PQ-E2EE label', /e2eeText\.textContent = isPQ \? 'PQ-E2EE' : 'E2EE'/.test(ocBody));
ok('chat.js no NaN msgs (Number() guard)', /const sent = Number\(status\.messagesSent\) \|\| 0/.test(ocBody));
ok('chat.js msgs omitted when zero', /\(sent \+ received\) > 0 \? ` · \$\{sent \+ received\} msgs` : ''/.test(ocBody));
ok('chat.js curve fallback', /`\$\{status\.curve \|\| 'X25519'\}\$\{msgs\}`/.test(ocBody));

console.log('== §3 e2ee-display.js session-level PQ proof ==');
ok('updateStatus checks session hybrid first', /securityStatus\?\.hybrid \|\| securityStatus\?\.pqMode \|\| \(PQ && PQ\.isAvailable\?\.\(\)\)/.test(e2eeSrc));
ok('detail panel declares pqActive outside if', /let pqActive = false;/.test(e2eeSrc));
ok('detail panel session-level pqActive', /pqActive = isHybridSession \|\| !!\(PQ && PQ\.isAvailable\?\.\(\)\)/.test(e2eeSrc));
ok('detail Key Exchange shows hybrid', /pqActive \? 'X25519 \+ ML-KEM-768' : 'X3DH \(4-DH\)'/.test(e2eeSrc));
ok('detail ML-KEM layer ACTIVE by session', /pqActive \? 'ACTIVE' : 'INACTIVE'/.test(e2eeSrc));
ok('detail Messages NaN-safe', /\(Number\(protocolInfo\.messagesSent\) \|\| 0\) \+ \(Number\(protocolInfo\.messagesReceived\) \|\| 0\)/.test(e2eeSrc));

console.log('');
console.log('RESULT: ' + pass + ' passed, ' + fail + ' failed');
process.exit(fail > 0 ? 1 : 0);
