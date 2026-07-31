
// 真实 Tauri invoke（打包后 window.__TAURI__ 存在）；浏览器/独立模式回退到 mock
const taCore = (typeof window !== 'undefined' && window.__TAURI__ && window.__TAURI__.core)
  ? window.__TAURI__.core : null;
const taInvoke = taCore ? taCore.invoke.bind(taCore) : null;

function showStatus(msg, type) {
  const bar = document.getElementById('statusBar');
  if (bar) bar.innerHTML = `<div class="status ${type}">${msg}</div>`;
}

async function mockInvoke(cmd, args) {
  if (cmd === 'calc_planet_hexagram') {
    const ts = args.timestampSecs;
    const dt = new Date(ts * 1000);
    const hour = dt.getHours();
    const day = dt.getDate();
    const month = dt.getMonth() + 1;
    const bits = [];
    for (let i = 0; i < 21; i++) {
      const mix = (ts + i * 7 + (month << (i % 4)) + (day << (i % 3))) ^ (hour << (i % 5));
      bits.push(mix & 1);
    }
    const hexagrams = bits.slice(0, 18).reduce((acc, b, i) => {
      if (i % 3 === 0) acc.push('');
      acc[acc.length - 1] = (acc[acc.length - 1] << 1) | b;
      return acc;
    }, []).map(v => ['☰','☱','☲','☳','☴','☵','☶','☷'][v & 7] || '?');
    const hexString = bits.map(b => b.toString(16)).join('').slice(0, 6);
    return { bits, hexagrams, hex_string: hexString };
  }
  if (cmd === 'get_tier_info') {
    const tiers = {
      '坎水': { name: '坎水级·艮渊', symbol: '☵', planet_count: 3, has_ratchet: false, has_obfuscation: false, has_mimicry: false, padding_max: 64 },
      '巽风': { name: '巽风级·巽翎', symbol: '☴', planet_count: 5, has_ratchet: true, has_obfuscation: true, has_mimicry: false, padding_max: 128 },
      '离火': { name: '离火级·离曜', symbol: '☲', planet_count: 7, has_ratchet: true, has_obfuscation: true, has_mimicry: true, padding_max: 256 },
      '乾天': { name: '乾天级·乾极', symbol: '☰', planet_count: 8, has_ratchet: true, has_obfuscation: true, has_mimicry: true, padding_max: 512 },
    };
    return tiers[args.tierName] || tiers['坎水'];
  }
  if (cmd === 'init_encryption' || cmd === 'create_compass') {
    return (args.tierName || '') + ' 已就绪（三才秘钥合成完毕）';
  }
  if (cmd === 'generate_keypair') {
    return 'a'.repeat(64);
  }
  if (cmd === 'establish_session' || cmd === 'establish_session_self') {
    return '已与对端/模拟对端建立会话，共享密钥已注入';
  }
  if (cmd === 'encrypt_message') {
    return { packet: 'deadbeef'.repeat(20), header_pk_preview: 'deadbeef', msg_num: 0 };
  }
  if (cmd === 'decrypt_message') {
    return { plaintext: 'Mock decrypted message', from_pk_preview: 'deadbeef', msg_num: 0 };
  }
  if (cmd === 'self_test_message') {
    return 'Mock: 自测通过';
  }
  throw new Error('Unknown command: ' + cmd);
}

async function invoke(cmd, args) {
  if (taInvoke) return await taInvoke(cmd, args);
  return mockInvoke(cmd, args);
}

// SHA-256 填充
async function sha256Hex(str) {
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) h = ((h ^ str.charCodeAt(i)) * 0x01000193) >>> 0;
    return h.toString(16).padStart(8, '0').repeat(8).slice(0, 64);
  }
}

// 状态管理
let selectedTier = null;

function selectTier(el) {
  document.querySelectorAll('.tier-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
  selectedTier = el.dataset.tier;
  const btn = document.getElementById('initBtn');
  if (btn) btn.disabled = !selectedTier;
  showStatus('已选择等级: ' + selectedTier, 'info');
}

// 行星本卦计算
async function calcHexagram() {
  const timeEl = document.getElementById('observationTime');
  const ts = Math.floor(new Date(timeEl.value).getTime() / 1000);
  if (!ts || isNaN(ts)) { showStatus('请先选择观测时间', 'error'); return; }
  try {
    const result = await invoke('calc_planet_hexagram', { timestampSecs: ts });
    let html = '<div class="hexagrams">';
    for (const h of result.hexagrams) html += `<div class="hexagram">${h}</div>`;
    html += '</div>';
    html += '<div class="result"><strong>21爻二进制:</strong> ' + result.bits.join('') + '<br>';
    html += '<strong>十六进制:</strong> ' + result.hex_string + '</div>';
    document.getElementById('hexagramResult').innerHTML = html;
  } catch (e) {
    showStatus('计算失败: ' + e, 'error');
  }
}

// 初始化
async function initEncryption() {
  if (!selectedTier) { showStatus('请先选择安全等级', 'error'); return; }
  const timeEl = document.getElementById('observationTime');
  const ts = Math.floor(new Date(timeEl.value).getTime() / 1000);
  const lat = parseFloat(document.getElementById('lat').value);
  const lon = parseFloat(document.getElementById('lon').value);
  const eventDesc = document.getElementById('eventDesc').value || '';
  const personalHex = document.getElementById('personalHex').value || '';
  const hashHex = await sha256Hex(eventDesc);
  try {
    const result = await invoke('init_encryption', {
      tierName: selectedTier,
      timestampSecs: ts,
      lat: lat,
      lon: lon,
      eventHash: '0x' + hashHex,
      personalHex: personalHex
    });
    showStatus('✓ ' + result, 'success');
    document.getElementById('initResult').innerHTML =
      '<div class="result">' + result + '<br><br>三才秘钥已合成，等待共享密钥注入...</div>';
  } catch (e) {
    showStatus('初始化失败: ' + e, 'error');
  }
}

// 密钥交换
async function generateKeypair() {
  try {
    const pub = await invoke('generate_keypair', {});
    document.getElementById('myPubKey').value = pub;
    showStatus('✓ 密钥对已生成，公钥已显示', 'success');
  } catch (e) {
    showStatus('生成密钥对失败: ' + e, 'error');
  }
}

async function establishSession() {
  const peer = (document.getElementById('peerPubKey').value || '').trim();
  if (!peer) { showStatus('请先粘贴对方公钥', 'error'); return; }
  const role = document.getElementById('roleSelect') ? document.getElementById('roleSelect').value : 'initiator';
  try {
    const r = await invoke('establish_session', { peerPublicHex: peer, role: role });
    showStatus('✓ ' + r, 'success');
    document.getElementById('sessionResult').innerHTML = '<div class="result">' + r + '</div>';
  } catch (e) {
    showStatus('建立会话失败: ' + e, 'error');
  }
}

async function establishSessionSelf() {
  try {
    const r = await invoke('establish_session_self', {});
    showStatus('✓ ' + r, 'success');
    document.getElementById('sessionResult').innerHTML = '<div class="result">' + r + '<br><br>共享密钥已注入，现在可以加解密了。</div>';
  } catch (e) {
    showStatus('自测失败: ' + e, 'error');
  }
}

// 消息加解密
async function encryptMessage() {
  const pt = document.getElementById('msgInput').value;
  if (!pt) { showStatus('请输入要加密的消息', 'error'); return; }
  try {
    const r = await invoke('encrypt_message', { plaintext: pt });
    document.getElementById('cipherOut').value = r.packet;
    showStatus('✓ 加密成功（消息序号: ' + r.msg_num + '，发送方公钥: ' + r.header_pk_preview + '...）', 'success');
    document.getElementById('msgResult').innerHTML = '<div class="result">加密完成，密文已生成，可将上方 hex 密文复制发送给对端。</div>';
  } catch (e) {
    showStatus('加密失败: ' + e, 'error');
    document.getElementById('msgResult').innerHTML = '<div class="result" style="color:var(--warning);">请先建立会话（点击「建立会话」或「自测」）后再试。</div>';
  }
}

async function decryptMessage() {
  const ct = (document.getElementById('cipherIn').value || '').trim();
  if (!ct) { showStatus('请粘贴要解密的密文（hex）', 'error'); return; }
  try {
    const r = await invoke('decrypt_message', { packetHex: ct });
    document.getElementById('plainOut').value = r.plaintext;
    showStatus('✓ 解密成功（来自: ' + r.from_pk_preview + '...，序号: ' + r.msg_num + '）', 'success');
    document.getElementById('msgResult').innerHTML = '<div class="result" style="color:var(--success);">解密成功！原文: <strong>' + r.plaintext + '</strong></div>';
  } catch (e) {
    showStatus('解密失败: ' + e, 'error');
    document.getElementById('plainOut').value = '';
    document.getElementById('msgResult').innerHTML = '<div class="result" style="color:var(--warning);">解密失败，请确认：1) 双方已建立会话 2) 双方角色正确（发起方/响应方） 3) 密文完整无误。</div>';
  }
}

async function selfTestMessage() {
  try {
    const r = await invoke('self_test_message', {});
    showStatus(r, r.includes('通过') ? 'success' : 'error');
    document.getElementById('msgResult').innerHTML = '<div class="result" style="font-size:0.9rem;">' + r + '</div>';
  } catch (e) {
    showStatus('自测失败: ' + e, 'error');
  }
}

// 事件绑定
const timeEl = document.getElementById('observationTime');
if (timeEl) timeEl.value = new Date().toISOString().slice(0, 16);
document.querySelectorAll('.tier-card').forEach(el => el.addEventListener('click', () => selectTier(el)));

const calcBtn = document.getElementById('calcBtn');
if (calcBtn) calcBtn.addEventListener('click', calcHexagram);

const initBtn = document.getElementById('initBtn');
if (initBtn) initBtn.addEventListener('click', initEncryption);

const genKeyBtn = document.getElementById('genKeyBtn');
if (genKeyBtn) genKeyBtn.addEventListener('click', generateKeypair);

const sessionBtn = document.getElementById('sessionBtn');
if (sessionBtn) sessionBtn.addEventListener('click', establishSession);

const selfTestBtn = document.getElementById('selfTestBtn');
if (selfTestBtn) selfTestBtn.addEventListener('click', establishSessionSelf);

const encryptBtn = document.getElementById('encryptBtn');
if (encryptBtn) encryptBtn.addEventListener('click', encryptMessage);

const decryptBtn = document.getElementById('decryptBtn');
if (decryptBtn) decryptBtn.addEventListener('click', decryptMessage);

const selfTestMsgBtn = document.getElementById('selfTestMsgBtn');
if (selfTestMsgBtn) selfTestMsgBtn.addEventListener('click', selfTestMessage);
