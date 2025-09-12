// crypto_list web SPA - all encryption happens client-side only.
// File container format: MAGIC ("CLST1") + 16-byte salt + FERNET_TOKEN (ascii base64url string bytes).
// Fernet details (compatible with python cryptography):
// - PBKDF2-HMAC-SHA256(password, salt, 200_000) -> 32 bytes
// - Split into signing key (first 16 bytes) and encryption key (last 16 bytes)
// - Encrypt payload JSON with AES-CBC (PKCS7) using 16-byte IV
// - Compute HMAC-SHA256 over (version||timestamp||IV||ciphertext)
// - Token = base64url(version||timestamp||IV||ciphertext||HMAC)

const MAGIC = new TextEncoder().encode("CLST1");
const SALT_LEN = 16;
const ITERATIONS = 200000;
const LEGACY_ITERATIONS = 100000;
const VERSION_BYTE = 0x80;

// State
let entries = {}; // key->value
let filteredKeys = [];
let currentFileName = null;
let currentPassword = null;
let currentSalt = null; // Uint8Array when available
let dirty = false;
let fileHandle = null; // File System Access API handle (when granted)

const statusEl = document.getElementById('status');
const listEl = document.getElementById('list');
const searchEl = document.getElementById('search');
const keyEl = document.getElementById('key');
const valueEl = document.getElementById('value');

function setStatus(text) { statusEl.textContent = text; }

function refreshList() {
  const needle = (searchEl.value || '').toLowerCase().trim();
  const keys = Object.keys(entries).sort().filter(k => !needle || k.toLowerCase().includes(needle));
  filteredKeys = keys;
  listEl.innerHTML = '';
  for (const k of keys) {
    const li = document.createElement('li');
    li.textContent = k;
    li.addEventListener('click', () => loadEntryToForm(k));
    listEl.appendChild(li);
  }
}

function loadEntryToForm(key) {
  keyEl.value = key || '';
  valueEl.value = key && entries[key] ? entries[key] : '';
  dirty = false;
}

function askPassword(msg = 'Enter password') {
  return new Promise((resolve) => {
    const backdrop = document.getElementById('modal-backdrop');
    const modal = document.getElementById('password-modal');
    const title = document.getElementById('password-modal-title');
    const text = document.getElementById('password-modal-msg');
    const input = document.getElementById('password-modal-input');
    const btnOk = document.getElementById('password-modal-ok');
    const btnCancel = document.getElementById('password-modal-cancel');

    function cleanup(result) {
      btnOk.removeEventListener('click', onOk);
      btnCancel.removeEventListener('click', onCancel);
      input.removeEventListener('keydown', onKey);
      window.removeEventListener('keydown', onGlobalKey);
      input.value = '';
      modal.style.display = 'none';
      backdrop.style.display = 'none';
      resolve(result);
    }
    function onOk() {
      const v = input.value;
      if (!v) { cleanup(null); return; }
      cleanup(v);
    }
    function onCancel() { cleanup(null); }
    function onKey(e) { if (e.key === 'Enter') onOk(); if (e.key === 'Escape') onCancel(); }
    function onGlobalKey(e) { if (e.key === 'Escape') onCancel(); }

    title.textContent = 'Password';
    text.textContent = msg;
    backdrop.style.display = 'block';
    modal.style.display = 'grid';
    btnOk.addEventListener('click', onOk);
    btnCancel.addEventListener('click', onCancel);
    input.addEventListener('keydown', onKey);
    window.addEventListener('keydown', onGlobalKey);
    setTimeout(() => input.focus(), 0);
  });
}

async function pbkdf2_32bytes(password, salt, iterations = ITERATIONS) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, baseKey, 256);
  return new Uint8Array(bits); // 32 bytes
}

function splitFernetKey(raw32) {
  // First 16 bytes: signing key; Last 16 bytes: encryption key
  return { signKey: raw32.slice(0, 16), encKey: raw32.slice(16, 32) };
}

async function importAesCbcKey(raw16) {
  return crypto.subtle.importKey('raw', raw16, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
}

async function importHmacKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

function genIv16() {
  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv);
  return iv;
}

function u64be(n) {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  dv.setBigUint64(0, BigInt(n), false);
  return b;
}

function concat(...arrs) {
  let total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function base64UrlEncode(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
  let b64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return b64;
}

function base64UrlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
  return out;
}

function asciiToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToAscii(bytes) {
  return new TextDecoder('utf-8').decode(bytes);
}

async function hmacSha256(keyBytes, data) {
  const key = await importHmacKey(keyBytes);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return new Uint8Array(sig);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
  return diff === 0;
}

async function fernetEncrypt(payloadBytes, raw32) {
  const { signKey, encKey } = splitFernetKey(raw32);
  const aesKey = await importAesCbcKey(encKey);
  const iv = genIv16();
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, payloadBytes));
  const ver = new Uint8Array([VERSION_BYTE]);
  const ts = u64be(Math.floor(Date.now() / 1000));
  const msg = concat(ver, ts, iv, ct);
  const mac = await hmacSha256(signKey, msg);
  const tok = concat(msg, mac);
  return base64UrlEncode(tok);
}

async function fernetDecrypt(tokenB64, raw32) {
  const tok = base64UrlDecode(tokenB64);
  if (tok.length < 1 + 8 + 16 + 16 + 32) throw new Error('Token too short');
  const mac = tok.slice(tok.length - 32);
  const msg = tok.slice(0, tok.length - 32);
  const ver = msg[0];
  if (ver !== VERSION_BYTE) throw new Error('Unsupported Fernet version');
  const ts = msg.slice(1, 9); // unused
  const iv = msg.slice(9, 25);
  const ct = msg.slice(25);
  const { signKey, encKey } = splitFernetKey(raw32);
  const macCalc = await hmacSha256(signKey, msg);
  if (!constantTimeEqual(mac, macCalc)) throw new Error('Invalid token (HMAC)');
  const aesKey = await importAesCbcKey(encKey);
  const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ct);
  return new Uint8Array(pt);
}

function generateSalt() {
  const salt = new Uint8Array(SALT_LEN);
  crypto.getRandomValues(salt);
  return salt;
}

async function encryptEntries(obj, password, salt) {
  const data = new TextEncoder().encode(JSON.stringify({ version: 1, entries: obj }));
  const raw32 = await pbkdf2_32bytes(password, salt);
  const tokenB64 = await fernetEncrypt(data, raw32);
  return asciiToBytes(tokenB64); // token bytes are ascii base64url
}

async function decryptEntries(containerBytes, password) {
  const data = new Uint8Array(containerBytes);
  // Detect new format by MAGIC header
  let isNew = true;
  for (let i = 0; i < MAGIC.length; i++) {
    if (data[i] !== MAGIC[i]) { isNew = false; break; }
  }
  if (isNew) {
    const salt = data.slice(MAGIC.length, MAGIC.length + SALT_LEN);
    const tokenAsciiBytes = data.slice(MAGIC.length + SALT_LEN);
    const tokenB64 = bytesToAscii(tokenAsciiBytes);
    const raw32 = await pbkdf2_32bytes(password, salt, ITERATIONS);
    const pt = await fernetDecrypt(tokenB64, raw32);
    const text = new TextDecoder().decode(pt);
    const obj = JSON.parse(text);
    return { entries: obj.entries || {}, salt, legacy: false };
  }
  // Legacy: whole file is Fernet token (base64url ascii). Ask for external .salt
  const tokenB64Legacy = bytesToAscii(data).trim();
  const saltLegacy = await askSaltFile();
  const raw32Legacy = await pbkdf2_32bytes(password, saltLegacy, LEGACY_ITERATIONS);
  const ptLegacy = await fernetDecrypt(tokenB64Legacy, raw32Legacy);
  // Try JSON first (some users might have JSON payloads)
  try {
    const text = new TextDecoder().decode(ptLegacy);
    const obj = JSON.parse(text);
    return { entries: obj.entries || obj || {}, salt: null, legacy: true };
  } catch (_) {
    const obj = unpickleToObject(ptLegacy);
    if (typeof obj !== 'object' || obj === null) throw new Error('Legacy file content invalid');
    const out = {};
    for (const [k, v] of Object.entries(obj)) out[String(k)] = String(v);
    return { entries: out, salt: null, legacy: true };
  }
}

async function serializeAndDownload() {
  if (!currentPassword) {
    const pw = await askPassword('Set a password');
    if (!pw) return;
    currentPassword = pw;
  }
  let salt = currentSalt || generateSalt();
  const token = await encryptEntries(entries, currentPassword, salt);
  const out = new Uint8Array(MAGIC.length + salt.length + token.length);
  out.set(MAGIC, 0);
  out.set(salt, MAGIC.length);
  out.set(token, MAGIC.length + salt.length);
  // Try saving via File System Access API first
  const saved = await saveBytesToDisk(out);
  if (!saved) {
    // Fallback to classic download
    const blob = new Blob([out], { type: 'application/octet-stream' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = currentFileName || 'crypto_list.crypto_list';
    a.click();
    setStatus('Saved');
  }
}

function newFile() {
  if (dirty && !confirm('Discard unsaved changes?')) return;
  entries = {};
  currentFileName = null;
  currentPassword = null;
  currentSalt = null;
  loadEntryToForm(null);
  refreshList();
  setStatus('New list (unsaved)');
}

async function openFile() {
  if (dirty && !confirm('Discard unsaved changes?')) return;
  const input = document.getElementById('file-input');
  input.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (file.name.toLowerCase().endsWith('.salt')) {
      alert('This looks like a legacy .salt file. Please select the encrypted list file (*.crypto_list).');
      input.value = '';
      return;
    }
    (async () => {
      // Peek header to determine format before any further prompts
      const header = new Uint8Array(await file.slice(0, MAGIC.length).arrayBuffer());
      const isNew = isNewFormat(header);
      const pw = await askPassword('Enter password');
      if (!pw) { input.value = ''; return; }
      try {
        const buf = await file.arrayBuffer();
        let result;
        if (isNew) {
          result = await decryptEntries(buf, pw); // new format path
        } else {
          // Ask for salt via a modal with a user-clicked button to open the picker
          const salt = await askSaltFile().catch(() => null);
          if (!salt) { alert('Salt required for legacy file'); input.value = ''; return; }
          result = await decryptLegacy(new Uint8Array(buf), pw, salt);
        }
        entries = result.entries || {};
        currentSalt = result.salt;
        currentPassword = pw;
        currentFileName = file.name;
        loadEntryToForm(null);
        refreshList();
        setStatus(`${file.name} (${result.legacy ? 'LEGACY' : 'v1'})`);
      } catch (err) {
        console.error(err);
        alert('Failed to open: ' + err);
      } finally {
        input.value = '';
      }
    })();
  };
  input.click();
}

function addEntry() {
  const k = window.prompt('Key');
  if (!k) return;
  if (entries[k]) { alert('Key already exists'); return; }
  entries[k] = '';
  refreshList();
  loadEntryToForm(k);
}

function deleteEntry() {
  const k = keyEl.value.trim();
  if (!k) return;
  if (!confirm(`Delete entry '${k}'?`)) return;
  delete entries[k];
  refreshList();
  loadEntryToForm(null);
}

function copyValue() {
  const k = keyEl.value.trim();
  if (!k) return;
  const v = entries[k] || '';
  navigator.clipboard.writeText(v).then(() => setStatus('Copied to clipboard'));
}

function saveEntry() {
  const k = keyEl.value.trim();
  if (!k) return;
  const sel = listEl.querySelector('li.selected');
  const prev = sel ? sel.textContent : null;
  if (prev && prev !== k && entries[k] && !confirm(`Key '${k}' exists. Overwrite?`)) return;
  if (prev && prev !== k) delete entries[prev];
  entries[k] = valueEl.value;
  dirty = false;
  refreshList();
  Array.from(listEl.children).forEach(li => { if (li.textContent === k) li.classList.add('selected'); });
  setStatus('Entry saved');
}

function newEntry() {
  Array.from(listEl.children).forEach(li => li.classList.remove('selected'));
  loadEntryToForm(null);
}

async function changePassword() {
  if (!currentPassword && !currentFileName) { alert('Save the file first.'); return; }
  const pw1 = await askPassword('New password');
  if (!pw1) return;
  const pw2 = await askPassword('Confirm new password');
  if (!pw2) return;
  if (pw1 !== pw2) { alert('Passwords do not match'); return; }
  currentPassword = pw1;
  currentSalt = null; // new salt on next save
  serializeAndDownload();
}

// Wire events
document.getElementById('btn-new').addEventListener('click', newFile);
document.getElementById('btn-open').addEventListener('click', openFile);
document.getElementById('btn-save').addEventListener('click', serializeAndDownload);
document.getElementById('btn-add').addEventListener('click', addEntry);
document.getElementById('btn-delete').addEventListener('click', deleteEntry);
document.getElementById('btn-copy').addEventListener('click', copyValue);
document.getElementById('btn-chpw').addEventListener('click', changePassword);
document.getElementById('btn-save-entry').addEventListener('click', saveEntry);
document.getElementById('btn-new-entry').addEventListener('click', newEntry);
searchEl.addEventListener('input', refreshList);
valueEl.addEventListener('input', () => { dirty = true; });
// When pressing Enter in search, select first filtered entry
searchEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    if (filteredKeys.length > 0) {
      const first = filteredKeys[0];
      // Update selection highlight in the list
      Array.from(listEl.children).forEach(li => li.classList.remove('selected'));
      const firstLi = listEl.querySelector('li');
      if (firstLi) firstLi.classList.add('selected');
      loadEntryToForm(first);
    }
  }
});

// Selection highlight
listEl.addEventListener('click', (e) => {
  if (e.target.tagName === 'LI') {
    Array.from(listEl.children).forEach(li => li.classList.remove('selected'));
    e.target.classList.add('selected');
  }
});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  // Use app search instead of browser find
  if ((e.ctrlKey || e.metaKey) && e.key && e.key.toLowerCase() === 'f') {
    e.preventDefault();
    searchEl.focus();
    // Select existing text for quick replacement
    if (typeof searchEl.select === 'function') searchEl.select();
  }
  // Open file
  if ((e.ctrlKey || e.metaKey) && e.key && e.key.toLowerCase() === 'o') {
    e.preventDefault();
    openFile();
  }
  // Save (download)
  if ((e.ctrlKey || e.metaKey) && e.key && e.key.toLowerCase() === 's') {
    e.preventDefault();
    serializeAndDownload();
  }
});

// Initial
refreshList();
setStatus('Ready');
// Save helper using File System Access API when available
async function saveBytesToDisk(bytes) {
  try {
    if (fileHandle) {
      const writable = await fileHandle.createWritable();
      await writable.write(bytes);
      await writable.close();
      setStatus('Saved');
      return true;
    }
    if (window.showSaveFilePicker) {
      const handle = await window.showSaveFilePicker({
        suggestedName: currentFileName || 'crypto_list.crypto_list',
        types: [{ description: 'Crypto List', accept: { 'application/octet-stream': ['.crypto_list'] } }]
      });
      const writable = await handle.createWritable();
      await writable.write(bytes);
      await writable.close();
      fileHandle = handle;
      setStatus('Saved');
      return true;
    }
    return false;
  } catch (e) {
    // User canceled or API not permitted; fall back to download
    if (e && e.name === 'AbortError') return false;
    console.warn('saveBytesToDisk fallback:', e);
    return false;
  }
}

// Format helpers
function isNewFormat(headerBytes) {
  if (!headerBytes || headerBytes.length < MAGIC.length) return false;
  for (let i = 0; i < MAGIC.length; i++) if (headerBytes[i] !== MAGIC[i]) return false;
  return true;
}

async function decryptLegacy(tokenBytes, password, saltBytes) {
  const tokenB64Legacy = bytesToAscii(tokenBytes).trim();
  const raw32Legacy = await pbkdf2_32bytes(password, saltBytes, LEGACY_ITERATIONS);
  const ptLegacy = await fernetDecrypt(tokenB64Legacy, raw32Legacy);
  try {
    const text = new TextDecoder().decode(ptLegacy);
    const obj = JSON.parse(text);
    return { entries: obj.entries || obj || {}, salt: null, legacy: true };
  } catch (_) {
    const obj = unpickleToObject(ptLegacy);
    if (typeof obj !== 'object' || obj === null) throw new Error('Legacy file content invalid');
    const out = {};
    for (const [k, v] of Object.entries(obj)) out[String(k)] = String(v);
    return { entries: out, salt: null, legacy: true };
  }
}


// ----- Legacy support helpers -----
function askSaltFile() {
  // Uses a modal with an explicit user click to trigger the file picker (satisfies user activation)
  return new Promise((resolve, reject) => {
    const backdrop = document.getElementById('modal-backdrop');
    const modal = document.getElementById('salt-modal');
    const chooseBtn = document.getElementById('salt-modal-choose');
    const cancelBtn = document.getElementById('salt-modal-cancel');

    function cleanup(result, isError = false) {
      chooseBtn.removeEventListener('click', onChoose);
      cancelBtn.removeEventListener('click', onCancel);
      window.removeEventListener('keydown', onKey);
      modal.style.display = 'none';
      backdrop.style.display = 'none';
      (isError ? reject : resolve)(result);
    }
    function onCancel() { cleanup(new Error('Salt required for legacy file'), true); }
    function onKey(e) { if (e.key === 'Escape') onCancel(); }
    function onChoose() {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.salt';
      input.style.display = 'none';
      document.body.appendChild(input);
      input.onchange = async (e) => {
        try {
          const file = e.target.files[0];
          if (!file) { cleanup(new Error('Salt required for legacy file'), true); return; }
          const buf = await file.arrayBuffer();
          cleanup(new Uint8Array(buf), false);
        } catch (err) { cleanup(err, true); }
        finally { document.body.removeChild(input); }
      };
      // Direct result of user's click on chooseBtn
      input.click();
    }

    backdrop.style.display = 'block';
    modal.style.display = 'grid';
    chooseBtn.addEventListener('click', onChoose);
    cancelBtn.addEventListener('click', onCancel);
    window.addEventListener('keydown', onKey);
  });
}

function unpickleToObject(bytes) {
  // Minimalist pickle reader for common dict[str->str] cases
  let i = 0;
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const MARK = 0x28; // '('
  const STOP = 0x2e; // '.'
  const EMPTY_DICT = 0x7d; // '}'
  const DICT = 0x64; // 'd'
  const SETITEM = 0x73; // 's'
  const SETITEMS = 0x75; // 'u'
  const PROTO = 0x80;
  const BINUNICODE = 0x58; // 'X'
  const SHORT_BINUNICODE = 0x55; // 'U'
  const BINPUT = 0x71; // 'q'
  const LONG_BINPUT = 0x72; // 'r'
  const MEMOIZE = 0x94; // protocol 4
  const stack = [];
  function read(n) { const s = data.slice(i, i + n); i += n; return s; }
  function readUint8() { return data[i++]; }
  function readUint32LE() { const v = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24); i += 4; return v >>> 0; }
  function readStr(len) { return new TextDecoder().decode(read(len)); }
  while (i < data.length) {
    const op = readUint8();
    switch (op) {
      case PROTO: { readUint8(); break; }
      case EMPTY_DICT: { stack.push({}); break; }
      case MARK: { stack.push(MARK); break; }
      case BINUNICODE: { const n = readUint32LE(); stack.push(readStr(n)); break; }
      case SHORT_BINUNICODE: { const n = readUint8(); stack.push(readStr(n)); break; }
      case DICT: {
        const items = [];
        while (stack.length && stack[stack.length - 1] !== MARK) { items.push(stack.pop()); }
        stack.pop();
        const obj = {};
        for (let j = items.length - 1; j > 0; j -= 2) {
          const key = items[j];      // items = [vN, kN, vN-1, kN-1, ...]
          const val = items[j - 1];  // so key is at j, value at j-1
          obj[String(key)] = String(val);
        }
        stack.push(obj);
        break;
      }
      case SETITEM: {
        const v = stack.pop();
        const k = stack.pop();
        const d = stack.pop();
        d[String(k)] = String(v);
        stack.push(d);
        break;
      }
      case SETITEMS: {
        const items = [];
        while (stack.length && stack[stack.length - 1] !== MARK) { items.push(stack.pop()); }
        stack.pop();
        const d = stack.pop();
        for (let j = items.length - 1; j > 0; j -= 2) {
          const key = items[j];      // key above value in items
          const val = items[j - 1];
          d[String(key)] = String(val);
        }
        stack.push(d);
        break;
      }
      case BINPUT: { readUint8(); break; }
      case LONG_BINPUT: { readUint32LE(); break; }
      case MEMOIZE: { break; }
      case STOP: { return stack.pop(); }
      default: throw new Error('Unsupported pickle opcode: 0x' + op.toString(16));
    }
  }
  return undefined;
}
