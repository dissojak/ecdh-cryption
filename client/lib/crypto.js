function hexToBuf(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}
function bufToHex(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function deriveAesKeyFromPin(pin, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: hexToBuf(saltHex), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function decryptVault(encryptedVault, pin) {
  const { encrypted, salt, iv, tag } = encryptedVault;
  const key = await deriveAesKeyFromPin(pin, salt);
  const encBuf = hexToBuf(encrypted);
  const tagBuf = hexToBuf(tag);
  const cipherBuf = new Uint8Array(encBuf.length + tagBuf.length);
  cipherBuf.set(encBuf);
  cipherBuf.set(tagBuf, encBuf.length);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBuf(iv), tagLength: 128 }, key, cipherBuf);
  // Try to parse as JSON (ECDH private JWK payload). Fallback to hex string for legacy vaults.
  const text = new TextDecoder().decode(plain);
  try {
    return JSON.parse(text);
  } catch (_) {
    // legacy random 32-byte session key
    return { legacySessionKeyHex: bufToHex(new Uint8Array(plain)) };
  }
}

export async function encryptWithSessionKey(plainText, keyHex) {
  const key = await crypto.subtle.importKey('raw', hexToBuf(keyHex), 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plainText));
  return { iv: bufToHex(iv), content: bufToHex(new Uint8Array(enc)) };
}

export async function decryptWithSessionKey(payload, keyHex) {
  const key = await crypto.subtle.importKey('raw', hexToBuf(keyHex), 'AES-GCM', false, ['decrypt']);
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBuf(payload.iv) }, key, hexToBuf(payload.content));
  return new TextDecoder().decode(dec);
}

export function cacheSessionKey(hex, ttlMs) {
  localStorage.setItem('sessionKey', hex);
  localStorage.setItem('sessionKeyExpiry', String(Date.now() + ttlMs));
}
export function loadSessionKey() {
  const key = localStorage.getItem('sessionKey');
  console.log('Loaded session key:', key);
  const expiry = parseInt(localStorage.getItem('sessionKeyExpiry') || '0', 10);
  if (key && Date.now() < expiry) return key;
  return null;
}

// ECDH helpers (P-256)
export async function importPrivateECJwk(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
}
export async function importPublicECJwk(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
}
export async function deriveConversationAesKey(myPrivateJwk, peerPublicJwk) {
  const privKey = await importPrivateECJwk(myPrivateJwk);
  const pubKey = await importPublicECJwk(peerPublicJwk);
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: pubKey },
    privKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
export async function encryptWithDerivedKey(plainText, aesKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plainText));
  return { iv: bufToHex(iv), content: bufToHex(new Uint8Array(enc)) };
}
export async function decryptWithDerivedKey(payload, aesKey) {
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBuf(payload.iv) }, aesKey, hexToBuf(payload.content));
  return new TextDecoder().decode(dec);
}

// Cache decrypted private JWK with TTL (short-lived in-memory via localStorage)
export function cachePrivateJwk(jwkObject, ttlMs) {
  localStorage.setItem('privJwk', JSON.stringify(jwkObject));
  localStorage.setItem('privJwkExpiry', String(Date.now() + ttlMs));
}
export function loadPrivateJwk() {
  const expiry = parseInt(localStorage.getItem('privJwkExpiry') || '0', 10);
  const raw = localStorage.getItem('privJwk');
  if (raw && Date.now() < expiry) {
    try { return JSON.parse(raw); } catch { return null; }
  }
  return null;
}
