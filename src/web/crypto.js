// Crypto primitives the three cards need, for browsers and Node.
//   HMAC-SHA256  -> WebCrypto
//   AES-CCM      -> built from WebCrypto AES-CBC (CBC-MAC) + AES-CTR (keystream)
//   3DES-ECB     -> compact pure-JS DES (WebCrypto has no 3DES)

export const webcrypto = globalThis.crypto ?? (await import('node:crypto')).webcrypto;

const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s) => new Uint8Array(s.match(/../g)?.map((h) => parseInt(h, 16)) ?? []);
export { hex, unhex };

// ---------------------------------------------------------------- HMAC ---- //
export async function hmacSha256(key, ...parts) {
  const k = await webcrypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const len = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { buf.set(p, off); off += p.length; }
  return new Uint8Array(await webcrypto.subtle.sign('HMAC', k, buf));
}

// ------------------------------------------------------------- AES-CCM ---- //
// CCM with a 12-byte nonce (L = 3), arbitrary tag length (we use 4).
async function aesKey(raw) {
  return webcrypto.subtle.importKey('raw', raw, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
}
async function ctrKey(raw) {
  return webcrypto.subtle.importKey('raw', raw, { name: 'AES-CTR' }, false, ['encrypt', 'decrypt']);
}

function xor(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i % b.length];
  return out;
}

/** CBC-MAC over arbitrary length using WebCrypto's AES-CBC (PKCS#7 pads a
 *  whole extra block, so the MAC is the block *before* that padding block). */
async function cbcMac(key, data) {
  const pad = (16 - (data.length % 16)) % 16;
  const block = new Uint8Array(data.length + (pad ? pad : 0));
  block.set(data);
  const ct = new Uint8Array(await webcrypto.subtle.encrypt(
    { name: 'AES-CBC', iv: new Uint8Array(16) }, await aesKey(key), block));
  // ciphertext = CBC(data) || E(padding block)
  const start = ct.length - 16 - 16;
  return ct.slice(start < 0 ? 0 : start, start < 0 ? 16 : start + 16);
}

async function ctrCrypt(key, nonce, counter, data) {
  const iv = new Uint8Array(16);
  iv[0] = 0x02;                       // L-1 = 2  -> 3-byte counter
  iv.set(nonce, 1);
  iv[13] = (counter >> 16) & 0xff;
  iv[14] = (counter >> 8) & 0xff;
  iv[15] = counter & 0xff;
  return new Uint8Array(await webcrypto.subtle.encrypt(
    { name: 'AES-CTR', counter: iv, length: 24 }, await ctrKey(key), data));
}

/** AES-CCM encrypt; mirrors AESCCM(key, tag_length=4) in the Python client. */
export async function aesccmEncrypt(key, nonce, aad, plaintext, tagLen = 4) {
  const b0 = new Uint8Array(16);
  b0[0] = 0x40 | (((tagLen - 2) / 2) << 3) | 0x02;      // Adata=0, L-1=2
  b0.set(nonce, 1);
  const len = plaintext.length;
  b0[13] = (len >> 16) & 0xff; b0[14] = (len >> 8) & 0xff; b0[15] = len & 0xff;

  const aadPadded = aad.length
    ? new Uint8Array([...new Uint8Array(2 + aad.length).map((_, i) =>
        i < 2 ? ((aad.length >> 8) & 0xff) * (i === 0) + (aad.length & 0xff) * (i === 1) : aad[i - 2]),
        ...new Uint8Array((16 - ((2 + aad.length) % 16)) % 16)])
    : new Uint8Array(0);
  const ptPadded = new Uint8Array(plaintext.length + ((16 - (plaintext.length % 16)) % 16));
  ptPadded.set(plaintext);

  const macInput = new Uint8Array(b0.length + aadPadded.length + ptPadded.length);
  macInput.set(b0, 0); macInput.set(aadPadded, b0.length); macInput.set(ptPadded, b0.length + aadPadded.length);
  let tag = await cbcMac(key, macInput);

  const s0 = await ctrCrypt(key, nonce, 0, new Uint8Array(tagLen));
  tag = xor(tag.slice(0, tagLen), s0);

  const ct = await ctrCrypt(key, nonce, 1, plaintext);
  const out = new Uint8Array(ct.length + tagLen);
  out.set(ct); out.set(tag, ct.length);
  return out;
}

export async function aesccmDecrypt(key, nonce, aad, ciphertext, tagLen = 4) {
  const ct = ciphertext.slice(0, ciphertext.length - tagLen);
  const tag = ciphertext.slice(ciphertext.length - tagLen);
  const plaintext = await ctrCrypt(key, nonce, 1, ct);          // CTR first

  const b0 = new Uint8Array(16);
  b0[0] = 0x40 | (((tagLen - 2) / 2) << 3) | 0x02;
  b0.set(nonce, 1);
  const len = plaintext.length;
  b0[13] = (len >> 16) & 0xff; b0[14] = (len >> 8) & 0xff; b0[15] = len & 0xff;

  const aadPadded = aad.length
    ? new Uint8Array([...new Uint8Array(2 + aad.length).map((_, i) =>
        i < 2 ? ((aad.length >> 8) & 0xff) * (i === 0) + (aad.length & 0xff) * (i === 1) : aad[i - 2]),
        ...new Uint8Array((16 - ((2 + aad.length) % 16)) % 16)])
    : new Uint8Array(0);
  const ptPadded = new Uint8Array(plaintext.length + ((16 - (plaintext.length % 16)) % 16));
  ptPadded.set(plaintext);
  const macInput = new Uint8Array(b0.length + aadPadded.length + ptPadded.length);
  macInput.set(b0, 0); macInput.set(aadPadded, b0.length); macInput.set(ptPadded, b0.length + aadPadded.length);
  let expect = await cbcMac(key, macInput);
  const s0 = await ctrCrypt(key, nonce, 0, new Uint8Array(tagLen));
  expect = xor(expect.slice(0, tagLen), s0);
  for (let i = 0; i < tagLen; i++) if (expect[i] !== tag[i]) throw new Error('AES-CCM tag mismatch');
  return plaintext;
}

// --------------------------------------------------------------- 3DES ---- //
const IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7];
const FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25];
const E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
           16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1];
const P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25];
const PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
             63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4];
const PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
             41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32];
const SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];
const SBOX = [
 [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
 [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
 [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
 [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
 [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
 [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
 [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
 [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]];

const perm = (bits, table) => table.map((i) => bits[i - 1]);
const toBits = (bytes) => {
  const out = [];
  for (const b of bytes) for (let i = 7; i >= 0; i--) out.push((b >> i) & 1);
  return out;
};
const toBytes = (bits) => {
  const out = new Uint8Array(bits.length / 8);
  for (let i = 0; i < out.length; i++) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | bits[i * 8 + j];
    out[i] = v;
  }
  return out;
};

function subkeys(key) {
  const kb = toBits(key);
  const cd = perm(kb, PC1);
  let c = cd.slice(0, 28), d = cd.slice(28);
  const out = [];
  for (const s of SHIFTS) {
    c = [...c.slice(s), ...c.slice(0, s)];
    d = [...d.slice(s), ...d.slice(0, s)];
    out.push(perm([...c, ...d], PC2));
  }
  return out;
}

function feistel(r, k) {
  const x = perm(r, E).map((b, i) => b ^ k[i]);
  const out = [];
  for (let i = 0; i < 8; i++) {
    const chunk = x.slice(i * 6, i * 6 + 6);
    const row = (chunk[0] << 1) | chunk[5];
    const col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4];
    const v = SBOX[i][row * 16 + col];
    for (let b = 3; b >= 0; b--) out.push((v >> b) & 1);
  }
  return perm(out, P);
}

function desBlock(block, ks, decrypt) {
  const bits = perm(toBits(block), IP);
  let l = bits.slice(0, 32), r = bits.slice(32);
  for (let i = 0; i < 16; i++) {
    const k = ks[decrypt ? 15 - i : i];
    const f = feistel(r, k);
    const nr = l.map((b, j) => b ^ f[j]);
    l = r; r = nr;
  }
  return toBytes(perm([...r, ...l], FP));
}

export function desEcb(key, data, decrypt = false) {
  const ks = subkeys(key);
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += 8) {
    out.set(desBlock(data.slice(off, off + 8), ks, decrypt), off);
  }
  return out;
}

/** 2-key 3DES (K1||K2||K1) ECB, matching Cryptography's TripleDES. */
export function tripleDesEcb(key16, data, decrypt = false) {
  const k1 = key16.slice(0, 8), k2 = key16.slice(8, 16);
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += 8) {
    const block = data.slice(off, off + 8);
    let r = decrypt
      ? desEcb(k1, desEcb(k2, desEcb(k1, block, true), false), true)
      : desEcb(k1, desEcb(k2, desEcb(k1, block, false), true), false);
    out.set(r, off);
  }
  return out;
}

export function sum16(data) {
  return data.reduce((a, b) => (a + b) & 0xffff, 0);
}
