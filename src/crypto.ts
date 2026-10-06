const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) {
  K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
}

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/** MD5, returned as 16 raw bytes. Web Crypto has no MD5. */
export function md5(data: Uint8Array): Uint8Array {
  const bitLen = data.length * 8;
  const pad = (56 - ((data.length + 1) % 64) + 64) % 64;
  const buf = new Uint8Array(data.length + 1 + pad + 8);
  buf.set(data);
  buf[data.length] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(buf.length - 8, bitLen >>> 0, true);
  view.setUint32(buf.length - 4, Math.floor(bitLen / 0x100000000), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  for (let off = 0; off < buf.length; off += 64) {
    const m = new Uint32Array(16);
    for (let i = 0; i < 16; i++) m[i] = view.getUint32(off + i * 4, true);
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f: number;
      let g: number;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }
      f = (f + a + K[i] + m[g]) >>> 0;
      a = d;
      d = c;
      c = b;
      b = (b + rotl(f, S[i])) >>> 0;
    }
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  const out = new Uint8Array(16);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, a0, true);
  ov.setUint32(4, b0, true);
  ov.setUint32(8, c0, true);
  ov.setUint32(12, d0, true);
  return out;
}

export function md5Hex(text: string, upper = true): string {
  const raw = md5(new TextEncoder().encode(text));
  const hex = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
  return upper ? hex.toUpperCase() : hex;
}

/** Reolink clips the 32-char MD5 hex to 31 chars on the legacy login body. */
export function credentialHash(text: string, clip = 31): string {
  return md5Hex(text).slice(0, clip);
}

const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
const RCON = new Uint8Array(11);

function xtime(x: number): number {
  return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0)) & 0xff;
}

{
  let p = 1, q = 1;
  do {
    p = p ^ (p << 1) ^ ((p & 0x80) ? 0x1b : 0);
    p &= 0xff;
    q ^= q << 1;
    q ^= q << 2;
    q ^= q << 4;
    q ^= (q & 0x80) ? 0x09 : 0;
    q &= 0xff;
    const xformed = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
    SBOX[p] = xformed ^ 0x63;
    q = q;
  } while (p !== 1);
  SBOX[0] = 0x63;
  for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;
  let r = 1;
  RCON[1] = 1;
  for (let i = 2; i < 11; i++) {
    r = xtime(r);
    RCON[i] = r;
  }
}

function rotl8(x: number, n: number): number {
  return ((x << n) | (x >>> (8 - n))) & 0xff;
}

function expandKey(key: Uint8Array): Uint8Array {
  if (key.length !== 16) throw new Error("AES-128 key must be 16 bytes");
  const w = new Uint8Array(176);
  w.set(key);
  let bytes = 16;
  let rcon = 1;
  const t = new Uint8Array(4);
  while (bytes < 176) {
    t.set(w.subarray(bytes - 4, bytes));
    if (bytes % 16 === 0) {
      const tmp = t[0];
      t[0] = SBOX[t[1]] ^ RCON[rcon++];
      t[1] = SBOX[t[2]];
      t[2] = SBOX[t[3]];
      t[3] = SBOX[tmp];
    }
    for (let i = 0; i < 4; i++) w[bytes] = w[bytes - 16] ^ t[i], bytes++;
  }
  return w;
}

function encryptBlock(block: Uint8Array, roundKeys: Uint8Array): Uint8Array {
  const s = new Uint8Array(block);
  addRound(s, roundKeys, 0);
  for (let round = 1; round <= 10; round++) {
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    shiftRows(s);
    if (round !== 10) mixColumns(s);
    addRound(s, roundKeys, round);
  }
  return s;
}

function addRound(s: Uint8Array, rk: Uint8Array, round: number): void {
  const off = round * 16;
  for (let i = 0; i < 16; i++) s[i] ^= rk[off + i];
}

function shiftRows(s: Uint8Array): void {
  const t = s.slice();
  for (let r = 1; r < 4; r++) {
    for (let c = 0; c < 4; c++) s[r + 4 * c] = t[r + 4 * ((c + r) % 4)];
  }
}

function mixColumns(s: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const i = c * 4;
    const a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
    s[i] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
    s[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
    s[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
    s[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
  }
}

export function aes128EncryptBlock(block: Uint8Array, key: Uint8Array): Uint8Array {
  return encryptBlock(block, expandKey(key));
}

/** AES-128-CFB encrypt. Feedback register is the ciphertext block. */
export function aes128CfbEncrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  if (iv.length !== 16) throw new Error("AES-CFB IV must be 16 bytes");
  const rk = expandKey(key);
  const out = new Uint8Array(data.length);
  let prev = iv.slice();
  for (let off = 0; off < data.length; off += 16) {
    const stream = encryptBlock(prev, rk);
    const n = Math.min(16, data.length - off);
    const next = new Uint8Array(16);
    for (let i = 0; i < n; i++) {
      out[off + i] = data[off + i] ^ stream[i];
      next[i] = out[off + i];
    }
    if (n < 16) next.set(prev.subarray(n), n);
    prev = next;
  }
  return out;
}

/** AES-128-CFB decrypt. Feedback register is the ciphertext block. */
export function aes128CfbDecrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  if (iv.length !== 16) throw new Error("AES-CFB IV must be 16 bytes");
  const rk = expandKey(key);
  const out = new Uint8Array(data.length);
  let prev = iv.slice();
  for (let off = 0; off < data.length; off += 16) {
    const stream = encryptBlock(prev, rk);
    const n = Math.min(16, data.length - off);
    const next = new Uint8Array(16);
    next.set(data.subarray(off, off + n));
    if (n < 16) next.set(prev.subarray(n), n);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ stream[i];
    prev = next;
  }
  return out;
}

/** @deprecated use aes128CfbEncrypt / aes128CfbDecrypt. CFB is not symmetric. */
export function aes128Cfb(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  return aes128CfbEncrypt(data, key, iv);
}

/**
 * Baichuan AES key: MD5(`${nonce}-${password}`) as uppercase hex, first 16 chars.
 * Some firmwares omit the dash; `dash` selects which derivation to use.
 */
export function baichuanAesKey(
  nonce: string,
  password: string,
  dash = true,
): Uint8Array {
  const phrase = dash ? `${nonce}-${password}` : `${nonce}${password}`;
  return new TextEncoder().encode(md5Hex(phrase).slice(0, 16));
}
