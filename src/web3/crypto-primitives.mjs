/**
 * Zero-Dependency Pure-JS & Node `crypto` Primitives (`crypto-primitives.mjs`):
 * - Keccak-256 (original 0x01 pad used by Ethereum/EVM/Tron) + EIP-55 Checksum
 * - SHA-256 & Double-SHA-256 (`sha256d`)
 * - Base58 & Base58Check (Bitcoin/Tron/Solana + Ripple XRPL alphabets)
 * - Bech32 (BIP-173) & Bech32m (BIP-350) + 5/8-bit witness conversion
 * - Ed25519 Twisted Edwards Curve Point Check ($p = 2^{255} - 19$) for Solana Wallet vs PDA detection
 * - CRC16-CCITT (XMODEM, poly `0x1021`) for TON Friendly Addresses (`EQ...` / `UQ...`)
 * - Stacks c32check (`SP...` / `SM...` / `ST...` / `SN...`)
 */

import { createHash } from 'node:crypto';

// ============================================================================
// 1. Keccak-256 (Original Ethereum 0x01 Domain Padding, 24-Round Keccak-f[1600])
// ============================================================================

const MASK_64 = 0xffffffffffffffffn;

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const KECCAK_PILN = [
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

function rotl64(x, n) {
  if (n === 0n) return x & MASK_64;
  return ((x << n) | (x >> (64n - n))) & MASK_64;
}

function keccakF1600(state) {
  const bc = new Array(5).fill(0n);
  for (let round = 0; round < 24; round++) {
    // Theta
    for (let i = 0; i < 5; i++) {
      bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
    }
    for (let i = 0; i < 5; i++) {
      const t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1n);
      for (let j = 0; j < 25; j += 5) {
        state[j + i] = (state[j + i] ^ t) & MASK_64;
      }
    }
    // Rho & Pi (triangular rotation offsets: (i + 1)(i + 2)/2 mod 64)
    let t = state[1];
    for (let i = 0; i < 24; i++) {
      const j = KECCAK_PILN[i];
      const r = BigInt((((i + 1) * (i + 2)) / 2) % 64);
      const tmp = state[j];
      state[j] = rotl64(t, r);
      t = tmp;
    }
    // Chi
    for (let j = 0; j < 25; j += 5) {
      for (let i = 0; i < 5; i++) bc[i] = state[j + i];
      for (let i = 0; i < 5; i++) {
        state[j + i] = (bc[i] ^ ((~bc[(i + 1) % 5] & MASK_64) & bc[(i + 2) % 5])) & MASK_64;
      }
    }
    // Iota
    state[0] = (state[0] ^ KECCAK_RC[round]) & MASK_64;
  }
}

export function keccak256Bytes(input) {
  const msg = typeof input === 'string' ? new TextEncoder().encode(input) : Uint8Array.from(input);
  const rate = 136; // 1088 bits for Keccak-256
  const state = new Array(25).fill(0n);

  const paddedLen = Math.ceil((msg.length + 1) / rate) * rate;
  const buf = new Uint8Array(paddedLen);
  buf.set(msg);
  buf[msg.length] ^= 0x01;
  buf[paddedLen - 1] ^= 0x80;

  for (let offset = 0; offset < paddedLen; offset += rate) {
    for (let lane = 0; lane < 17; lane++) {
      let word = 0n;
      const base = offset + lane * 8;
      for (let b = 0; b < 8; b++) {
        word |= BigInt(buf[base + b]) << BigInt(8 * b);
      }
      state[lane] ^= word;
    }
    keccakF1600(state);
  }

  const out = new Uint8Array(32);
  for (let lane = 0; lane < 4; lane++) {
    const word = state[lane];
    for (let b = 0; b < 8; b++) {
      out[lane * 8 + b] = Number((word >> BigInt(8 * b)) & 0xffn);
    }
  }
  return out;
}

export function keccak256Hex(input) {
  return Buffer.from(keccak256Bytes(input)).toString('hex');
}

export function toEip55Address(hex40OrPrefixed) {
  const clean = String(hex40OrPrefixed).replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(clean)) {
    throw new Error('Invalid 20-byte EVM hex address');
  }
  const hash = keccak256Hex(clean);
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    const ch = clean[i];
    if (ch >= 'a' && ch <= 'f' && parseInt(hash[i], 16) >= 8) {
      out += ch.toUpperCase();
    } else {
      out += ch;
    }
  }
  return out;
}

// ============================================================================
// 2. SHA-256 & Double-SHA-256
// ============================================================================

export function sha256(bytes) {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

export function sha256d(bytes) {
  return sha256(sha256(bytes));
}

// ============================================================================
// 3. Base58 & Base58Check (Bitcoin/Tron/Solana + Ripple XRPL Alphabets)
// ============================================================================

export const BASE58_BTC_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export const BASE58_XRPL_ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

export function base58Decode(str, alphabet = BASE58_BTC_ALPHABET) {
  if (!str || typeof str !== 'string') throw new Error('Empty Base58 input');
  const zeroChar = alphabet[0];
  let leadingZeros = 0;
  while (leadingZeros < str.length && str[leadingZeros] === zeroChar) {
    leadingZeros++;
  }

  let num = 0n;
  for (let i = leadingZeros; i < str.length; i++) {
    const idx = alphabet.indexOf(str[i]);
    if (idx === -1) {
      throw new Error(`Invalid Base58 character "${str[i]}" at index ${i}`);
    }
    num = num * 58n + BigInt(idx);
  }

  const tail = [];
  while (num > 0n) {
    tail.push(Number(num & 0xffn));
    num >>= 8n;
  }
  tail.reverse();

  const out = new Uint8Array(leadingZeros + tail.length);
  out.set(tail, leadingZeros);
  return out;
}

export function base58Encode(bytes, alphabet = BASE58_BTC_ALPHABET) {
  const u8 = Uint8Array.from(bytes);
  let leadingZeros = 0;
  while (leadingZeros < u8.length && u8[leadingZeros] === 0) {
    leadingZeros++;
  }
  let num = 0n;
  for (let i = leadingZeros; i < u8.length; i++) {
    num = (num << 8n) | BigInt(u8[i]);
  }
  const chars = [];
  while (num > 0n) {
    const rem = Number(num % 58n);
    num /= 58n;
    chars.push(alphabet[rem]);
  }
  chars.reverse();
  return alphabet[0].repeat(leadingZeros) + chars.join('');
}

export function base58CheckDecode(str, alphabet = BASE58_BTC_ALPHABET) {
  const raw = base58Decode(str, alphabet);
  if (raw.length < 5) {
    throw new Error('Base58Check payload too short (< 5 bytes)');
  }
  const payload = raw.subarray(0, raw.length - 4);
  const checksum = raw.subarray(raw.length - 4);
  const expected = sha256d(payload).subarray(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expected[i]) {
      throw new Error('Base58Check SHA-256d checksum mismatch');
    }
  }
  return payload;
}

export function base58CheckEncode(payload, alphabet = BASE58_BTC_ALPHABET) {
  const u8 = Uint8Array.from(payload);
  const csum = sha256d(u8).subarray(0, 4);
  const full = new Uint8Array(u8.length + 4);
  full.set(u8, 0);
  full.set(csum, u8.length);
  return base58Encode(full, alphabet);
}

// ============================================================================
// 4. Bech32 (BIP-173) & Bech32m (BIP-350)
// ============================================================================

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const ret = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >>> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

export function bech32Decode(addr, maxLen = 90) {
  if (typeof addr !== 'string' || addr.length < 8 || addr.length > maxLen) {
    throw new Error(`Invalid Bech32 length (${addr?.length ?? 0})`);
  }
  let hasLower = false;
  let hasUpper = false;
  for (let i = 0; i < addr.length; i++) {
    const c = addr.charCodeAt(i);
    if (c < 33 || c > 126) throw new Error('Invalid ASCII character in Bech32 string');
    if (c >= 97 && c <= 122) hasLower = true;
    if (c >= 65 && c <= 90) hasUpper = true;
  }
  if (hasLower && hasUpper) {
    throw new Error('Mixed-case Bech32 strings are forbidden by BIP-173');
  }

  const lower = addr.toLowerCase();
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) {
    throw new Error('Invalid Bech32 separator position');
  }
  const hrp = lower.slice(0, pos);
  const data = [];
  for (let i = pos + 1; i < lower.length; i++) {
    const d = BECH32_CHARSET.indexOf(lower[i]);
    if (d === -1) throw new Error(`Invalid Bech32 data character "${lower[i]}"`);
    data.push(d);
  }

  const check = bech32Polymod([...bech32HrpExpand(hrp), ...data]);
  let encoding = null;
  if (check === BECH32_CONST) encoding = 'bech32';
  else if (check === BECH32M_CONST) encoding = 'bech32m';
  else throw new Error('Bech32 / Bech32m BCH checksum mismatch');

  return {
    hrp,
    words: data.slice(0, data.length - 6),
    encoding,
    wasUppercase: hasUpper && !hasLower,
    canonical: lower,
  };
}

export function convertBits(data, fromBits, toBits, pad) {
  let acc = 0;
  let bits = 0;
  const ret = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    if (value < 0 || value >>> fromBits !== 0) {
      throw new Error('Invalid bit group value');
    }
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error('Invalid non-zero Bech32 bit padding');
  }
  return new Uint8Array(ret);
}

// ============================================================================
// 5. Ed25519 Curve Check ($p = 2^{255} - 19$) for Solana Wallet vs PDA
// ============================================================================

const ED25519_P = (1n << 255n) - 19n;
// d = -121665 * inv(121666) mod p
const ED25519_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

function modPow(base, exp, mod) {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

export function isOnEd25519Curve(bytes32) {
  if (!bytes32 || bytes32.length !== 32) return false;
  let y = 0n;
  for (let i = 0; i < 32; i++) {
    y |= BigInt(bytes32[i]) << BigInt(8 * i);
  }
  const signBit = Number((y >> 255n) & 1n);
  y &= (1n << 255n) - 1n;
  if (y >= ED25519_P) return false;

  const y2 = (y * y) % ED25519_P;
  const u = (y2 - 1n + ED25519_P) % ED25519_P;
  const v = ((ED25519_D * y2) % ED25519_P + 1n) % ED25519_P;
  if (v === 0n) return false;
  if (u === 0n) {
    // x = 0 with negative sign bit is non-canonical in RFC 8032
    return signBit === 0;
  }

  const vInv = modPow(v, ED25519_P - 2n, ED25519_P);
  const x2 = (u * vInv) % ED25519_P;
  // Euler's criterion: x^2 is a non-zero quadratic residue mod p iff (x^2)^((p-1)/2) == 1 mod p
  const legendre = modPow(x2, (ED25519_P - 1n) / 2n, ED25519_P);
  return legendre === 1n;
}

// ============================================================================
// 6. TON CRC16-CCITT (XMODEM, poly `0x1021`)
// ============================================================================

export function crc16Xmodem(bytes) {
  let crc = 0x0000;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) {
      if (crc & 0x8000) {
        crc = ((crc << 1) ^ 0x1021) & 0xffff;
      } else {
        crc = (crc << 1) & 0xffff;
      }
    }
  }
  return new Uint8Array([(crc >>> 8) & 0xff, crc & 0xff]);
}

// ============================================================================
// 7. Stacks c32check (`SP` / `SM` / `ST` / `SN`)
// ============================================================================

const C32_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function c32CheckDecode(addr) {
  if (typeof addr !== 'string' || !/^S[PMTN][0-9A-Za-z]+$/i.test(addr)) {
    throw new Error('Invalid Stacks c32 address prefix');
  }
  const upper = addr.toUpperCase();
  const versionChar = upper[1];
  const version = C32_ALPHABET.indexOf(versionChar);
  if (version === -1) throw new Error('Invalid Stacks version character');

  const body = upper.slice(2);
  let leadingZeros = 0;
  while (leadingZeros < body.length && body[leadingZeros] === '0') {
    leadingZeros++;
  }

  let num = 0n;
  for (let i = leadingZeros; i < body.length; i++) {
    const idx = C32_ALPHABET.indexOf(body[i]);
    if (idx === -1) throw new Error(`Invalid c32 character "${body[i]}"`);
    num = (num << 5n) | BigInt(idx);
  }

  const tail = [];
  while (num > 0n) {
    tail.push(Number(num & 0xffn));
    num >>= 8n;
  }
  tail.reverse();

  const raw = new Uint8Array(leadingZeros + tail.length);
  raw.set(tail, leadingZeros);
  if (raw.length !== 24) {
    throw new Error(`Invalid Stacks c32check payload length (${raw.length}, expected 24)`);
  }

  const hash160 = raw.subarray(0, 20);
  const csum = raw.subarray(20, 24);
  const versioned = new Uint8Array(21);
  versioned[0] = version;
  versioned.set(hash160, 1);
  const expected = sha256d(versioned).subarray(0, 4);
  for (let i = 0; i < 4; i++) {
    if (csum[i] !== expected[i]) {
      throw new Error('Stacks c32check SHA-256d checksum mismatch');
    }
  }

  return {
    version,
    versionChar,
    hash160Hex: Buffer.from(hash160).toString('hex'),
    canonical: upper,
  };
}
