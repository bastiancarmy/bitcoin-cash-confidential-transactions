// src/ecdh.js
import { sha256 } from '@noble/hashes/sha2.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { concat } from './utils.js';

// Derive shared secret using sender eph priv & recipient scan/view pub, or vice-versa.
// In noble-curves v2, getSharedSecret returns a 33B "pubkey-like" value.
// Strip the leading format byte for 32B x-only material.
export function deriveSharedSecret(priv32 /* Uint8Array(32) */, pub33 /* Uint8Array(33) */) {
  const ss = secp256k1.getSharedSecret(priv32, pub33); // 33B
  return ss.slice(1); // drop parity byte
}

// HKDF-lite (domain separated) for blind & K_enc from shared secret + context
function kdf(secret32, label /* string */, extra = new Uint8Array(0)) {
  const L = new TextEncoder().encode(label);
  return sha256(concat(L, secret32, extra));
}

// Produce (blind scalar mod n, 32-byte enc key)
export function deriveBlindAndKey(priv32, pub33, ctx /* Uint8Array */ = new Uint8Array(0)) {
  const ss = deriveSharedSecret(priv32, pub33);
  const blindBytes = kdf(ss, 'BCH-CT blind', ctx);
  const encKey = kdf(ss, 'BCH-CT enc', ctx);

  // Reduce to scalar mod n (explicit constant avoids removed CURVE export)
  let r = 0n;
  for (let i = 0; i < 32; i++) r = (r << 8n) + BigInt(blindBytes[i]);
  const ORDER_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  r %= ORDER_N;
  if (r === 0n) r = 1n; // avoid degenerate

  return { r, encKey };
}

// Minimal stream cipher (counter-mode SHA-256)
export function streamXor(key32 /* Uint8Array(32) */, nonce /* Uint8Array */, msg /* Uint8Array */) {
  const out = new Uint8Array(msg.length);
  let counter = 0, off = 0;
  while (off < msg.length) {
    const block = sha256(concat(key32, nonce, Uint8Array.of(counter)));
    const n = Math.min(block.length, msg.length - off);
    for (let i = 0; i < n; i++) out[off + i] = msg[off + i] ^ block[i];
    off += n; counter++;
  }
  return out;
}