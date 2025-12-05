// src/pedersen.js
// Noble v2-compatible: ESM .js paths, ProjectivePoint->Point, toBytes/fromBytes
import { sha256 } from '@noble/hashes/sha2.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { concat, bytesToHex } from './utils.js';

// Field order for secp256k1 (Fn); avoids relying on removed CURVE export in v2.
const ORDER_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

const TAG_H = new TextEncoder().encode('BCH-CT/H');
const TAG_ASSET = new TextEncoder().encode('BCH-CT/ASSET');

// Try-and-increment: map (tag || data || ctr) -> valid compressed point
function hashToPoint(tagBytes, dataBytes) {
  for (let ctr = 0; ctr < 255; ctr++) {
    const x32 = sha256(concat(tagBytes, dataBytes, Uint8Array.of(ctr)));
    // Attempt both parities (02 / 03). Point.fromBytes expects Uint8Array in v2.
    for (const prefix of [0x02, 0x03]) {
      const comp = concat(Uint8Array.of(prefix), x32);
      try {
        return secp256k1.Point.fromBytes(comp);
      } catch {} // not a point, keep trying
    }
  }
  throw new Error('hashToPoint: failed to find curve point');
}

// Cache H and asset-scoped generators
let _H = null;
const _assetH = new Map();

export function getH() {
  if (_H) return _H;
  _H = hashToPoint(TAG_H, new Uint8Array(0));
  return _H;
}

export function getAssetH(assetId /* Uint8Array(32) or null */) {
  if (!assetId) return getH();
  const key = bytesToHex(assetId);
  const cached = _assetH.get(key);
  if (cached) return cached;
  const H = hashToPoint(TAG_ASSET, assetId);
  _assetH.set(key, H);
  return H;
}

// Commit to v (<= 2^64-1) with blinding r mod n using generator set (G, H*)
export function pedersenCommit64(value /* number|bigint */, r /* bigint */, assetId = null) {
  const v = BigInt(value);
  if (v < 0n || v > 0xffff_ffff_ffff_ffffn) throw new Error('pedersenCommit64: value must be 0..2^64-1');
  const blind = ((r % ORDER_N) + ORDER_N) % ORDER_N;

  const G = secp256k1.Point.BASE;
  const H = getAssetH(assetId);
  return G.multiply(v).add(H.multiply(blind)); // returns Point
}

export function toCompressed(P /* Point */) {
  return P.toBytes(true); // 33 bytes
}
