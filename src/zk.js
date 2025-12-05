// src/zk.js
// -----------------------------------------------------------------------------
// Zero-knowledge primitives for a 64-bit Sigma range proof over secp256k1.
// - Deterministic prover using seeded randomness (reproducible transcripts)
// - Compatible with noble-curves v2 API style
// - Preserves the classic "OR-of-two-statements per bit" Sigma construction
//
// Conventions:
// - Points are compressed (33 bytes) in serialization
// - Scalars are 32-byte big-endian in serialization
// - All scalar arithmetic is mod n (curve order), derived via Fn.fromBytes()
// -----------------------------------------------------------------------------

// Dependencies
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToBigInt, bigIntToBytes, concat, uint64le } from './utils.js';

/* ========================================================================== */
/* Curve constants & generators                                               */
/* ========================================================================== */

const Point = secp256k1.Point;
const G = Point.BASE;
// v2: curve params via Point.CURVE(). Some builds expose it as a property/function; this form
// stays compatible with your existing setup.
const CURVE = Point.CURVE();
const n = CURVE.n; // curve order

// Deterministic secondary generator H for Pedersen commitments.
// IMPORTANT (v2): reduce with the curve scalar field instead of bigint % n.
const h_scalar = Point.Fn.fromBytes(
  sha256(new TextEncoder().encode('PEDERSEN_H'))
);
const H = G.multiply(h_scalar);

/* ========================================================================== */
/* Local configuration                                                        */
/* ========================================================================== */

// Centralize bit-width to ensure code, logs, and serialization stay in sync.
export const BITS = 64;

/* ========================================================================== */
/* Pedersen commitment                                                        */
/* ========================================================================== */

/**
 * Pedersen commitment C = v*H + r*G
 * @param {number|bigint} v - committed value (interpreted as bigint)
 * @param {bigint|Uint8Array} r - blinding (scalar or bytes -> scalar mod n)
 * @returns {secp256k1.Point} - commitment point
 */
export function pedersenCommit(v, r) {
  const vBig = BigInt(v);
  const rBig = typeof r === 'bigint'
    ? (r % n + n) % n
    : Point.Fn.fromBytes(r); // v2-safe reduction
  return H.multiply(vBig).add(G.multiply(rBig));
}

/* ========================================================================== */
/* Sigma range proof (64-bit)                                                 */
/* ========================================================================== */
/**
 * Generate a 64-bit Sigma range proof that v is in [0, 2^64).
 * Deterministic via `seedBytes`: all prover randomness is derived from seed.
 *
 * Protocol sketch per bit i:
 *  - Commit C_i = r_i*G            if bit=0
 *            C_i = H + r_i*G       if bit=1
 *  - Prove in Sigma that either C_i == r_i*G (b=0) OR (C_i - H) == r_i*G (b=1)
 *  - Fiat–Shamir to combine e0,e1: e = H(A0 || A1 || C_i), with e0+e1 = e
 *
 * @param {number|bigint} v - integer value, 0 <= v < 2^64
 * @param {Uint8Array} seedBytes - seed for deterministic randomness
 * @returns {{
 *   C: secp256k1.Point,
 *   commitments: secp256k1.Point[],
 *   proofs: {A0: secp256k1.Point, A1: secp256k1.Point, e0: bigint, z0: bigint, e1: bigint, z1: bigint}[],
 *   C_bytes: Uint8Array
 * }}
 */
export function generateSigmaRangeProof(v, seedBytes) {
  const vBig = BigInt(v);
  if (vBig < 0n || vBig >= (1n << 64n)) throw new Error('v out of 64-bit range');

  const commitments = []; // C_i per bit
  const proofs = [];      // per-bit OR-proof tuples
  let r = 0n;             // aggregated blinding for C

  // Commit to each bit
  for (let i = 0; i < BITS; i++) {
    const bit = Number((vBig >> BigInt(i)) & 1n);
    // v2-safe scalar derivation (no manual % n)
    const ri = Point.Fn.fromBytes(sha256(concat(seedBytes, uint64le(i), uint64le(0))));
    const C_i = bit ? H.add(G.multiply(ri)) : G.multiply(ri);
    commitments.push(C_i);
    r = (r + (1n << BigInt(i)) * ri) % n;
  }

  // Aggregate commitment C = v*H + r*G
  const C = H.multiply(vBig).add(G.multiply(r));

  // Per-bit Sigma OR-proofs
  for (let i = 0; i < BITS; i++) {
    const bit = Number((vBig >> BigInt(i)) & 1n);
    const ri = Point.Fn.fromBytes(sha256(concat(seedBytes, uint64le(i), uint64le(0))));
    const C_i = commitments[i];

    // Two statements:
    // D0: C_i == r_i*G         (true if bit=0)
    // D1: C_i - H == r_i*G     (true if bit=1)
    const D0 = C_i;
    const D1 = C_i.subtract(H);

    const real = bit;         // which statement is true (0 or 1)
    const sim = 1 - bit;      // the simulated side
    const D_real = real ? D1 : D0;
    const D_sim  = real ? D0 : D1;

    // Real-side randomness
    const k_real = Point.Fn.fromBytes(sha256(concat(seedBytes, uint64le(i), uint64le(1))));
    const A_real = G.multiply(k_real);

    // Simulated side (Fiat–Shamir later enforces e0+e1)
    const e_sim = Point.Fn.fromBytes(sha256(concat(seedBytes, uint64le(i), uint64le(2))));
    const z_sim = Point.Fn.fromBytes(sha256(concat(seedBytes, uint64le(i), uint64le(3))));
    const A_sim = G.multiply(z_sim).subtract(D_sim.multiply(e_sim));

    // Order transcripts consistently as (A0, A1)
    const A0 = real === 0 ? A_real : A_sim;
    const A1 = real === 0 ? A_sim  : A_real;

    // Fiat–Shamir challenge for the bit (v2-safe reduction)
    const e = Point.Fn.fromBytes(
      sha256(concat(A0.toBytes(true), A1.toBytes(true), C_i.toBytes(true)))
    );

    // Split challenge: e_real = e - e_sim mod n
    const e_real = (e - e_sim + n) % n;
    const z_real = (k_real + e_real * ri) % n;

    // Assign (e0,z0) and (e1,z1) by which side is real
    const e0 = real === 0 ? e_real : e_sim;
    const z0 = real === 0 ? z_real : z_sim;
    const e1 = real === 1 ? e_real : e_sim;
    const z1 = real === 1 ? z_real : z_sim;

    proofs.push({ A0, A1, e0, z0, e1, z1 });
  }

  // Internal aggregate check (developer guard)
  let aggC = Point.ZERO;
  for (let i = 0; i < BITS; i++) {
    aggC = aggC.add(commitments[i].multiply(1n << BigInt(i)));
  }
  if (!aggC.equals(C)) throw new Error('Aggregate mismatch between per-bit commitments and C');

  return { C, commitments, proofs, C_bytes: C.toBytes(true) };
}

/* ========================================================================== */
/* Proof (de)serialization                                                    */
/* ========================================================================== */
/**
 * Serialize proof as:
 *   C(33) || C_i(33)*BITS || [ A0(33) || A1(33) || e0(32) || z0(32) || e1(32) || z1(32) ] * BITS
 * @param {*} proof
 * @returns {Uint8Array}
 */
export function serializeProof(proof) {
  const parts = [proof.C_bytes];
  for (let i = 0; i < BITS; i++) parts.push(proof.commitments[i].toBytes(true));
  for (let i = 0; i < BITS; i++) {
    const p = proof.proofs[i];
    parts.push(p.A0.toBytes(true), p.A1.toBytes(true));
    parts.push(bigIntToBytes(p.e0, 32), bigIntToBytes(p.z0, 32));
    parts.push(bigIntToBytes(p.e1, 32), bigIntToBytes(p.z1, 32));
  }
  return concat(...parts);
}

/**
 * Inverse of serializeProof().
 * @param {Uint8Array} bytes
 * @returns {{
 *   C: secp256k1.Point,
 *   commitments: secp256k1.Point[],
 *   proofs: {A0: secp256k1.Point, A1: secp256k1.Point, e0: bigint, z0: bigint, e1: bigint, z1: bigint}[],
 *   C_bytes: Uint8Array
 * }}
 */
export function deserializeProof(bytes) {
  let pos = 0;

  const C_bytes = bytes.slice(pos, pos + 33);
  pos += 33;
  const C = Point.fromBytes(C_bytes);

  const commitments = [];
  for (let i = 0; i < BITS; i++) {
    commitments.push(Point.fromBytes(bytes.slice(pos, pos + 33)));
    pos += 33;
  }

  const proofs = [];
  for (let i = 0; i < BITS; i++) {
    const A0 = Point.fromBytes(bytes.slice(pos, pos + 33)); pos += 33;
    const A1 = Point.fromBytes(bytes.slice(pos, pos + 33)); pos += 33;
    const e0 = bytesToBigInt(bytes.slice(pos, pos + 32));   pos += 32;
    const z0 = bytesToBigInt(bytes.slice(pos, pos + 32));   pos += 32;
    const e1 = bytesToBigInt(bytes.slice(pos, pos + 32));   pos += 32;
    const z1 = bytesToBigInt(bytes.slice(pos, pos + 32));   pos += 32;
    proofs.push({ A0, A1, e0, z0, e1, z1 });
  }

  return { C, commitments, proofs, C_bytes };
}

/* ========================================================================== */
/* Verifier                                                                   */
/* ========================================================================== */
/**
 * Verify a 64-bit Sigma range proof.
 * Checks:
 *  - Aggregation: sum_i 2^i * C_i equals C
 *  - Fiat–Shamir consistency: e0 + e1 == H(A0 || A1 || C_i)
 *  - OR-proof equations: z*G == A + e*D for both branches
 *
 * @param {{
 *   C: secp256k1.Point,
 *   commitments: secp256k1.Point[],
 *   proofs: {A0: secp256k1.Point, A1: secp256k1.Point, e0: bigint, z0: bigint, e1: bigint, z1: bigint}[]
 * }} proof
 * @returns {boolean}
 */
export function verifySigmaRangeProof(proof) {
  // Check aggregate commitment
  let computedC = Point.ZERO;
  for (let i = 0; i < BITS; i++) {
    computedC = computedC.add(proof.commitments[i].multiply(1n << BigInt(i)));
  }
  if (!computedC.equals(proof.C)) return false;

  // Per-bit OR-proof checks
  for (let i = 0; i < BITS; i++) {
    const p = proof.proofs[i];
    const C_i = proof.commitments[i];

    // Fiat–Shamir: e = H(A0 || A1 || C_i) reduced via Fn.fromBytes()
    const e_computed = Point.Fn.fromBytes(
      sha256(concat(p.A0.toBytes(true), p.A1.toBytes(true), C_i.toBytes(true)))
    );
    if ((p.e0 + p.e1) % n !== e_computed) return false;

    // D0 and D1 statements
    const D0 = C_i;
    const D1 = C_i.subtract(H);

    // Check z0*G == A0 + e0*D0
    const left0 = G.multiply(p.z0 % n);
    const right0 = p.A0.add(D0.multiply(p.e0 % n));
    if (!left0.equals(right0)) return false;

    // Check z1*G == A1 + e1*D1
    const left1 = G.multiply(p.z1 % n);
    const right1 = p.A1.add(D1.multiply(p.e1 % n));
    if (!left1.equals(right1)) return false;
  }

  return true;
}

/* ========================================================================== */
/* Proof hash helper (double-SHA256)                                          */
/* ========================================================================== */

/**
 * Compute a proof hash from a serialized envelope or core proof.
 * This mirrors Bitcoin-style hash256: sha256(sha256(bytes)).
 *
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function computeProofHash(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('computeProofHash: bytes must be Uint8Array');
  }
  return sha256(sha256(bytes));
}
