// src/ephemeral.js
// Deterministic "ephemeral" key derivation used by Phase-1 demo flows.
//
// This factors out the original pattern:
//
//   ephemPriv = sha256(
//     concat(
//       basePub33,
//       uint64le(amount),
//       hexToBytes(txidHex),
//       uint64le(vout),
//     ),
//   );
//
// IMPORTANT: with domainTag omitted this is bit-for-bit identical
// to the existing Phase-1 behavior, so nothing changes on-chain or
// in transcripts.

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256, concat, hexToBytes, uint64le } from './utils.js';

const te = new TextEncoder();

/**
 * Derive an ephemeral private key for a single funding / change context.
 *
 * @param {Object} params
 * @param {Uint8Array} params.basePub33 - 33-byte compressed pubkey
 *   - funding case: receiver (Bob) pubkey
 *   - self-change case: self paycode pubkey
 * @param {number|bigint} params.amount - amount in satoshis
 * @param {string} params.txidHex - 32-byte txid (big-endian hex, no 0x)
 * @param {number|bigint} params.vout - output index
 * @param {string} [params.domainTag] - optional domain separation tag
 *
 * If domainTag is omitted, this matches the original inline derivation
 * exactly: sha256(basePub33 || amt || txid || vout).
 */
export function deriveEphemeralPriv({
  basePub33,
  amount,
  txidHex,
  vout,
  domainTag,
}) {
  if (!(basePub33 instanceof Uint8Array) || basePub33.length !== 33) {
    throw new Error('deriveEphemeralPriv: basePub33 must be 33-byte compressed pubkey');
  }
  if (typeof txidHex !== 'string' || txidHex.length !== 64) {
    throw new Error('deriveEphemeralPriv: txidHex must be 32-byte txid hex string');
  }

  const parts = [
    basePub33,
    uint64le(amount),
    hexToBytes(txidHex),
    uint64le(vout),
  ];

  if (domainTag && domainTag.length > 0) {
    parts.push(te.encode(domainTag));
  }

  return sha256(concat(...parts));
}

/**
 * Convenience: derive priv + compressed pubkey together.
 */
export function deriveEphemeralKeypair(args) {
  const ephemPriv = deriveEphemeralPriv(args);
  const ephemPub = secp256k1.getPublicKey(ephemPriv, true);
  return { ephemPriv, ephemPub };
}
