// src/proofs.js
// -----------------------------------------------------------------------------
// Sigma range proof helpers (noble-curves v2 + CompactSize envelope).
// - Keeps zk primitives in zk.js
// - Envelope uses Bitcoin-style CompactSize (varInt) for each field
// - Returns proof hash = hash256(envelope) for the covenant
// -----------------------------------------------------------------------------

import { sha256 } from '@noble/hashes/sha2.js';
import { concat, varInt, decodeVarInt, uint64le, bytesToHex } from './utils.js';
import { generateSigmaRangeProof, serializeProof, verifySigmaRangeProof } from './zk.js';

// -- CompactSize helpers ------------------------------------------------------

const enc = {
  vbytes(u8) {
    if (!(u8 instanceof Uint8Array)) throw new Error('vbytes expects Uint8Array');
    return concat(varInt(u8.length), u8);
  },
  u64le(n) {
    // store amount as 8-byte little-endian, wrapped in CompactSize
    return enc.vbytes(uint64le(n));
  }
};

// Envelope format (CompactSize for every field):
//   domainTag (vbytes) || ephemPub(33) as vbytes || amount(8 LE) as vbytes || proofBytes as vbytes
function buildEnvelope({ domainTag = 'BCH-CT/Sigma32-v1', ephemPub, amount, proofBytes }) {
  const tag = new TextEncoder().encode(domainTag);
  return concat(
    enc.vbytes(tag),
    enc.vbytes(ephemPub),
    enc.u64le(amount),
    enc.vbytes(proofBytes)
  );
}

function parseEnvelope(bytes) {
  let off = 0;
  function readV() {
    const { value, length } = decodeVarInt(bytes, off);
    off += length;
    const body = bytes.slice(off, off + value);
    off += value;
    return body;
  }

  const domain = readV();                 // domain tag (bytes)
  const ephemPub = readV();               // should be 33B
  const amountLE = readV();               // must be 8B LE
  if (amountLE.length !== 8) throw new Error('amountLE must be 8 bytes');
  const proofBytes = readV();             // serialized proof

  return { domain, ephemPub, amountLE, proofBytes };
}

/**
 * Generate + locally verify a 64-bit Sigma range proof deterministically.
 * Returns:
 *  - proofHashBytes: hash256(envelope)  (for covenant binding)
 *  - commitment:     C (33B) to embed into the NFT commitment
 *  - verified:       boolean local verification result
 *  - envelope:       CompactSize-framed bytes for on-chain push
 *  - proofBytes:     raw serialized proof (fixed layout from zk.js)
 */
export function generateAndVerifyProofs(ephemPubBytes, amount) {
  console.log('--- Generating Sigma Range ZKP (64-bit) for Shielded Send Deterministically ---');

  // Seed: must match Bob's regeneration path (ephemPub || uint64le(amount))
  const seed = sha256(concat(ephemPubBytes, uint64le(amount)));

  // Create proof with deterministic seed
  const proof = generateSigmaRangeProof(amount, seed);
  const proofBytes = serializeProof(proof);

  // CompactSize envelope to avoid "bad point length" issues
  const envelope = buildEnvelope({
    ephemPub: ephemPubBytes,
    amount,
    proofBytes
  });

  // Covenant anchor: hash256(envelope)
  const proofHashBytes = sha256(sha256(envelope));
  console.log('Proof Hash (hash256(envelope)):', bytesToHex(proofHashBytes));
  console.log('--- Verifying Sigma Range ZKP Locally ---');

  const verified = verifySigmaRangeProof(proof);

  // Commitment for token NFT commitment field
  const commitment = proof.C_bytes;

  return { proofHashBytes, commitment, verified, envelope, proofBytes };
}

export { buildEnvelope as buildProofEnvelope, parseEnvelope as parseProofEnvelope };
