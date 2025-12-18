// zk_identity.js

// This file defines the proof-system-agnostic ABI for Goal 1:
// "ZK identity for paycodes" (Phase 2, Goal 1).

// ------------------------------
// Constants & protocol tags
// ------------------------------

/**
 * Protocol tag for the identity proof.
 * This is the stable identifier we bind to in scripts / metadata.
 *
 * DO NOT change this once deployed without versioning.
 */
const ZK_ID_PROTOCOL_TAG = 'BCH-RPA-ID-v1';

/**
 * Default range bits. Your spec says k <= 52 by default.
 * For now we keep it a parameter, but 52 is a good default.
 */
const DEFAULT_RANGE_BITS = 52;

// ------------------------------
// Helper: basic validation
// ------------------------------

function assertUint8Array(name, value, expectedLength) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
  if (expectedLength != null && value.length !== expectedLength) {
    throw new Error(`${name} must be ${expectedLength} bytes, got ${value.length}`);
  }
}

function assertNumber(name, value) {
  if (typeof value !== 'number') {
    throw new TypeError(`${name} must be a number`);
  }
}

// ------------------------------
// Identity Public Inputs
// ------------------------------

/**
 * Build canonical IdentityPublicInputs struct.
 *
 * This mirrors Section 4.1 of your Phase-2 spec:
 *  - paycodeHash (32 bytes)
 *  - C (commitment) as compressed point (33 bytes)
 *  - sessionID (32 bytes)
 *  - rangeBound k
 *  - optional envHash (32 bytes)
 *
 * @param {Object} params
 * @param {Uint8Array} params.paycodeHash32
 * @param {Uint8Array} params.commitmentC33
 * @param {Uint8Array} params.sessionId32
 * @param {number}     [params.rangeBits=DEFAULT_RANGE_BITS]
 * @param {Uint8Array|null} [params.envHash32=null]
 * @returns {IdentityPublicInputs}
 */
function buildIdentityPublicInputs({
  paycodeHash32,
  commitmentC33,
  sessionId32,
  rangeBits = DEFAULT_RANGE_BITS,
  envHash32 = null,
}) {
  assertUint8Array('paycodeHash32', paycodeHash32, 32);
  assertUint8Array('commitmentC33', commitmentC33, 33);
  assertUint8Array('sessionId32', sessionId32, 32);
  assertNumber('rangeBits', rangeBits);
  if (envHash32 !== null) {
    assertUint8Array('envHash32', envHash32, 32);
  }

  return {
    protocolTag: ZK_ID_PROTOCOL_TAG,
    paycodeHash32,
    commitmentC33,
    sessionId32,
    rangeBits,
    envHash32,
  };
}

/**
 * Encode public inputs into canonical bytes.
 * This is intentionally simple and reversible, and can later be
 * replaced with CBOR or another format without breaking the ABI
 * as long as encode/decode remain consistent.
 *
 * Layout:
 *   [ len(tag)=1 ][ tag UTF-8 ][ paycodeHash 32 ]
 *   [ commitmentC33 33 ][ sessionId32 32 ]
 *   [ rangeBits u32le ][ hasEnv u8 ][ envHash32? ]
 *
 * @param {IdentityPublicInputs} inputs
 * @returns {Uint8Array}
 */
function encodeIdentityPublicInputs(inputs) {
  const tagBytes = new TextEncoder().encode(inputs.protocolTag);
  const tagLen = tagBytes.length;

  const baseLen =
    1 + tagLen + // tag length + tag
    32 + // paycodeHash
    33 + // commitmentC33
    32 + // sessionId32
    4 + // rangeBits (u32le)
    1; // hasEnv flag

  const hasEnv = inputs.envHash32 instanceof Uint8Array;
  const envLen = hasEnv ? 32 : 0;

  const out = new Uint8Array(baseLen + envLen);
  let offset = 0;

  out[offset++] = tagLen;
  out.set(tagBytes, offset);
  offset += tagLen;

  out.set(inputs.paycodeHash32, offset);
  offset += 32;

  out.set(inputs.commitmentC33, offset);
  offset += 33;

  out.set(inputs.sessionId32, offset);
  offset += 32;

  // rangeBits as unsigned 32-bit little endian
  const rb = inputs.rangeBits >>> 0;
  out[offset++] = rb & 0xff;
  out[offset++] = (rb >>> 8) & 0xff;
  out[offset++] = (rb >>> 16) & 0xff;
  out[offset++] = (rb >>> 24) & 0xff;

  out[offset++] = hasEnv ? 1 : 0;

  if (hasEnv) {
    out.set(inputs.envHash32, offset);
    offset += 32;
  }

  return out;
}

/**
 * Decode public inputs from bytes.
 * Inverse of encodeIdentityPublicInputs.
 *
 * @param {Uint8Array} bytes
 * @returns {IdentityPublicInputs}
 */
function decodeIdentityPublicInputs(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('bytes must be a Uint8Array');
  }
  let offset = 0;

  const tagLen = bytes[offset++];
  const tagBytes = bytes.slice(offset, offset + tagLen);
  offset += tagLen;

  const protocolTag = new TextDecoder().decode(tagBytes);
  if (protocolTag !== ZK_ID_PROTOCOL_TAG) {
    throw new Error(`Invalid protocolTag: ${protocolTag}`);
  }

  const paycodeHash32 = bytes.slice(offset, offset + 32);
  offset += 32;

  const commitmentC33 = bytes.slice(offset, offset + 33);
  offset += 33;

  const sessionId32 = bytes.slice(offset, offset + 32);
  offset += 32;

  const rb =
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24);
  offset += 4;

  const hasEnv = bytes[offset++] === 1;
  let envHash32 = null;
  if (hasEnv) {
    envHash32 = bytes.slice(offset, offset + 32);
    offset += 32;
  }

  return {
    protocolTag,
    paycodeHash32,
    commitmentC33,
    sessionId32,
    rangeBits: rb,
    envHash32,
  };
}

// ------------------------------
// Proof wrapper API (dummy backend)
// ------------------------------

/**
 * Shape of the identity proof we pass around.
 * This is proof-system agnostic:
 *
 *  - protocolTag ties to the identity spec.
 *  - backend identifies which proof system implementation
 *    generated the proof (e.g. "sigma64", "plonk-halo2", "pq-v1").
 *  - publicInputsEncoded is the canonical encoding we defined above.
 *  - proofBytes is an opaque blob owned by the backend.
 *
 * @typedef {Object} IdentityProof
 * @property {string} protocolTag
 * @property {string} backend
 * @property {Uint8Array} publicInputsEncoded
 * @property {Uint8Array} proofBytes
 */

/**
 * Dummy hash function for the placeholder backend.
 * In real code you would import HASH256 or a library hash.
 *
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
function hashPlaceholder(data) {
  // Very dumb non-cryptographic hash: XOR all bytes and repeat.
  // This is ONLY for dev scaffolding; do not rely on this for security.
  let acc = 0;
  for (let i = 0; i < data.length; i++) {
    acc ^= data[i];
  }
  const out = new Uint8Array(32);
  out.fill(acc & 0xff);
  return out;
}

/**
 * Prove paycode identity + amount consistency.
 *
 * IMPORTANT:
 *  - This is a placeholder implementation: it does NOT provide
 *    soundness or zero-knowledge. It's just to establish the ABI
 *    and wiring in the Phase-1 demo.
 *
 * Later, this function will:
 *  - Take a witness consistent with your spec (x_scan, x_spend, v, r, ...).
 *  - Call a real proof backend (Bulletproof, PLONK, PQ scheme).
 *
 * @param {Object} witness - currently unused; shaped later.
 * @param {ReturnType<typeof buildIdentityPublicInputs>} publicInputs
 * @returns {IdentityProof}
 */
function provePaycodeIdentity(witness, publicInputs) {
  const publicInputsEncoded = encodeIdentityPublicInputs(publicInputs);

  // For now, "proofBytes" is just hashPlaceholder(publicInputs || some dummy).
  // In real code this becomes the actual ZK proof bytes.
  const proofBytes = hashPlaceholder(publicInputsEncoded);

  return {
    protocolTag: ZK_ID_PROTOCOL_TAG,
    backend: 'dummy-v0',
    publicInputsEncoded,
    proofBytes,
  };
}

/**
 * Verify identity proof.
 *
 * For now:
 *  - Checks protocolTag and backend string.
 *  - Recomputes the dummy hash and compares.
 *
 * Later:
 *  - Dispatch to the real backend verifier.
 *
 * @param {IdentityProof} proof
 * @returns {boolean}
 */
function verifyPaycodeIdentity(proof) {
  if (!proof || typeof proof !== 'object') return false;
  if (proof.protocolTag !== ZK_ID_PROTOCOL_TAG) return false;
  if (!(proof.publicInputsEncoded instanceof Uint8Array)) return false;
  if (!(proof.proofBytes instanceof Uint8Array)) return false;

  if (proof.backend === 'dummy-v0') {
    const expected = hashPlaceholder(proof.publicInputsEncoded);
    if (expected.length !== proof.proofBytes.length) return false;
    for (let i = 0; i < expected.length; i++) {
      if (expected[i] !== proof.proofBytes[i]) return false;
    }
    return true;
  }

  // Unknown backend – reject for now.
  // When you add real backends, dispatch on proof.backend here.
  return false;
}

// ------------------------------
// Exports
// ------------------------------

module.exports = {
  ZK_ID_PROTOCOL_TAG,
  DEFAULT_RANGE_BITS,
  buildIdentityPublicInputs,
  encodeIdentityPublicInputs,
  decodeIdentityPublicInputs,
  provePaycodeIdentity,
  verifyPaycodeIdentity,
};
