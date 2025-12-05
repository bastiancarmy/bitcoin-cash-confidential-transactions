// src/psbt_rpa.js
//
// PSBT helpers for RPA (Phase 1.5 – draft, internal).
// This matches docs/PSBT-RPA-EXTENSIONS-draft-v0.md.
//
// Design goals:
// - No scanning, no on-chain prefixes or markers.
// - PSBT carries derivation *context*, not ephemeral child keys.
// - Deterministic re-derivation from seed + on-chain data.

export const PSBT_RPA_PROP_TYPE = 0xfc; // proprietary key type
export const PSBT_RPA_PREFIX = Buffer.from('bch-rpa-v0', 'ascii'); // draft namespace
export const PSBT_RPA_PREFIX_LEN = PSBT_RPA_PREFIX.length;

/** @enum {number} */
export const RpaPsbtSubType = Object.freeze({
  CONTEXT: 0x01,
  PROOF_HASH: 0x02,
  ZK_SEED: 0x03,
});

/** @enum {number} */
export const RpaModeId = Object.freeze({
  STEALTH_P2PKH: 1,
  PQ_VAULT: 2,
  CONF_ASSET: 3,
});

// --------------------
// Encoding / decoding
// --------------------

const RPA_CONTEXT_V1_LEN = 77; // 1+1+1+1+4+4+32+33

/**
 * @typedef {Object} RpaContextV1
 * @property {number} version
 * @property {number} mode
 * @property {number} index
 * @property {number} prevoutVout
 * @property {Buffer} prevoutTxid
 * @property {Buffer} senderPubkey
 */

/**
 * @typedef {Object} RpaContextV1Hex
 * @property {number} [version]
 * @property {number} mode
 * @property {number} index
 * @property {number} prevoutVout
 * @property {string} prevoutTxidHex
 * @property {string} senderPubkeyHex
 */

/**
 * @typedef {Object} PsbtUnknownKeyVal
 * @property {Buffer} key
 * @property {Buffer} value
 */

/**
 * @typedef {Object} PsbtOutputLike
 * @property {PsbtUnknownKeyVal[]} [unknownKeyVals]
 */

/**
 * @typedef {Object} PsbtLike
 * @property {PsbtOutputLike[]} outputs
 */

/**
 * @param {RpaContextV1} ctx
 * @returns {Buffer}
 */
export function encodeRpaContextV1(ctx) {
  const buf = Buffer.alloc(RPA_CONTEXT_V1_LEN);

  const version = ctx.version ?? 0x01;
  if (version !== 0x01) {
    throw new Error(`encodeRpaContextV1: unsupported version ${version}`);
  }

  if (ctx.prevoutTxid.length !== 32) {
    throw new Error('encodeRpaContextV1: prevoutTxid must be 32 bytes');
  }
  if (ctx.senderPubkey.length !== 33) {
    throw new Error('encodeRpaContextV1: senderPubkey must be 33 bytes');
  }

  buf[0] = version & 0xff;
  buf[1] = ctx.mode & 0xff;
  buf[2] = 0x00; // reserved1
  buf[3] = 0x00; // reserved2

  buf.writeUInt32LE(ctx.index >>> 0, 4);
  buf.writeUInt32LE(ctx.prevoutVout >>> 0, 8);

  ctx.prevoutTxid.copy(buf, 12);  // bytes 12..43
  ctx.senderPubkey.copy(buf, 44); // bytes 44..76

  return buf;
}

/**
 * @param {Buffer} data
 * @returns {RpaContextV1}
 */
export function decodeRpaContextV1(data) {
  if (data.length !== RPA_CONTEXT_V1_LEN) {
    throw new Error(
      `decodeRpaContextV1: expected ${RPA_CONTEXT_V1_LEN} bytes, got ${data.length}`,
    );
  }

  const version = data[0];
  const mode = data[1];
  // const reserved1 = data[2];
  // const reserved2 = data[3];

  if (version !== 0x01) {
    throw new Error(`decodeRpaContextV1: unsupported version ${version}`);
  }

  const index = data.readUInt32LE(4);
  const prevoutVout = data.readUInt32LE(8);
  const prevoutTxid = data.slice(12, 44);  // 32 bytes
  const senderPubkey = data.slice(44, 77); // 33 bytes

  if (prevoutTxid.length !== 32) {
    throw new Error('decodeRpaContextV1: prevoutTxid length mismatch');
  }
  if (senderPubkey.length !== 33) {
    throw new Error('decodeRpaContextV1: senderPubkey length mismatch');
  }

  return {
    version,
    mode,
    index,
    prevoutVout,
    prevoutTxid,
    senderPubkey,
  };
}

/**
 * Build a binary context from hex-friendly fields.
 *
 * @param {RpaContextV1Hex} input
 * @returns {RpaContextV1}
 */
export function makeRpaContextV1FromHex(input) {
  const version = input.version ?? 0x01;

  const prevoutTxid = hexToBufExact(input.prevoutTxidHex, 32, 'prevoutTxidHex');
  const senderPubkey = hexToBufExact(
    input.senderPubkeyHex,
    33,
    'senderPubkeyHex',
  );

  return {
    version,
    mode: input.mode,
    index: input.index,
    prevoutVout: input.prevoutVout,
    prevoutTxid,
    senderPubkey,
  };
}

// ---------------
// PSBT key utils
// ---------------

/**
 * Build proprietary key: 0xFC || prefixLen || prefix || subType || [keyData]
 *
 * @param {number} subType
 * @param {Buffer} [keyData]
 * @returns {Buffer}
 */
export function buildRpaProprietaryKey(subType, keyData) {
  const header = Buffer.from([PSBT_RPA_PROP_TYPE, PSBT_RPA_PREFIX_LEN]);
  const subTypeBuf = Buffer.from([subType & 0xff]);
  if (keyData && keyData.length > 0) {
    return Buffer.concat([header, PSBT_RPA_PREFIX, subTypeBuf, keyData]);
  }
  return Buffer.concat([header, PSBT_RPA_PREFIX, subTypeBuf]);
}

/**
 * Parse a proprietary key and check if it’s one of ours.
 *
 * @param {Buffer} key
 * @returns {{ subType: number, keyData: Buffer } | null}
 */
export function parseRpaProprietaryKey(key) {
  if (!key || key.length < 2 + PSBT_RPA_PREFIX_LEN + 1) {
    return null;
  }
  const keyType = key[0];
  const prefixLen = key[1];

  if (keyType !== PSBT_RPA_PROP_TYPE) return null;
  if (prefixLen !== PSBT_RPA_PREFIX_LEN) return null;

  const prefixStart = 2;
  const prefixEnd = prefixStart + prefixLen;
  const prefix = key.slice(prefixStart, prefixEnd);

  if (!prefix.equals(PSBT_RPA_PREFIX)) return null;

  const subTypePos = prefixEnd;
  const subType = key[subTypePos];

  const keyData = key.slice(subTypePos + 1);

  if (
    subType === RpaPsbtSubType.CONTEXT ||
    subType === RpaPsbtSubType.PROOF_HASH ||
    subType === RpaPsbtSubType.ZK_SEED
  ) {
    return { subType, keyData };
  }

  return null;
}

// ---------------------
// Attach / extract API
// ---------------------

/**
 * @param {PsbtLike} psbt
 * @param {number} outputIndex
 * @param {RpaContextV1} ctx
 */
export function attachRpaContextToPsbtOutput(psbt, outputIndex, ctx) {
  const out = psbt.outputs[outputIndex];
  if (!out) {
    throw new Error(`attachRpaContextToPsbtOutput: no output at index ${outputIndex}`);
  }

  const value = encodeRpaContextV1(ctx);
  const key = buildRpaProprietaryKey(RpaPsbtSubType.CONTEXT);

  ensureUnknownKeyVals(out);
  out.unknownKeyVals.push({ key, value });
}

/**
 * @param {PsbtLike} psbt
 * @param {number} outputIndex
 * @param {Buffer} proofHash32
 */
export function attachProofHashToPsbtOutput(psbt, outputIndex, proofHash32) {
  if (proofHash32.length !== 32) {
    throw new Error('attachProofHashToPsbtOutput: proofHash must be 32 bytes');
  }
  const out = psbt.outputs[outputIndex];
  if (!out) {
    throw new Error(`attachProofHashToPsbtOutput: no output at index ${outputIndex}`);
  }

  const key = buildRpaProprietaryKey(RpaPsbtSubType.PROOF_HASH);
  const value = Buffer.from(proofHash32);

  ensureUnknownKeyVals(out);
  out.unknownKeyVals.push({ key, value });
}

/**
 * @param {PsbtLike} psbt
 * @param {number} outputIndex
 * @param {Buffer} zkSeed32
 */
export function attachZkSeedToPsbtOutput(psbt, outputIndex, zkSeed32) {
  if (zkSeed32.length !== 32) {
    throw new Error('attachZkSeedToPsbtOutput: zkSeed must be 32 bytes');
  }
  const out = psbt.outputs[outputIndex];
  if (!out) {
    throw new Error(`attachZkSeedToPsbtOutput: no output at index ${outputIndex}`);
  }

  const key = buildRpaProprietaryKey(RpaPsbtSubType.ZK_SEED);
  const value = Buffer.from(zkSeed32);

  ensureUnknownKeyVals(out);
  out.unknownKeyVals.push({ key, value });
}

/**
 * @param {PsbtOutputLike} out
 * @returns {RpaContextV1 | null}
 */
export function extractRpaContextFromPsbtOutput(out) {
  if (!out.unknownKeyVals) return null;

  for (const kv of out.unknownKeyVals) {
    const parsed = parseRpaProprietaryKey(kv.key);
    if (!parsed) continue;
    if (parsed.subType === RpaPsbtSubType.CONTEXT) {
      return decodeRpaContextV1(kv.value);
    }
  }
  return null;
}

/**
 * @param {PsbtOutputLike} out
 * @returns {Buffer | null}
 */
export function extractProofHashFromPsbtOutput(out) {
  if (!out.unknownKeyVals) return null;
  for (const kv of out.unknownKeyVals) {
    const parsed = parseRpaProprietaryKey(kv.key);
    if (!parsed) continue;
    if (parsed.subType === RpaPsbtSubType.PROOF_HASH) {
      if (kv.value.length !== 32) {
        throw new Error('extractProofHashFromPsbtOutput: invalid length');
      }
      return kv.value;
    }
  }
  return null;
}

/**
 * @param {PsbtOutputLike} out
 * @returns {Buffer | null}
 */
export function extractZkSeedFromPsbtOutput(out) {
  if (!out.unknownKeyVals) return null;
  for (const kv of out.unknownKeyVals) {
    const parsed = parseRpaProprietaryKey(kv.key);
    if (!parsed) continue;
    if (parsed.subType === RpaPsbtSubType.ZK_SEED) {
      if (kv.value.length !== 32) {
        throw new Error('extractZkSeedFromPsbtOutput: invalid length');
      }
      return kv.value;
    }
  }
  return null;
}

// -----------------
// Internal helpers
// -----------------

/**
 * @param {PsbtOutputLike} out
 */
function ensureUnknownKeyVals(out) {
  if (!out.unknownKeyVals) {
    out.unknownKeyVals = [];
  }
}

/**
 * @param {string} hex
 * @param {number} len
 * @param {string} label
 * @returns {Buffer}
 */
function hexToBufExact(hex, len, label) {
  let h = hex.trim().toLowerCase();
  if (h.startsWith('0x')) h = h.slice(2);
  if (h.length !== len * 2) {
    throw new Error(
      `hexToBufExact(${label}): expected ${len * 2} hex chars, got ${h.length}`,
    );
  }
  if (!/^[0-9a-f]+$/i.test(h)) {
    throw new Error(`hexToBufExact(${label}): invalid hex`);
  }
  return Buffer.from(h, 'hex');
}
