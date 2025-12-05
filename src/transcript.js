// src/transcript.js
import { sha256 } from '@noble/hashes/sha2';
import { concat, uint64le, varInt, decodeVarInt } from './utils.js';

// CompactSize length-prefix for small fields
function vbytes(u8) {
  if (!(u8 instanceof Uint8Array)) throw new Error('vbytes: expected Uint8Array');
  return concat(varInt(u8.length), u8);
}

export function buildProofEnvelope({
  protocolTag,                  // string, e.g. 'BCH-CT/Sigma64-v1'
  rangeBits,                    // 64
  ephemPub33,                   // Uint8Array(33)
  H33,                          // Uint8Array(33)
  assetId32 = null,             // Uint8Array(32) or null
  outIndex = 0,                 // number | bigint (fits uint64)
  extraCtx = new Uint8Array(0), // Uint8Array
  coreProofBytes,               // Uint8Array (serialized ZK proof)
}) {
  const tag = new TextEncoder().encode(protocolTag);
  const asset = assetId32 ? assetId32 : new Uint8Array(0);

  // header: vbytes(tag) | uint64le(rangeBits) | vbytes(ephemPub33) | vbytes(H33)
  //       | vbytes(assetId32 or empty) | uint64le(outIndex) | vbytes(extraCtx)
  const header = concat(
    vbytes(tag),
    uint64le(rangeBits),
    vbytes(ephemPub33),
    vbytes(H33),
    vbytes(asset),
    uint64le(outIndex),
    vbytes(extraCtx),
  );

  // envelope: "CTv1" | vbytes(header) | vbytes(coreProofBytes)
  const magic = new TextEncoder().encode('CTv1');
  return concat(magic, vbytes(header), vbytes(coreProofBytes));
}

export function parseProofEnvelope(envelope /* Uint8Array */) {
  const magic = new TextEncoder().encode('CTv1');
  if (envelope.length < magic.length) throw new Error('envelope too short');
  for (let i = 0; i < magic.length; i++) {
    if (envelope[i] !== magic[i]) throw new Error('bad envelope magic');
  }

  let off = magic.length;

  // header
  const hdrLenInfo = decodeVarInt(envelope, off);
  off += hdrLenInfo.length;
  const header = envelope.slice(off, off + hdrLenInfo.value);
  off += hdrLenInfo.value;

  // core
  const coreLenInfo = decodeVarInt(envelope, off);
  off += coreLenInfo.length;
  const core = envelope.slice(off, off + coreLenInfo.value);

  return { header, core };
}

export function hash256(u8 /* Uint8Array */) {
  return sha256(sha256(u8));
}
