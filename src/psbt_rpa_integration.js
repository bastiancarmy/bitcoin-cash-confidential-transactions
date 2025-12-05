// src/psbt_rpa_integration.js
//
// Glue between the RPA/conf-asset demo and the psbt_rpa helpers.
// Given a PSBT and an array of RPA-output descriptors, attach:
//
// - RPA context (mode, index, prevout, senderPubkey)
// - proofHash (32 bytes)
// - zkSeed (32 bytes)

import {
    RpaModeId,
    makeRpaContextV1FromHex,
    attachRpaContextToPsbtOutput,
    attachProofHashToPsbtOutput,
    attachZkSeedToPsbtOutput,
  } from './psbt_rpa.js';
  
  /**
   * One RPA-enabled PSBT output.
   *
   * @typedef {Object} RpaOutputDescriptor
   * @property {number} outputIndex      - index into psbt.outputs[]
   * @property {number} mode             - RpaModeId value
   * @property {number} index            - RPA child index
   * @property {number} prevoutVout      - funding input vout (number)
   * @property {string} prevoutTxidHex   - 32-byte txid, hex
   * @property {string} senderPubkeyHex  - 33-byte compressed pubkey, hex
   * @property {string} proofHashHex     - 32-byte hash, hex
   * @property {string} zkSeedHex        - 32-byte seed, hex
   */
  
  /**
   * Attach RPA metadata (context + proofHash + zkSeed) to PSBT outputs.
   *
   * @param {import('./psbt_rpa.js').PsbtLike} psbt
   * @param {RpaOutputDescriptor[]} rpaOutputs
   */
  export function attachRpaMetadataToPsbt(psbt, rpaOutputs) {
    for (const outDesc of rpaOutputs) {
      const {
        outputIndex,
        mode,
        index,
        prevoutVout,
        prevoutTxidHex,
        senderPubkeyHex,
        proofHashHex,
        zkSeedHex,
      } = outDesc;
  
      // 1) Build the RPA context struct from hex fields.
      const ctx = makeRpaContextV1FromHex({
        mode,
        index,
        prevoutVout,
        prevoutTxidHex,
        senderPubkeyHex,
      });
  
      // 2) Attach context.
      attachRpaContextToPsbtOutput(psbt, outputIndex, ctx);
  
      // 3) Attach proofHash and zkSeed (32-byte buffers).
      const proofHash = hex32(proofHashHex, 'proofHashHex');
      const zkSeed = hex32(zkSeedHex, 'zkSeedHex');
  
      attachProofHashToPsbtOutput(psbt, outputIndex, proofHash);
      attachZkSeedToPsbtOutput(psbt, outputIndex, zkSeed);
    }
  }
  
  /**
   * Convenience: construct a single descriptor for the Phase-1 conf-asset demo.
   *
   * You can adjust this or ignore it and build RpaOutputDescriptor yourself.
   */
  export function makeConfAssetRpaDescriptor({
    outputIndex,
    rpaIndex,
    fundingPrevoutTxidHex,
    fundingPrevoutVout,
    senderPubkeyHex,
    proofHashHex,
    zkSeedHex,
  }) {
    return {
      outputIndex,
      mode: RpaModeId.CONF_ASSET,
      index: rpaIndex,
      prevoutVout: fundingPrevoutVout,
      prevoutTxidHex: fundingPrevoutTxidHex,
      senderPubkeyHex,
      proofHashHex,
      zkSeedHex,
    };
  }
  
  // ---- internal helper ----
  
  function hex32(hex, label) {
    let h = String(hex || '').trim().toLowerCase();
    if (h.startsWith('0x')) h = h.slice(2);
    if (h.length !== 64) {
      throw new Error(
        `hex32(${label}): expected 64 hex chars (32 bytes), got ${h.length}`,
      );
    }
    if (!/^[0-9a-f]+$/i.test(h)) {
      throw new Error(`hex32(${label}): invalid hex`);
    }
    return Buffer.from(h, 'hex');
  }
  