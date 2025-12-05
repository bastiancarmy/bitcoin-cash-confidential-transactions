// src/covenants.js
import { _hash160, hexToBytes, concat } from './utils.js';
import { getP2SHScript } from './tx.js';
import artifact from '../artifact.json' assert { type: 'json' };
import debugArtifact from '../artifact.json' assert { type: 'json' };

/* -------------------------------------------------------------------------- */
/* Load covenant template bytecode from artifacts                             */
/* - We expect the *template* to ALREADY be compiled WITHOUT any OP_HASH256   */
/*   + OP_EQUALVERIFY that ties to a proof/envelope.                           */
/* - I.e., the template should still do:                                       */
/*   - token prefix/NFT checks                                                 */
/*   - output[0] bytecode = P2PKH(Bob)                                         */
/*   - output[0] value == <amount> (provided by unlocker)                      */
/*   - CHECKSIG                                                                */
/* -------------------------------------------------------------------------- */
function getTemplateBytecodeHex() {
  const candidates = [
    debugArtifact?.debug?.bytecode,
    artifact?.debug?.bytecode,
    artifact?.bytecode,
  ].filter(Boolean);

  for (const s of candidates) {
    const trimmed = String(s).trim().replace(/\s+/g, '');
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
      return trimmed.toLowerCase();
    }
  }
  throw new Error(
    'No valid hex bytecode found in artifacts. Compile your CashScript WITHOUT the envelope-hash block (use --debug for debug.bytecode).'
  );
}

/* -------------------------------------------------------------------------- */
/* instantiateCovenantBytecode (no proof hash anymore)                        */
/* - We only PUSHDATA(20) bobPaycodeHash, then append the template tail.      */
/* - The template tail is responsible for:                                     */
/*     token prefix checks + Bob pay-to + value equality + CHECKSIG            */
/* -------------------------------------------------------------------------- */
export function instantiateCovenantBytecode(bobPaycodeHash20 /* Uint8Array */) {
  if (!(bobPaycodeHash20 instanceof Uint8Array) || bobPaycodeHash20.length !== 20) {
    throw new Error('bobPaycodeHash must be 20-byte Uint8Array');
  }

  // Push order (constants first, like before, but ONLY the 20B paycode hash):
  //   PUSHDATA(20) bobPaycodeHash
  const pushPaycode = concat(Uint8Array.of(0x14), bobPaycodeHash20);

  // Then append the compiled template (which must NOT expect to see a 32B proof hash)
  const templateHex      = getTemplateBytecodeHex();
  const templateBytecode = hexToBytes(templateHex);

  const redeemScript = concat(pushPaycode, templateBytecode);

  // Lightweight sanity notes:
  // - We used to hard-check specific opcode bytes here. Since the CashScript template
  //   changed (we dropped the OP_HASH256/OP_EQUALVERIFY preimage guard), exact bytes
  //   differ. We keep a minimal guard to catch obviously empty or too-short templates.
  if (redeemScript.length < (1 + 20 + 16)) {
    // 1 (push opcode) + 20 bytes + some template body
    throw new Error(
      `Redeem script unexpectedly short (${redeemScript.length} bytes). Ensure artifact.json was rebuilt without the envelope-hash block.`
    );
  }

  // Optional: log the first few ops to help when debugging
  // console.log('RedeemScript prefix (first 48 bytes):', bytesToHex(redeemScript.slice(0, 48)));

  return redeemScript;
}

/* -------------------------------------------------------------------------- */
/* deriveRedeemScript                                                         */
/* - Accepts: 33B compressed pubkey, or 20B hash160                            */
/* - Computes/uses hash160(pubkey) and builds the final redeem script          */
/* -------------------------------------------------------------------------- */
export function deriveRedeemScript(bobKeyOrHash /* Uint8Array */) {
  if (!(bobKeyOrHash instanceof Uint8Array)) {
    throw new Error('bobKeyOrHash must be Uint8Array');
  }

  let bobPaycodeHash20;
  if (bobKeyOrHash.length === 33) {
    // ✅ Commit to hash160(compressed pubkey)
    bobPaycodeHash20 = _hash160(bobKeyOrHash);
  } else if (bobKeyOrHash.length === 20) {
    bobPaycodeHash20 = bobKeyOrHash;
  } else {
    throw new Error('bobKeyOrHash must be 33-byte compressed pubkey or 20-byte hash160');
  }

  return instantiateCovenantBytecode(bobPaycodeHash20);
}

function toBobHash20(bobKeyOrHash) {
  if (!(bobKeyOrHash instanceof Uint8Array)) {
    throw new Error('bobKeyOrHash must be Uint8Array');
  }
  if (bobKeyOrHash.length === 33) return _hash160(bobKeyOrHash);
  if (bobKeyOrHash.length === 20) return bobKeyOrHash;
  throw new Error('bobKeyOrHash must be 33-byte compressed pubkey or 20-byte hash160');
}

/**
 * createCovenant(guardHash160OrPub, proofHash32?)
 *
 * - guardHash160OrPub: 20-byte HASH160 or 33-byte compressed pubkey
 * - proofHash32: optional 32-byte HASH256(proofBytes) for L1 anchoring
 *
 * We build:
 *
 *   redeemScript =
 *     [if proofHash32]
 *       OP_PUSH32 <proofHash32>
 *       OP_DROP                        // remove it from the runtime stack
 *     end
 *     OP_PUSH20 <bobHash160>
 *     <templateBytecode>
 *
 * Then covenantScript = OP_HASH160 <hash160(redeemScript)> OP_EQUAL
 */
export function createCovenant(bobKeyOrHash, proofHash32 /* Uint8Array | undefined */) {
  const bobHash20 = toBobHash20(bobKeyOrHash);

  // Load the template from artifact.json (no proof hash baked in)
  const templateHex      = getTemplateBytecodeHex();
  const templateBytecode = hexToBytes(templateHex);

  // PUSHDATA(20) bobHash20 (Bob-only guard)
  const pushBobGuard = concat(Uint8Array.of(0x14), bobHash20);

  let header;

  if (proofHash32 != null) {
    if (!(proofHash32 instanceof Uint8Array) || proofHash32.length !== 32) {
      throw new Error('proofHash32 must be a 32-byte Uint8Array when provided');
    }

    // PUSHDATA(32) proofHash32
    const pushProof = concat(Uint8Array.of(0x20), proofHash32);
    const opDrop    = Uint8Array.of(0x75); // OP_DROP

    // Stack effect:
    //   existing unlock stack ...,
    //   then we push proofHash,
    //   OP_DROP removes it again,
    //   then we push bobHash20 and enter the template.
    header = concat(pushProof, opDrop, pushBobGuard);
  } else {
    // No proof anchoring, just the Bob guard in front
    header = pushBobGuard;
  }

  const redeemScript   = concat(header, templateBytecode);
  const covenantScript = getP2SHScript(_hash160(redeemScript));

  return { covenantBytecode: redeemScript, covenantScript };
}