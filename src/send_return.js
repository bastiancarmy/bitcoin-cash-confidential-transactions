// src/send_return.js
/**
 * Phase-1 send/return flows for confidential assets.
 *
 * This file wires together:
 *   - Alice → covenant funding (NFT + amount under Bob-only RPA guard),
 *   - Bob → Alice return (RPA-derived one-time address),
 *   - Alice → Alice "loop close" spend from the RPA child back to her base wallet.
 *
 * Conceptual layers:
 *   - RPA (derivation.js)           = identity / addressing layer
 *   - Covenant (covenants.js)       = on-chain guard enforcing equality constraints
 *   - ZK proofs (transcript.js +
 *                pedersen.js)       = off-chain confidential amount proof
 *   - Ephemeral encrypt/decrypt     = Phase-1 deterministic encryption helper
 *                                     (used to hide the amount from everyone
 *                                      except the intended receiver).
 *
 * In Phase-2 / PQ vaults, the covenant + ZK layer can be replaced with a
 * Quantumroot-style vault script, while RPA and paycodes remain the front-end
 * interface for discovering which outputs belong to which wallet.
 */

import { consolidateUtxos, getP2PKHScript, estimateTxSize, buildRawTx, signInput, signCovenantInput, addTokenToScript, getP2SHScript, getPreimage } from './tx.js';
import { getFeeRate, broadcastTx, connectElectrum, parseTx, getTxDetails } from './electrum.js';
import { decodeCashAddress } from './cashaddr.js';
import {
  _hash160,
  bytesToHex,
  sha256,
  concat,
  uint64le,
  arraysEqual,
  pushDataPrefix,
  minimalScriptNumber,
  extractPubKeyFromPaycode,
  hexToBytes,
  bchSchnorrSign,
  bchSchnorrVerify,
  normalizeCategory32
} from './utils.js';
import { createCovenant } from './covenants.js';
import {
  decryptAmount,
  deriveRpaOneTimePrivReceiver,  // Bob’s covenant guard one-time priv
  deriveRpaLockIntent,
  RPA_MODE_STEALTH_P2PKH
} from './derivation.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { buildProofEnvelope, hash256 as dhash } from './transcript.js';
import { getH, toCompressed } from './pedersen.js';
import { DUST } from './config.js';
import { generateSigmaRangeProof, serializeProof } from './zk.js';

const VERBOSE = false; // flip to true when you want full cryptographic tracing

function debug(...args) {
  if (VERBOSE) console.log(...args);
}

/* -------------------------------------------------------------------------- */
/* Address Utilities */
/* -------------------------------------------------------------------------- */

export function getHash160FromAddress(address) {
  const decoded = decodeCashAddress(address);
  return decoded.hash;
}

/**
 * Deterministic paycode-based self-change derivation (RPA-style).
 * Used for both Alice (funding change) and Bob (return-change) in Mode B.
 */
function deriveSelfPaycodeChange(paycode, amount, txid, vout) {
  if (!paycode) {
    throw new Error('Missing paycode for paycode-based self-change');
  }

  // 33-byte compressed pubkey from paycode (already validated elsewhere)
  const selfPub33 = extractPubKeyFromPaycode(paycode);

  // Deterministic ephemeral for this self-change output
  const ephemPriv = sha256(
    concat(
      selfPub33,
      uint64le(amount),
      hexToBytes(txid),
      uint64le(vout),
    ),
  );
  const ephemPub = secp256k1.getPublicKey(ephemPriv, true);

  // Sender-side address derivation from paycode (RPA-style)
  const rpaResult = deriveAddressFromPaycode(ephemPriv, selfPub33);

  let addr, hash20;
  if (typeof rpaResult === 'string') {
    addr = rpaResult;
    hash20 = getHash160FromAddress(addr);
  } else if (rpaResult && typeof rpaResult === 'object') {
    addr = rpaResult.address;
    hash20 = rpaResult.oneTimeHash160 ?? getHash160FromAddress(addr);
  } else {
    throw new Error('deriveAddressFromPaycode returned unexpected type for self-change');
  }

  console.log('🔁 Paycode self-change RPA addr:', addr);
  console.log('🔁 Paycode self-change RPA hash160:', bytesToHex(hash20));

  return { addr, hash20, ephemPriv, ephemPub };
}

function extractPayHashFromRedeemScript(redeemScript /* Uint8Array */) {
  if (!(redeemScript instanceof Uint8Array)) {
    throw new Error('redeemScript must be Uint8Array');
  }
  if (redeemScript.length < 1 + 20) {
    throw new Error('redeemScript too short');
  }

  let i = 0;

  // Optional header:
  //   0x20 <32 bytes proofHash> 0x75 (OP_DROP)
  // This is what createCovenant(bobHash20, proofHash32) produces.
  if (redeemScript[i] === 0x20) {
    const len = redeemScript[i]; // should be 32
    const start = i + 1;
    const end = start + len;

    if (end + 1 > redeemScript.length) {
      throw new Error('redeemScript too short for proofHash32 header');
    }

    // (Optional sanity: if (len !== 32) throw ...)
    i = end;

    const opDrop = redeemScript[i];
    i += 1;
    if (opDrop !== 0x75) {
      throw new Error('Expected OP_DROP after proofHash32 header');
    }
  }

  // After optional proofHash32+OP_DROP, we must see PUSHDATA(20) with bobHash160
  if (redeemScript[i] !== 0x14) {
    throw new Error(
      'Unexpected covenant header: missing PUSHDATA(20) for bobHash160',
    );
  }

  const startHash = i + 1;
  const endHash = startHash + 20;
  if (endHash > redeemScript.length) {
    throw new Error('redeemScript too short for bobHash160');
  }

  const payHash20 = redeemScript.slice(startHash, endHash);
  return { payHash20, offset: endHash };
}

function assertCovenantWillPassEqVerifies({
  redeemScript,
  payPub33,
  vout0Value,
  decryptedAmount,
}) {
  // (1) Verify HASH160(pubkey33) == embedded payHash20
  const { payHash20 } = extractPayHashFromRedeemScript(redeemScript);
  const pubHash = _hash160(payPub33);
  if (!arraysEqual(pubHash, payHash20)) {
    throw new Error(
      [
        'Covenant guard failed: HASH160(pay pub) mismatch',
        `  got: ${bytesToHex(pubHash)}`,
        `  exp: ${bytesToHex(payHash20)}`,
      ].join('\n')
    );
  }

  // (2) Verify OUTPUTVALUE(0) == decryptedAmount (what the unlocker will push)
  if (BigInt(vout0Value) !== BigInt(decryptedAmount)) {
    throw new Error(
      [
        'Covenant guard failed: vout0.value != decryptedAmount',
        `  got: ${vout0Value}`,
        `  exp: ${decryptedAmount}`,
      ].join('\n')
    );
  }
}

function extractPubKeyFromP2PKHScriptSig(rawScriptSig /* string | Uint8Array | number[] */) {
  let scriptSig;

  if (rawScriptSig instanceof Uint8Array) {
    scriptSig = rawScriptSig;
  } else if (typeof rawScriptSig === 'string') {
    // hex string -> bytes
    scriptSig = hexToBytes(rawScriptSig);
  } else if (Array.isArray(rawScriptSig)) {
    // in case parseTx gives a plain array of numbers
    scriptSig = Uint8Array.from(rawScriptSig);
  } else {
    throw new Error('Unsupported scriptSig type for P2PKH pubkey extraction');
  }

  if (scriptSig.length < 2) {
    throw new Error('scriptSig too short to contain sig and pubkey');
  }

  let i = 0;

  // First push: signature
  const sigLen = scriptSig[i];
  i += 1;
  if (i + sigLen > scriptSig.length) {
    throw new Error('Invalid sig length in scriptSig');
  }
  i += sigLen;

  if (i >= scriptSig.length) {
    throw new Error('Missing pubkey push in scriptSig');
  }

  // Second push: pubkey
  const pubLen = scriptSig[i];
  i += 1;
  if (i + pubLen > scriptSig.length) {
    throw new Error('Invalid pubkey length in scriptSig');
  }

  const pubkey = scriptSig.slice(i, i + pubLen);
  if (pubkey.length !== 33) {
    throw new Error(`Unexpected pubkey length in scriptSig: ${pubkey.length}`);
  }

  return pubkey; // 33-byte compressed pubkey
}

function extractLeadingPush20(bytecode /* Uint8Array */) {
  if (!(bytecode instanceof Uint8Array)) return null;

  try {
    const { payHash20 } = extractPayHashFromRedeemScript(bytecode);
    return payHash20;
  } catch {
    // If the script layout is unexpected, just skip the pk-hash guard locally.
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Transaction Builders */
/* -------------------------------------------------------------------------- */

export async function buildAliceSendTx(
  alice,
  aliceUtxo,
  derivedHash160,
  covenantScript,
  token,
  sendAmount,
  dust,
  aliceHash160,
  alicePrivBytes,
  network
) {
  if (!(alicePrivBytes instanceof Uint8Array)) {
    throw new Error('alicePrivBytes must be Uint8Array');
  }

  console.log('\n--- [1] Alice funds covenant-locked NFT using her base wallet ---');
  console.log('Alice base wallet UTXO:');
  console.log('  - txid :', aliceUtxo.txid);
  console.log('  - vout :', aliceUtxo.vout);
  console.log('  - value:', aliceUtxo.value, 'sats');

  if (alice && alice.address) {
    console.log('Alice base P2PKH address:', alice.address);
  }
  if (alice && alice.paycode) {
    console.log('Alice static paycode:', alice.paycode);
    console.log('  (In this phase, we still send change back to her base wallet.');
    console.log('   A later mode can direct change via self-RPA using this paycode.)');
  } else {
    console.log('Alice paycode: <none set for this run>');
  }

  const rate = await getFeeRate();
  console.log('Dynamic Fee rate:', rate, 'sat/byte');

  const covenantWithToken = addTokenToScript(token, covenantScript);

  // vout0: RPA-derived address (already computed outside -> derivedHash160)
  const derivedScript     = getP2PKHScript(derivedHash160);

  // vout2: Alice’s base wallet change (P2PKH)
  const baseChangeScript  = getP2PKHScript(aliceHash160);

  // Size estimate – values in estOutputs aren't used by estimateTxSize,
  // but we keep the structure realistic.
  const dummyScriptSig = new Uint8Array(7515); // big cushion for covenant flow
  const estInputs  = [{ scriptSig: dummyScriptSig }]; // 1 input (Alice)
  const estOutputs = [
    { value: dust,       script: derivedScript },
    { value: sendAmount, script: covenantWithToken },
    { value: 0,          script: baseChangeScript },
  ];

  const estSize = estimateTxSize(estInputs.length, estOutputs.length) + dummyScriptSig.length;
  const fee     = Math.ceil(estSize * rate) + 10; // small buffer
  const change  = aliceUtxo.value - sendAmount - dust - fee;

  if (change < DUST) {
    throw new Error('Insufficient funds for fee');
  }

  let finalChangeScript = baseChangeScript;

  // --- NOTE: Mode B (self-RPA change) left for a later phase ---
  // if (alice.paycode) {
  //   const { addr, hash20 } = deriveSelfPaycodeChange(
  //     alice.paycode,
  //     change,
  //     aliceUtxo.txid,
  //     aliceUtxo.vout,
  //   );
  //   console.log('🔁 Alice self-change (paycode-derived RPA) addr:', addr);
  //   console.log('🔁 Alice self-change (paycode-derived RPA) hash160:', bytesToHex(hash20));
  //   finalChangeScript = getP2PKHScript(hash20);
  // } else {
  //   console.log('ℹ️ alice.paycode not set; using base P2PKH change (Mode A)');
  // }

  const tx = {
    version: 1,
    inputs: [
      {
        txid: aliceUtxo.txid,
        vout: aliceUtxo.vout,
        sequence: 0xffffffff,
        scriptSig: new Uint8Array(),
      },
    ],
    outputs: [
      // vout0: tiny P2PKH to RPA-derived one-time address (placeholder for encrypted amount)
      { value: dust,       scriptPubKey: derivedScript },

      // vout1: covenant-locked NFT output (P2SH + token prefix)
      { value: sendAmount, scriptPubKey: covenantWithToken },

      // vout2: change back to Alice’s base wallet
      { value: change,     scriptPubKey: finalChangeScript },
    ],
    locktime: 0,
  };

  console.log('\n[1A] Alice funding transaction layout:');
  console.log('  input[0]: Alice base P2PKH (source wallet)');
  console.log('  output[0]: small P2PKH to paycode/RPA-derived address (dust marker)');
  console.log('  output[1]: covenant-locked NFT (guarded by RPA-derived child key)');
  console.log('  output[2]: change back to Alice base wallet P2PKH');
  console.log('  change value:', change, 'sats');

  const inputScriptCode = getP2PKHScript(aliceHash160);
  signInput(tx, 0, alicePrivBytes, inputScriptCode, aliceUtxo.value);

  const txHex = buildRawTx(tx);
  const txId  = await broadcastTx(txHex, network);

  console.log('\n✅ Alice → covenant funding TX broadcast:', txId);
  return txId;
}

async function getPrevoutDetails(txId, vout, network) {
  const client = await connectElectrum(network);
  try {
    const txHex = await client.request('blockchain.transaction.get', txId);
    const txDetails = parseTx(txHex);
    return {
      scriptPubKey: txDetails.outputs[vout].scriptPubKey,
      value: Number(txDetails.outputs[vout].value),
      token_data: txDetails.outputs[vout].token_data
    };
  } finally {
    await client.disconnect();
  }
}

/**
 * Build Bob's return transaction spending the covenant UTXO back to Alice.
 *
 * Flow:
 *  1) Decrypt amount from (ephemeral pubkey, ciphertext) passed into this function
 *  2) Reconstruct the RPA covenant-guard key and verify redeemScript ↔ UTXO P2SH hash
 *  3) Build outputs (tokenized to Alice + optional Bob change)
 *  4) Run pre-broadcast covenant guards (output value, pk-hash) mirroring covenant introspection
 *  5) Sign covenant input (RPA-derived key) + fee input (Bob base key)
 *  6) Broadcast
 */
export async function buildBobReturnTx(
  bob,
  covenantUtxo,
  alicePaycode,
  ephemPubReceived,
  encryptedAmountReceived,
  network,
) {
  console.log('--- [3] Bob builds return TX from covenant → Alice (RPA) ---');

  /* ------------------------------------------------------------------------ */
  /* 1) Decrypt amount (using Alice’s ephemeral pub + Bob’s static key)       */
  /* ------------------------------------------------------------------------ */
  let decryptedAmountStr;
  try {
    decryptedAmountStr = decryptAmount(
      bob.privBytes,
      ephemPubReceived,
      encryptedAmountReceived
    );
    console.log('\n[3A] Bob decrypts the encrypted amount:');
    console.log('  - using: Alice’s ephemeral pubkey + Bob’s static secret');
    console.log('  - raw decrypted JSON:', decryptedAmountStr);
  } catch (err) {
    console.error('Decryption failed:', err);
    throw err;
  }

  const parsed = JSON.parse(decryptedAmountStr);
  if (typeof parsed.v !== 'number') {
    throw new Error('Invalid decrypted format: expected {"v": <number>}');
  }
  const decryptedAmount = parsed.v;
  console.log('  decrypted amount (sats):', decryptedAmount);
  console.log('  (This is the value Bob will enforce on vout[0].)');

  /* ------------------------------------------------------------------------ */
  /* 2) Reconstruct covenant guard key via RPA (receiver side)                */
  /* ------------------------------------------------------------------------ */

  // The covenant UTXO comes from Alice's funding transaction.
  // We use the *funding input 0* as the RPA outpoint for the covenant guard.

  const fundingTxId = covenantUtxo.tx_hash;
  const fundingTx   = await getTxDetails(fundingTxId, network);

  if (!fundingTx.inputs || fundingTx.inputs.length === 0) {
    throw new Error('Funding tx has no inputs; cannot derive RPA covenant key');
  }

  const fundingInput = fundingTx.inputs[0];

  const rpaPrevoutHashHex = fundingInput.txid; // Alice’s previous txid
  const rpaPrevoutN       = fundingInput.vout;

  // Alice's pubkey from P2PKH scriptSig <sig> <pubkey>
  const senderPub33 = extractPubKeyFromP2PKHScriptSig(fundingInput.scriptSig);

  const bobScanPriv  = bob.scanPrivBytes  ?? bob.privBytes;
  const bobSpendPriv = bob.spendPrivBytes ?? bob.privBytes;
  const COVENANT_INDEX = 0; // must match funding side

  const { oneTimePriv } = deriveRpaOneTimePrivReceiver(
    bobScanPriv,
    bobSpendPriv,
    senderPub33,
    rpaPrevoutHashHex,
    rpaPrevoutN,
    COVENANT_INDEX,
  );

  const oneTimePub33 = secp256k1.getPublicKey(oneTimePriv, true);

  console.log('\n[3B] Bob reconstructs the covenant-guard one-time key via RPA:');
  console.log('  RPA receiver context:');
  console.log('    - Bob scan & spend secrets (from paycode privs)');
  console.log('    - Alice funding pubkey (from scriptSig)');
  console.log('    - RPA outpoint: prev txid + vout of Alice’s funding input');
  console.log('    - index:', COVENANT_INDEX);
  console.log('  => one-time child pubkey (covenant guard):', bytesToHex(oneTimePub33));
  console.log('  HASH160(one-time pub) must match the guard hash embedded in the covenant.');

  // Bob's HASH160(one-time pub) for covenant recreation
  const bobHash20 = _hash160(oneTimePub33);

  const {
    scriptPubKey: rawPrevScript,
    value: covenantValue,
    token_data: initial_token_data,
  } = await getPrevoutDetails(covenantUtxo.tx_hash, covenantUtxo.tx_pos, network);

  // Reuse the exact serialized on-chain token prefix (if present)
  const prevTokenPrefix = extractTokenPrefixFromScript(rawPrevScript); // null if none

  /* ------------------------------------------------------------------------ */
  /* 2.5) Rebuild ZK envelope and proofHash for covenant anchoring            */
  /* ------------------------------------------------------------------------ */

  // Same deterministic seed as funding side:
  //   seed = sha256(ephemPub33 || uint64le(amount))
  const regenSeed = sha256(concat(ephemPubReceived, uint64le(decryptedAmount)));

  // Rebuild the *core* Sigma proof
  const regenProof = generateSigmaRangeProof(decryptedAmount, regenSeed);
  const regenCoreProofBytes = serializeProof(regenProof);

  const rangeBits = 64;
  const H33 = toCompressed(getH());

  // MUST match funding side:
  const outIndex = Number(covenantUtxo.tx_pos); // MUST match funding side (vout=1)
  const assetId32 = normalizeCategory32(initial_token_data?.category);
  if (assetId32 && assetId32.length !== 32) {
    throw new Error(`token_data.category must be 32 bytes, got ${assetId32.length}`);
  }
  
  console.log('envelope bind outIndex=', outIndex, 'assetId32.len=', assetId32?.length);

  const extraCtx = new Uint8Array(0);

  const regenEnvelope = buildProofEnvelope({
    protocolTag: 'BCH-CT/Sigma64-v1',
    rangeBits,
    ephemPub33: ephemPubReceived,
    H33,
    assetId32,
    outIndex,
    extraCtx,
    coreProofBytes: regenCoreProofBytes,
  });

  const regenProofHash = dhash(regenEnvelope);
  console.log('Rebuilt ZK proofHash for covenant script (hash256(envelope)):',
    bytesToHex(regenProofHash),
  );
  console.log('regenProofHash:', bytesToHex(regenProofHash));
  console.log('prevTokenPrefix:', prevTokenPrefix ? bytesToHex(prevTokenPrefix.slice(0, 1 + 32)) : '<none>');

  /* ------------------------------------------------------------------------ */
  /* 3) Load covenant prevout & verify redeemScript ↔ UTXO P2SH hash          */
  /* ------------------------------------------------------------------------ */
  console.log('\n[3C] Loading covenant UTXO and matching its P2SH script:');
  console.log('Spending covenant prevout:', covenantUtxo.tx_hash, covenantUtxo.tx_pos);

  if (prevTokenPrefix) {
    console.log('COVENANT prevTokenPrefix (hex):', bytesToHex(prevTokenPrefix));
  }

  console.log(
    'Input token_data:',
    JSON.stringify(
      initial_token_data,
      (k, v) =>
        v instanceof Uint8Array ? bytesToHex(v) : typeof v === 'bigint' ? v.toString() : v,
      2
    )
  );

  // createCovenant expects Bob's HASH160(one-time pub) and the ZK proofHash anchor
  const { covenantBytecode, covenantScript: expectedP2SH } =
    createCovenant(bobHash20, regenProofHash);
  const redeemScript = covenantBytecode; // this is the actual redeem script (bytecode)
  console.log('Redeem Script (hex):', bytesToHex(redeemScript));
  console.log('RedeemScript H160:', bytesToHex(_hash160(redeemScript)));
  console.log('Expected P2SH tail (OP_HASH160 <20> OP_EQUAL):', bytesToHex(expectedP2SH));

  console.log(
    'Actual UTXO P2SH script tail (slice -23):',
    bytesToHex(rawPrevScript.slice(-23))
  );

  if (!arraysEqual(rawPrevScript.slice(-23), expectedP2SH)) {
    throw new Error('RedeemScript does not match UTXO script hash');
  }
  console.log('✅ RedeemScript matches UTXO P2SH hash (covenant guard confirmed)');

  /* ------------------------------------------------------------------------ */
  /* 4) Pick Bob fee UTXO, derive RPA address to Alice, & estimate fees       */
  /* ------------------------------------------------------------------------ */

  console.log('\n[4A] Selecting Bob’s fee input and deriving RPA address for Alice:');
  const bobUtxo = await consolidateUtxos(bob.address, bob.privBytes, network, true);
  if (!bobUtxo) throw new Error('Bob needs a UTXO for fees');

  console.log('Bob fee UTXO:');
  console.log('  - txid :', bobUtxo.txid);
  console.log('  - vout :', bobUtxo.vout);
  console.log('  - value:', bobUtxo.value, 'sats');

  // RPA sender: use Bob's base priv + his P2PKH fee input outpoint
  const alicePayPub = extractPubKeyFromPaycode(alicePaycode); // 33-byte pub from Alice paycode
  const bobInputPrivBytes = bob.privBytes;                     // sender secret e
  const rpaReturnPrevoutHashHex = bobUtxo.txid;                // prevout txid
  const rpaReturnPrevoutN       = bobUtxo.vout;                // prevout index

  // Phase-1: we treat this as a stealth P2PKH payment from Bob → Alice,
  // even though it is currently used as "return change" in the covenant demo.
  // Phase-2: the same RPA intent can front a PQ vault instead of a bare P2PKH script.
  const rpaIntent = deriveRpaLockIntent({
    mode: RPA_MODE_STEALTH_P2PKH,
    senderPrivBytes: bobInputPrivBytes,
    receiverPub33: alicePayPub,
    prevoutTxidHex: rpaReturnPrevoutHashHex,
    prevoutN: rpaReturnPrevoutN,
    index: 0,
  });

  const { address: rpaAddr, childHash160, session } = rpaIntent;

  console.log('  RPA sender context:');
  console.log('    - sender priv e (Bob’s fee input key)');
  console.log('    - receiver scan/spend Q/R (Alice paycode pubkey)');
  console.log('    - outpoint = Bob fee UTXO (txid:vout)');
  console.log('    - index   = 0');
  console.log('  => RPA-derived one-time address for Alice: ', rpaAddr);
  console.log('  => HASH160(one-time pubkey): ', bytesToHex(childHash160));
  console.log('  (This address is unlinkable from Alice’s base wallet or static paycode.)');
  console.log('  RPA sender context:');
  console.log('    - sender priv e (Bob’s fee input key)');
  console.log('    - receiver scan/spend Q/R (Alice paycode pubkey)');
  console.log('    - outpoint = Bob fee UTXO (txid:vout)');
  console.log('    - index   = 0');
  console.log('  => RPA-derived one-time address for Alice: ', rpaAddr);
  console.log('  => HASH160(one-time pubkey): ', bytesToHex(childHash160));
  console.log('  (This address is unlinkable from Alice’s base wallet or static paycode.)');

  // Phase-1: session.zkSeed is used for the confidential asset proof.
  // Phase-2: the same zkSeed (possibly mixed with extraCtx) will seed PQ vault randomness.
  const aliceDerivedHash160 = childHash160;

  // For Alice’s reconstruction later
  const rpaSenderContext = {
    senderPrivBytes: bobInputPrivBytes,
    prevoutHashHex: rpaReturnPrevoutHashHex,
    prevoutN: rpaReturnPrevoutN,
  };

  const rate = await getFeeRate();
  console.log('\n[4B] Fee estimation and change planning:');
  console.log('Dynamic Fee rate:', rate, 'sat/byte');

  const totalInput = Number(covenantValue) + bobUtxo.value;

  // Reuse exact token prefix (if any) on vout0 → Alice
  const aliceP2PKH = getP2PKHScript(aliceDerivedHash160);
  const vout0Script = prevTokenPrefix ? concat(prevTokenPrefix, aliceP2PKH) : aliceP2PKH;

  // One-pass size estimator (with/without change)
  const estimateOnce = (withChange) => {
    const outputs = [
      { value: decryptedAmount, scriptPubKey: vout0Script },
      ...(withChange ? [{ value: 0, scriptPubKey: getP2PKHScript(bob.hash160) }] : []),
    ];

    const tempTx = {
      version: 1,
      inputs: [
        {
          txid: covenantUtxo.tx_hash,
          vout: covenantUtxo.tx_pos,
          sequence: 0xffffffff,
          scriptSig: new Uint8Array(),
        },
        {
          txid: bobUtxo.txid,
          vout: bobUtxo.vout,
          sequence: 0xffffffff,
          scriptSig: new Uint8Array(),
        },
      ],
      outputs,
      locktime: 0,
    };

    const amountBytes = minimalScriptNumber(BigInt(decryptedAmount));
    const amountPush = pushDataPrefix(amountBytes.length).length + amountBytes.length;

    const sigPush = pushDataPrefix(65).length + 65;
    const pubPush = pushDataPrefix(33).length + 33;
    const redeemPush = pushDataPrefix(redeemScript.length).length + redeemScript.length;
    const expectedCovenantSigSize = amountPush + pubPush + sigPush + redeemPush;

    const expectedP2SigSize = 1 + 65 + 1 + 33;

    const hex = buildRawTx(tempTx);
    const baseSize = hex.length / 2;
    const totalEstSize = baseSize + expectedCovenantSigSize + expectedP2SigSize;
    const fee = Math.ceil(totalEstSize * rate);

    return { fee, totalEstSize };
  };

  let { fee, totalEstSize } = estimateOnce(false);
  console.log('Estimated TX size (no change):', totalEstSize, 'bytes');
  console.log('Estimated fee (no change):', fee, 'sat');

  let change = totalInput - decryptedAmount - fee;

  if (change >= DUST) {
    console.log('\n[4C] Bob change output:');
    console.log('  - value:', change, 'sats');
    console.log('  - destination: Bob’s base wallet P2PKH');
    console.log('  (A wallet could later use self-RPA here to keep change unlinkable.)');
    const est = estimateOnce(true);
    fee = est.fee;
    console.log('Re-estimated TX size (with change):', est.totalEstSize, 'bytes');
    console.log('Re-estimated fee (with change):', fee, 'sat');
    change = totalInput - decryptedAmount - fee;
  }

  if (change < 0) throw new Error('Insufficient funds for fee and covenant amount');

  if (change > 0 && change < DUST) {
    fee += change;
    change = 0;
    console.log('Change below dust; burning via increased fee:', fee, 'sats');
  }

  let bobChangeScript = null;
  if (change >= DUST) {
    bobChangeScript = getP2PKHScript(bob.hash160);
  }

  /* ------------------------------------------------------------------------ */
  /* 5) Assemble final TX object                                              */
  /* ------------------------------------------------------------------------ */
  const tx = {
    version: 1,
    inputs: [
      {
        txid: covenantUtxo.tx_hash,
        vout: covenantUtxo.tx_pos,
        sequence: 0xffffffff,
        scriptSig: new Uint8Array(),
      },
      {
        txid: bobUtxo.txid,
        vout: bobUtxo.vout,
        sequence: 0xffffffff,
        scriptSig: new Uint8Array(),
      },
    ],
    outputs: [{ value: decryptedAmount, scriptPubKey: vout0Script }],
    locktime: 0,
  };

  if (change >= DUST) {
    tx.outputs.push({ value: change, scriptPubKey: bobChangeScript });
  }

  const actualTotalOutput = tx.outputs.reduce((sum, o) => sum + o.value, 0);
  if (actualTotalOutput !== totalInput - fee) {
    throw new Error(
      `TX does not balance: expected ${totalInput - fee}, got ${actualTotalOutput}`
    );
  }

  console.log('\n[4D] Final Bob → Alice RPA transaction layout:');
  console.log('  input[0]: covenant P2SH (unlocked by RPA-derived one-time key)');
  console.log('  input[1]: Bob fee P2PKH (links tx to Bob’s base wallet via standard heuristics)');
  console.log('  output[0]: NFT + amount to Alice’s RPA-derived one-time address');
  if (change >= DUST) {
    console.log('  output[1]: change to Bob base wallet P2PKH');
  } else {
    console.log('  (no change output; any tiny remainder burned in fees)');
  }

  console.log('amountCommitment (decryptedAmount):', decryptedAmount);
  console.log('tx.outputs[0].value:', tx.outputs[0].value);
  console.log('Output scriptPubKey (hex):', bytesToHex(tx.outputs[0].scriptPubKey));

  /* ------------------------------------------------------------------------ */
  /* 6) Covenant introspection expectations & local guards                    */
  /* ------------------------------------------------------------------------ */
  const expectedBobHash20 = extractLeadingPush20(redeemScript);
  const actualBobHash20 = _hash160(oneTimePub33);

  console.log('\n[4E] Covenant introspection preview (local mirror checks):');
  console.log('  hash160(one-time pub):         ', bytesToHex(actualBobHash20));
  if (expectedBobHash20) {
    console.log('  payHash20 in redeemScript:     ', bytesToHex(expectedBobHash20));
    if (!arraysEqual(expectedBobHash20, actualBobHash20)) {
      throw new Error(
        [
          'redeemScript payHash20 mismatch:',
          `  expected=${bytesToHex(expectedBobHash20)}`,
          `  actual=${bytesToHex(actualBobHash20)}`,
        ].join('\n')
      );
    }
  } else {
    console.warn('  No 20-byte payHash found at script start; skipping pk-hash guard.');
  }

  console.log('  The on-chain covenant will introspect the transaction and enforce:');
  console.log('    - HASH160(one-time pubkey) matches the embedded guard hash;');
  console.log('    - OUTPUTVALUE(0) equals the amount pushed by the unlocker.');
  console.log('  Here we mirror those checks locally via assertCovenantWillPassEqVerifies().');

  assertCovenantWillPassEqVerifies({
    redeemScript,
    payPub33: oneTimePub33,
    vout0Value: tx.outputs[0].value,
    decryptedAmount,
  });

  /* ------------------------------------------------------------------------ */
  /* 7) Sign inputs                                                           */
  /* ------------------------------------------------------------------------ */
  const covenantInputIndex =
    tx.inputs.findIndex(i => i.txid === covenantUtxo.tx_hash && i.vout === covenantUtxo.tx_pos);

  if (covenantInputIndex < 0) throw new Error('Covenant input not found in tx');

  signCovenantInput(
    tx,
    covenantInputIndex,
    oneTimePriv,
    redeemScript,
    covenantUtxo.value,
    rawPrevScript,
    decryptedAmount
  );

  const bobInputScriptCode = getP2PKHScript(bob.hash160);
  signInput(tx, 1, bob.privBytes, bobInputScriptCode, bobUtxo.value);

  const sigScript = tx.inputs[covenantInputIndex].scriptSig;
  console.log('Covenant unlocking script length (bytes):', sigScript.length);
  console.log('\n[4F] Inputs used in Bob → Alice RPA return tx:');
  console.log('  - input 0: covenant P2SH, signed by RPA-derived one-time key (unlinkable from base keys)');
  console.log('  - input 1: Bob’s P2PKH fee input, signed with Bob’s base wallet key');

  /* ------------------------------------------------------------------------ */
  /* 8) Broadcast                                                             */
  /* ------------------------------------------------------------------------ */
  const txHex = buildRawTx(tx);
  console.log('Bob Return TX Hex:', txHex);

  const returnTxId = await broadcastTx(txHex, network);

  console.log('\n✅ Bob returned funds (NFT + amount) to Alice via RPA one-time address:');
  console.log('  txid:', returnTxId);
  console.log('Verifying covenant enforcement:');
  console.log('  - On-chain, the covenant introspection ensures the guard hash and vout[0] value match');
  console.log('  - Off-chain, we ran the same equality checks before signing.');

  return { returnTxId, rpaSenderContext };
}

/** Extract the exact serialized token prefix from a scriptPubKey (if present) */
function extractTokenPrefixFromScript(spk /* Uint8Array */) {
  if (!spk || spk.length < 23) return null;
  // tokenized P2SH/P2PKH: <prefix..> OP_HASH160 <20> OP_EQUAL
  if (spk[0] !== 0xef) return null;
  return spk.slice(0, spk.length - 23);
}

/**
 * Build a spend transaction from Alice's paycode-derived (RPA) output
 * back to her source wallet.
 *
 *   input:  P2PKH with CashTokens prefix (Alice's one-time RPA-derived key)
 *   output: Alice's original P2PKH (source wallet)
 */
export async function buildAliceRpaSpendTx(
  derivedPrivBytes,  // 32-byte Uint8Array: one-time spending key
  prevTxId,          // string: paycode-derived UTXO txid (BE hex)
  prevVout,          // number: paycode-derived UTXO index
  prevValue,         // number|bigint: paycode-derived UTXO value in sats
  prevTokenPrefix,   // Uint8Array|null: token prefix from vout[0]
  aliceHash160,      // Uint8Array(20): Alice's original P2PKH hash
  network,
) {
  if (!(derivedPrivBytes instanceof Uint8Array) || derivedPrivBytes.length !== 32) {
    throw new Error('derivedPrivBytes must be a 32-byte Uint8Array');
  }

  console.log('\n--- [5] Alice spends RPA one-time UTXO back to her source wallet ---');
  console.log('Prev derived RPA UTXO:');
  console.log('  - txid :', prevTxId);
  console.log('  - vout :', prevVout);
  console.log('  - value:', prevValue, 'sats');
  console.log('  (This is the RPA-derived address Bob paid to, not Alice’s base wallet.)');

  const rate = await getFeeRate();
  console.log('Dynamic fee rate for spend:', rate, 'sat/byte');

  // 1) Derive one-time pubkey & its P2PKH scriptCode (no token prefix)
  const derivedPub33 = secp256k1.getPublicKey(derivedPrivBytes, true);
  const derivedHash160 = _hash160(derivedPub33);
  const derivedScriptCode = getP2PKHScript(derivedHash160); // scriptCode for sighash

  console.log('[5A] One-time RPA spending key:');
  console.log('  derived child pubkey:', bytesToHex(derivedPub33));
  console.log('  HASH160(derived pub):', bytesToHex(derivedHash160));
  console.log('  (Externally, this just looks like a normal P2PKH key.)');

  // 2) Destination: Alice base P2PKH with SAME token prefix (if any)
  const baseDestScript = getP2PKHScript(aliceHash160);
  const destScript =
    prevTokenPrefix && prevTokenPrefix.length
      ? concat(prevTokenPrefix, baseDestScript)
      : baseDestScript;

  if (prevTokenPrefix && prevTokenPrefix.length) {
    console.log('[5B] Preserving token prefix (NFT category/commitment) on spend:');
    console.log('  token prefix (hex):', bytesToHex(prevTokenPrefix));
    console.log('  output script: token prefix + P2PKH(Alice base hash160)');
  } else {
    console.log('[5B] No token prefix on input; simple BCH P2PKH spend to Alice base wallet.');
  }

  // 3) Fee estimate
  const dummyScriptSig = new Uint8Array(1 + 65 + 1 + 33); // <PUSH 65><sig65><PUSH 33><pub33>
  const estSize =
    4 +                               // version
    1 +                               // input count
    32 + 4 + 1 + dummyScriptSig.length + 4 + // input
    1 +                               // output count
    8 + 1 + destScript.length +       // output
    4;                                // locktime

  const fee = Math.ceil(estSize * rate) + 10; // safety margin
  console.log('[5C] Estimated TX size:', estSize, 'bytes');
  console.log('     Estimated fee    :', fee, 'sats');

  const sendValueBig = BigInt(prevValue) - BigInt(fee);
  if (sendValueBig <= BigInt(DUST)) {
    throw new Error(
      `paycode-derived RPA output too small to pay fee cleanly: prevValue=${prevValue}, ` +
        `fee≈${fee}, result=${sendValueBig.toString()}`
    );
  }
  const sendValue = Number(sendValueBig);
  console.log('Alice will receive back (minus fee):', sendValue, 'sats');
  console.log('Destination: Alice base P2PKH (original source wallet).');

  const tx = {
    version: 1,
    inputs: [
      {
        txid: prevTxId,
        vout: prevVout,
        sequence: 0xffffffff,
        scriptSig: new Uint8Array(),
      },
    ],
    outputs: [
      {
        value: sendValue,
        scriptPubKey: destScript,
      },
    ],
    locktime: 0,
  };

  const sigHashType = 0x41; // SIGHASH_ALL | FORKID
  const preimage = getPreimage(
    tx,
    0,
    derivedScriptCode,
    prevValue,
    sigHashType,
    prevTokenPrefix
  );
  const sighash = sha256(sha256(preimage));

  console.log('\n[5D] Token-aware sighash preimage & signature:');
  console.log('Spend preimage hex:', Buffer.from(preimage).toString('hex'));
  console.log('Spend sighash  hex:', Buffer.from(sighash).toString('hex'));

  const sig64 = bchSchnorrSign(sighash, derivedPrivBytes, derivedPub33);
  const sig65 = concat(sig64, Uint8Array.of(sigHashType));

  if (!bchSchnorrVerify(sig65, sighash, derivedPub33)) {
    console.error('RPA-derived spend verify failed');
    throw new Error('Local Schnorr verification failed for paycode-derived RPA spend');
  }

  const scriptSig = concat(
    pushDataPrefix(sig65.length),
    sig65,
    pushDataPrefix(derivedPub33.length),
    derivedPub33
  );
  tx.inputs[0].scriptSig = scriptSig;

  console.log('\n[5E] Final RPA spend layout:');
  console.log('  input[0]: one-time P2PKH key derived via RPA (child of Alice paycode)');
  console.log('  output[0]: Alice base P2PKH + original token prefix (if any)');
  console.log('  From the chain’s POV this is indistinguishable from a normal tokenized P2PKH spend.');

  const txHex = buildRawTx(tx);
  console.log('\nAlice paycode-derived → source TX hex:', txHex);

  const txId = await broadcastTx(txHex, network);
  console.log('✅ Broadcast Alice paycode-derived → source TX:', txId);
  return txId;
}