/**
 * Phase-1 PZ-SQH demo entrypoint.
 *
 * This CLI ties together the full confidential-asset + RPA flow:
 *   0. Base wallet + paycode generation for Alice and Bob.
 *   1. Alice → covenant: lock NFT + amount under an RPA-derived Bob-only guard key.
 *   2. Bob → Alice: return NFT + amount to an RPA-derived child of Alice's paycode.
 *   3. Alice → Alice: spend the RPA child output back to her base wallet.
 *
 * The goal here is pedagogy and traceability:
 *   - logs are intentionally verbose,
 *   - every derivation step is printed,
 *   - and the three transactions can be inspected in a block explorer.
 *
 * Future phases (PSBT/HW, PQ vaults) will reuse this CLI framing but swap
 * in additional checks (e.g. proof-hash verification on hardware) or new
 * back-end vault scripts, without changing the RPA layer.
 */

import { Command } from 'commander';
import { randomBytes } from 'crypto';
import { consolidateUtxos, splitTokenPrefix } from './tx.js';
import { encodeCashAddr } from './cashaddr.js';
import { getTipHeader, connectElectrum, getTxDetails } from './electrum.js';
import {
  _hash160,
  hexToBytes,
  bytesToHex,
  reverseBytes,
  sha256,
  concat,
  bytesToBigInt,
  decodeVarInt,
  uint64le,
  arraysEqual,
  extractPubKeyFromPaycode,
} from './utils.js';
import { NETWORK, DUST } from './config.js';
import { getWallets } from './wallets.js';
import { setupPaycodesAndDerivation } from './paycodes.js';
import { createToken, validateTokenCategory } from './tokens.js';
import { createCovenant } from './covenants.js';
import {
  buildAliceSendTx,
  buildBobReturnTx,
  getHash160FromAddress,
  buildAliceRpaSpendTx,
} from './send_return.js';
import {
  encryptAmount,
  decryptAmount,
  deriveRpaOneTimePrivReceiver,
  deriveRpaLockIntent,
  RPA_MODE_CONF_ASSET,
  RPA_MODE_STEALTH_P2PKH,
  RPA_MODE_PQ_VAULT,
} from './derivation.js';
import { deriveEphemeralKeypair } from './ephemeral.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  buildAmountProofEnvelope,
  generateSigmaRangeProof,
  serializeProof,
  computeProofHash,
  BITS,
} from './zk.js';
import {
  makeRpaContextV1FromHex,
  attachRpaContextToPsbtOutput,
  attachProofHashToPsbtOutput,
  attachZkSeedToPsbtOutput,
  RpaModeId,
} from './psbt_rpa.js';
import { promptFundAddress } from './prompts.js';
import { demoPoolHashFold } from './pool_hash_fold_demo.js';
import { POOL_HASH_FOLD_VERSION } from './pool_hash_fold_script.js';

function logSection(title) {
  console.log('\n' + '═'.repeat(70));
  console.log(`🔹 ${title}`);
  console.log('═'.repeat(70));
}

function shortenPaycode(pc) {
  if (!pc) return '';
  if (pc.length <= 20) return pc;
  // e.g. PM8TJQi7puEN... style
  return pc.slice(0, 20) + '...';
}

function normalizeRpaMode(rawMode) {
  const v = (rawMode || '').toString().toLowerCase();

  if (v === 'conf' || v === 'conf-asset' || v === 'confidential-asset') {
    return RPA_MODE_CONF_ASSET;
  }
  if (v === 'stealth' || v === 'stealth-p2pkh') {
    return RPA_MODE_STEALTH_P2PKH;
  }
  if (v === 'pq' || v === 'pq-vault' || v === 'pq_vault') {
    return RPA_MODE_PQ_VAULT;
  }

  console.warn(
    `Unrecognized --mode '${rawMode}', defaulting to '${RPA_MODE_CONF_ASSET}'`,
  );
  return RPA_MODE_CONF_ASSET;
}

async function ensureFundedUtxo(address, privBytes, label, optional = false) {
  let utxo;

  try {
    utxo = await consolidateUtxos(address, privBytes, NETWORK, optional);
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    if (!msg.includes('No UTXOs')) {
      throw e; // real error, not "empty wallet"
    }
  }

  if (utxo) return utxo;

  // No UTXOs yet – ask the user to fund this wallet.
  console.log(`\n[${label}] No UTXOs found on-chain yet.`);
  await promptFundAddress(address);

  // Retry once after the user hits Enter.
  try {
    utxo = await consolidateUtxos(address, privBytes, NETWORK, optional);
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    if (!msg.includes('No UTXOs')) {
      throw e;
    }
  }

  if (!utxo) {
    throw new Error(
      `Still no UTXOs detected for ${label} after funding. ` +
        `Check the chipnet explorer, confirm the transaction, and try again.`,
    );
  }

  return utxo;
}

/**
 * Print a human-readable Phase 1 summary at the end of the demo.
 */
function printPhase1Report({
  aliceAddress,
  alicePaycode,
  bobAddress,
  bobPaycode,
  fundingTxId,
  returnTxId,
  rpaSpendTxId,
  aliceRpaAddress, // paycode-derived one-time receive addr (Bob → Alice)
}) {
  console.log('\n=== Phase 1: Paycode → Covenant → RPA Return Demo (PZ-SQH) ===\n');

  console.log('[0] Base wallets and paycodes');
  console.log('  Alice base wallet: ', aliceAddress);
  console.log('  Alice paycode:     ', shortenPaycode(alicePaycode));
  console.log('  Bob base wallet:   ', bobAddress);
  console.log('  Bob paycode:       ', shortenPaycode(bobPaycode));
  console.log('');
  console.log('  (Paycodes are static identifiers derived from each wallet’s pubkey.');
  console.log('   They are never used directly on-chain; each payment uses a fresh child address.)');
  console.log('');

  console.log('[1] Alice → covenant: lock NFT + amount under Bob-only guard');
  console.log('  - Input[0]: from Alice base wallet (this UTXO could come from CashFusion).');
  console.log('  - Output[0]: small marker → Bob base wallet (optional, for explorer UX).');
  console.log('  - Output[1]: NFT + 100000 sats → covenant lock');
  console.log('      • Guard key: one-time child derived from Bob’s paycode (RPA receiver side).');
  console.log('  - Output[2]: change → Alice base wallet (no paycode-change yet in Phase 1).');
  console.log('');
  console.log('  Funding txid:');
  console.log('    ' + fundingTxId);
  console.log('');

  console.log('[2] Bob → Alice: return NFT + amount to a paycode-derived one-time address');
  console.log('  - Bob decrypts encrypted amount from Alice: 100000 sats.');
  console.log('  - Bob reconstructs the covenant guard key using:');
  console.log('      • his paycode secrets (scan/spend),');
  console.log('      • Alice’s funding pubkey,');
  console.log('      • the funding input outpoint,');
  console.log('      • index = 0.');
  console.log('');
  console.log('  - Inputs:');
  console.log('      input[0]: covenant P2SH (unlocked by Bob’s one-time child key)');
  console.log('      input[1]: Bob fee UTXO from his base wallet: ' + bobAddress);
  console.log('');
  console.log('  - Outputs:');
  console.log('      output[0]: NFT + 100000 sats → one-time address from Alice’s paycode');
  console.log('                 ' + aliceRpaAddress);
  console.log('      output[1]: change → Bob base wallet: ' + bobAddress);
  console.log('');
  console.log('  Return txid:');
  console.log('    ' + returnTxId);
  console.log('');
  console.log('  Note:');
  console.log('    The address Alice receives is not her base wallet address and not her paycode.');
  console.log('    It’s a fresh child address derived from:');
  console.log('      - Bob’s sender key (fee input),');
  console.log('      - Alice’s paycode pubkey,');
  console.log('      - Bob’s fee outpoint,');
  console.log('      - index = 0.');
  console.log('    To an outside observer, it looks like a random P2PKH token address.');
  console.log('');

  console.log('[3] Alice → Alice: spend the RPA-derived output back to her source wallet');
  console.log('  - Alice recognizes Bob’s payment as hers by scanning with her paycode keys.');
  console.log('  - She derives the matching one-time private key and spends that UTXO.');
  console.log('');
  console.log('  - Input[0]: one-time P2PKH child from Alice paycode');
  console.log('              (same address as TX [2] output[0])');
  console.log('  - Output[0]: Alice base wallet:');
  console.log('               ' + aliceAddress);
  console.log('');
  console.log('  RPA spend txid:');
  console.log('    ' + rpaSpendTxId);
  console.log('');

  console.log('[4] UTXO consolidation (internal)');
  console.log('  - Along the way, the demo may consolidate Alice or Bob’s UTXOs into');
  console.log('    a single input to simplify the flow.');
  console.log('  - This is an internal wallet hygiene step; it does not affect the paycode logic.');
  console.log('');

  console.log('Explorer links:');
  console.log('  [1] Alice → covenant:');
  console.log('      https://chipnet.chaingraph.cash/tx/' + fundingTxId);
  console.log('  [2] Bob → Alice (paycode-derived child address):');
  console.log('      https://chipnet.chaingraph.cash/tx/' + returnTxId);
  console.log('  [3] Alice (RPA child) → Alice (base wallet):');
  console.log('      https://chipnet.chaingraph.cash/tx/' + rpaSpendTxId);
  console.log('');
}

/* -------------------------------------------------------------------------- */
/* Basic TX parsing helpers                                                   */
/* -------------------------------------------------------------------------- */

function parseRawTx(txHex) {
  const bytes = hexToBytes(txHex);
  let pos = 0;

  const version = bytesToBigInt(reverseBytes(bytes.slice(pos, pos + 4)));
  pos += 4;

  const inputCountInfo = decodeVarInt(bytes, pos);
  pos += inputCountInfo.length;
  const inputCount = inputCountInfo.value;

  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    const txid = bytesToHex(reverseBytes(bytes.slice(pos, pos + 32)));
    pos += 32;
    const vout = Number(bytesToBigInt(reverseBytes(bytes.slice(pos, pos + 4))));
    pos += 4;

    const scriptSigSizeInfo = decodeVarInt(bytes, pos);
    pos += scriptSigSizeInfo.length;
    const scriptSig = bytes.slice(pos, pos + scriptSigSizeInfo.value);
    pos += scriptSigSizeInfo.value;

    const sequence = bytesToBigInt(reverseBytes(bytes.slice(pos, pos + 4)));
    pos += 4;

    inputs.push({ txid, vout, scriptSig, sequence });
  }

  const outputCountInfo = decodeVarInt(bytes, pos);
  pos += outputCountInfo.length;
  const outputCount = outputCountInfo.value;

  const outputs = [];
  for (let i = 0; i < outputCount; i++) {
    const value = bytesToBigInt(reverseBytes(bytes.slice(pos, pos + 8)));
    pos += 8;

    const scriptSizeInfo = decodeVarInt(bytes, pos);
    pos += scriptSizeInfo.length;

    const scriptPubKey = bytes.slice(pos, pos + scriptSizeInfo.value);
    pos += scriptSizeInfo.value;

    let token_data = null;
    if (scriptPubKey[0] === 0xef) {
      token_data = parseTokenPrefix(scriptPubKey);
    }
    outputs.push({ value, scriptPubKey, token_data });
  }

  const locktime = bytesToBigInt(reverseBytes(bytes.slice(pos, pos + 4)));
  pos += 4;

  return { version, inputs, outputs, locktime };
}

function parseTokenPrefix(script) {
  let pos = 0;
  if (script[pos] !== 0xef) return null;
  pos += 1;

  const category = script.slice(pos, pos + 32);
  pos += 32;

  const bitfield = script[pos];
  pos += 1;

  const hasCommitment = (bitfield & 0x40) !== 0;
  const hasNft        = (bitfield & 0x20) !== 0;
  const hasAmount     = (bitfield & 0x10) !== 0;

  const capabilityCode = bitfield & 0x0f;
  const capabilities = ['none', 'mutable', 'minting'];
  const capability = hasNft ? capabilities[capabilityCode] : null;

  let commitment = new Uint8Array(0);
  if (hasCommitment) {
    const commitLenInfo = decodeVarInt(script, pos);
    pos += commitLenInfo.length;
    commitment = script.slice(pos, pos + commitLenInfo.value);
    pos += commitLenInfo.value;
  }

  let amount = 0n;
  if (hasAmount) {
    const amountInfo = decodeVarInt(script, pos);
    pos += amountInfo.length;
    amount = BigInt(amountInfo.value);
  }

  return {
    category,
    nft: hasNft ? { capability, commitment } : undefined,
    amount: hasAmount ? amount : 0n,
  };
}

/**
 * Locate the covenant UTXO from Alice's funding TX.
 * We prefer the NFT-bearing output; fallback is a hard-coded value match.
 */
async function getCovenantUtxoFromTxId(txId, network) {
  const client = await connectElectrum(network);
  try {
    const txHex = await client.request('blockchain.transaction.get', txId);
    const txDetails = parseRawTx(txHex);

    let covenantOutput = txDetails.outputs.find(
      (out) => out.token_data && out.token_data.nft,
    );

    if (!covenantOutput) {
      console.warn(
        'No NFT output found; falling back to value match (assuming 100000 sat)',
      );
      covenantOutput = txDetails.outputs.find(
        (out) => out.value === BigInt(100000),
      );
      if (!covenantOutput) throw new Error('No covenant output found');
    }

    const vout = txDetails.outputs.indexOf(covenantOutput);
    let token_data = covenantOutput.token_data;
    if (!token_data) {
      token_data = parseTokenPrefix(covenantOutput.scriptPubKey);
    }

    return {
      tx_hash: txId,
      tx_pos: vout,
      value: Number(covenantOutput.value),
      token_data,
      script: covenantOutput.scriptPubKey, // full script with token prefix
    };
  } finally {
    await client.disconnect();
  }
}

/* -------------------------------------------------------------------------- */
/* Envelope computation (funding proof)                                      */
/* -------------------------------------------------------------------------- */

function computeFundingEnvelope(
  ephemPub33,
  amount,
  tokenCategory32 = null,
  outIndex = 1,
  extraCtx = new Uint8Array(0),
) {
  if (!(ephemPub33 instanceof Uint8Array) || ephemPub33.length !== 33) {
    throw new Error('ephemPub33 must be a 33-byte compressed pubkey');
  }
  if (typeof amount !== 'number' && typeof amount !== 'bigint') {
    throw new Error('amount must be a non-negative number or bigint');
  }
  const amountBig = BigInt(amount);
  if (amountBig < 0n) {
    throw new Error('amount must be non-negative');
  }

  // Phase-1 CTv1 spec: seed = sha256(ephemPub33 || uint64le(amount))
  const seed = sha256(concat(ephemPub33, uint64le(amountBig)));

  const {
    envelope,
    proofHash,
    coreHashBytes,
    commitmentC33,
  } = buildAmountProofEnvelope({
    value: amountBig,
    zkSeed: seed,
    ephemPub33,
    assetId32: tokenCategory32,
    outIndex,
    extraCtx,
  });

  const proofHashBytes = proofHash;

  console.log('--- Funding Envelope Params ---');
  console.log('ephemPub33:', bytesToHex(ephemPub33));
  console.log('rangeBits:', BITS);
  console.log('outIndex:', outIndex);
  console.log(
    'assetId32:',
    tokenCategory32 ? bytesToHex(tokenCategory32) : 'null',
  );
  console.log('extraCtx.len:', extraCtx.length);
  console.log('coreHash (hash256(coreProofBytes)):', bytesToHex(coreHashBytes));
  console.log('proofHash (hash256(envelope)):', bytesToHex(proofHashBytes));

  return {
    envelope,
    proofHashBytes,
    coreHashBytes,
    commitment33: commitmentC33, // used for NFT commitment
  };
}

/**
 * Stealth P2PKH demo:
 *
 * - No network calls, no covenant, no ZK, no tokens.
 * - Just:
 *    • RPA sender/receiver derivation in STEALTH mode,
 *    • one-time P2PKH-style address,
 *    • amount encryption using encryptAmount/decryptAmount.
 *
 * Intended as an "offline" mode sanity demo.
 */
export async function demoStealthP2PKH() {
  logSection('Stealth P2PKH demo (RPA_MODE_STEALTH_P2PKH)');

  // Local-only keys (NOT persisted, no wallet integration).
  const alicePriv = new Uint8Array(randomBytes(32)); // sender
  const bobScanPriv = new Uint8Array(randomBytes(32));
  const bobSpendPriv = bobScanPriv; // scan/spend folded for demo

  const bobPaycodePub33 = secp256k1.getPublicKey(bobSpendPriv, true);

  // Dummy outpoint context for RPA (never hits the chain in this demo)
  const fakePrevoutTxidHex = bytesToHex(new Uint8Array(randomBytes(32)));
  const fakePrevoutN = 0;
  const index = 0;

  const sendAmount = 123456; // sats (demo)

  // Sender side: derive an RPA lock intent in stealth mode
  const intent = deriveRpaLockIntent({
    mode: RPA_MODE_STEALTH_P2PKH,
    senderPrivBytes: alicePriv,
    receiverPub33: bobPaycodePub33,
    prevoutTxidHex: fakePrevoutTxidHex,
    prevoutN: fakePrevoutN,
    index,
  });

  console.log('Stealth mode: one-time P2PKH-style address (off-chain demo):');
  console.log('  address:', intent.address);
  console.log('  childHash160:', bytesToHex(intent.childHash160));
  console.log('  session.zkSeed:', bytesToHex(intent.session.zkSeed));
  console.log(
    '  (In a real send, this would be the chain-visible address for the BCH output.)',
  );

  // Side-channel amount encryption (ephemeral → Bob static key)
  const ephemPriv = new Uint8Array(randomBytes(32));
  const ephemPub33 = secp256k1.getPublicKey(ephemPriv, true);

  const envelope = encryptAmount(ephemPriv, bobPaycodePub33, sendAmount);
  const decryptedStr = decryptAmount(bobSpendPriv, ephemPub33, envelope);
  const parsed = JSON.parse(decryptedStr);

  if (typeof parsed.v !== 'number') {
    throw new Error('Stealth mode decrypt: expected {"v": <number>}');
  }
  if (parsed.v !== sendAmount) {
    throw new Error(
      `Stealth mode amount mismatch: expected ${sendAmount}, got ${parsed.v}`,
    );
  }

  console.log(
    `✅ Stealth mode amount encryption round-trip succeeded for ${sendAmount} sats.`,
  );
}

/**
 * PQ vault front-door stub demo:
 *
 * - Uses RPA_MODE_PQ_VAULT to derive:
 *    • one-time address,
 *    • PSBT-friendly context,
 *    • session.zkSeed.
 * - Logs these as the future anchor for Quantumroot-style vault scripts.
 * - No chain interaction, no ZK, no tokens – purely a front-end identity demo.
 */
export async function demoPqVaultStub() {
  logSection('PQ vault front-door stub (RPA_MODE_PQ_VAULT)');

  const senderPriv = new Uint8Array(randomBytes(32));
  const receiverPayPriv = new Uint8Array(randomBytes(32));
  const receiverPayPub33 = secp256k1.getPublicKey(receiverPayPriv, true);

  const fakePrevoutTxidHex = bytesToHex(new Uint8Array(randomBytes(32)));
  const fakePrevoutN = 1;
  const index = 0;

  const intent = deriveRpaLockIntent({
    mode: RPA_MODE_PQ_VAULT,
    senderPrivBytes: senderPriv,
    receiverPub33: receiverPayPub33,
    prevoutTxidHex: fakePrevoutTxidHex,
    prevoutN: fakePrevoutN,
    index,
    extraCtx: new Uint8Array(0),
  });

  console.log('PQ vault RPA lock intent (stub, no on-chain vault yet):');
  console.log('  address (placeholder P2PKH):', intent.address);
  console.log('  context:', {
    prevoutTxidHex: intent.context.prevoutTxidHex,
    prevoutN: intent.context.prevoutN,
    index: intent.context.index,
    mode: intent.context.mode,
  });
  console.log('  zkSeed (session):', bytesToHex(intent.session.zkSeed));
  console.log(
    '  (In Phase-2, zkSeed/extraCtx will parameterize the Quantumroot vault script.)',
  );
}

/* --------------------------------------------------------------------------- */
/* Main demo: Alice → covenant → Bob → Alice (RPA), then Alice spends RPA UTXO */
/* --------------------------------------------------------------------------- */

export async function demoSilentTransfer(options = {}) {
  const { exportPsbt = false } = options;
  // Optional: key generation helper
  if (process.env.GENERATE_KEYS === 'true') {
    console.log('Generating/adjusting keys...');
    // This assumes keygen.js is CJS; if you're fully ESM, swap to dynamic import.
    // eslint-disable-next-line global-require
    require('./keygen.js');
    console.log(
      'Keys generated/adjusted. Update env vars and re-run without GENERATE_KEYS=true.',
    );
    return;
  }

  const { alice, bob } = await getWallets();

  let aliceRpaAddress = null;  // will be set when we parse Bob→Alice vout[0]

  // For this demo, use single-key paycodes: scan == spend == base key
  // RPA helper expects separate scan/spend privs, so we alias them.
  alice.scanPrivBytes = alice.scanPrivBytes ?? alice.privBytes;
  alice.spendPrivBytes = alice.spendPrivBytes ?? alice.privBytes;
  bob.scanPrivBytes    = bob.scanPrivBytes ?? bob.privBytes;
  bob.spendPrivBytes   = bob.spendPrivBytes ?? bob.privBytes;

  const { bobPaycode, alicePaycode, derivedAddr } = setupPaycodesAndDerivation(
    alice,
    bob,
    100000,
  );

  // Attach paycodes to wallet objects for Mode B self-change
  alice.paycode = alicePaycode;
  bob.paycode = bobPaycode;

  console.log('Alice paycode:', alicePaycode);
  console.log('Bob paycode:', bobPaycode);

  const derivedHash160 = getHash160FromAddress(derivedAddr);

  // Extract Bob pubkey from paycode for encryption
  const bobPubBytes = extractPubKeyFromPaycode(bobPaycode);
  console.log(
    '✅ Extracted Bob Public Key from Paycode (hex):',
    bytesToHex(bobPubBytes),
  );

  /* ---------------------------------------------------------------------- */
  /* 1) Alice consolidates & prepares funding                               */
  /* ---------------------------------------------------------------------- */

  const aliceUtxo = await ensureFundedUtxo(
    alice.address,
    alice.privBytes,
    'Alice',
    false, // not optional – Alice MUST have a UTXO to run the demo
  );


  // Genesis token category from Alice’s UTXO
  const inputTxHash = hexToBytes(aliceUtxo.txid);
  const categoryBytes = reverseBytes(inputTxHash);
  validateTokenCategory(inputTxHash, categoryBytes);

  const sendAmount = Number(process.env.SEND_AMOUNT ?? 100000); // satoshis

  // 1) Phase-1 ephemeral key for amount encryption, derived via shared helper.
  //    NOTE: no domainTag → bit-for-bit identical to the original inline derivation.
  const {
    ephemPriv: aliceEphemPriv,
    ephemPub: aliceEphemPubBytes,
  } = deriveEphemeralKeypair({
    basePub33: bobPubBytes,
    amount: sendAmount,
    txidHex: aliceUtxo.txid,
    vout: aliceUtxo.vout,
    // domainTag intentionally omitted to preserve Phase-1 behavior
  });

  console.log(
    '🔑 Generated Alice Ephemeral Public Key (hex):',
    bytesToHex(aliceEphemPubBytes),
  );

  // --- RPA-based covenant guard (Alice → Bob) ---

  // Sender key for RPA: use Alice's base wallet key – the same one whose pubkey
  // appears in the P2PKH funding input scriptSig. This lets Bob recover it later.
  const aliceSenderPriv = alice.privBytes;

  // Outpoint for RPA shared secret: the UTXO Alice is spending into the covenant.
  const rpaPrevoutHashHex = aliceUtxo.txid;
  const rpaPrevoutN = aliceUtxo.vout;
  const COVENANT_INDEX = 0; // reserved RPA index for covenant guard

  // Phase-1: treat this as a confidential-asset RPA lock intent.
  // - mode:     covenant + ZK + NFT
  // - sender:   Alice funding key (priv)
  // - receiver: Bob paycode pub (scan/spend folded)
  // - context:  funding input outpoint + index
  const sendIntent = deriveRpaLockIntent({
    mode: RPA_MODE_CONF_ASSET,
    senderPrivBytes: aliceSenderPriv,
    receiverPub33: bobPubBytes,
    prevoutTxidHex: rpaPrevoutHashHex,
    prevoutN: rpaPrevoutN,
    index: COVENANT_INDEX,
  });

  const {
    address: bobOneTimeAddr,
    childPubkey: bobCovGuardPub,
    childHash160: bobCovGuardHash160,
    session: rpaSession,
    context: rpaContext,
  } = sendIntent;

  console.log('\n[2A] Alice derives Bob-only covenant guard key using RPA:');
  console.log('  - Sender priv e (Alice funding key)');
  console.log('  - Receiver scan/spend Q/R (Bob’s paycode pubkey)');
  console.log('  - Outpoint = Alice funding input (txid:vout)');
  console.log('  - Index   =', COVENANT_INDEX);
  console.log('  => child pubkey (Bob covenant guard):', bytesToHex(bobCovGuardPub));
  console.log('  => HASH160(child pubkey) embedded in covenant:', bytesToHex(bobCovGuardHash160));
  console.log('  => one-time P2PKH guard address (Bob side):', bobOneTimeAddr);
  console.log('  RPA context for this covenant output:', {
    mode: rpaContext.mode,
    prevoutTxidHex: rpaContext.prevoutTxidHex,
    prevoutN: rpaContext.prevoutN,
    index: rpaContext.index,
  });
  console.log(
    '  (Chain will only ever see this child pubkey/address, never Bob’s paycode or base wallet pub.)',
  );

  // RPA receiver-side check: Bob reconstructs the same covenant guard key from his seed.
  const aliceSenderPub33 = secp256k1.getPublicKey(aliceSenderPriv, true);
  const { oneTimePriv: bobGuardPriv } = deriveRpaOneTimePrivReceiver(
    bob.scanPrivBytes,
    bob.spendPrivBytes,
    aliceSenderPub33,
    rpaPrevoutHashHex,
    rpaPrevoutN,
    COVENANT_INDEX,
  );
  const bobGuardPubCheck = secp256k1.getPublicKey(bobGuardPriv, true);
  const bobGuardHash160Check = _hash160(bobGuardPubCheck);

  console.log(
    '  [Bob-side check] Derived covenant guard pub from scan/spend & sender pub:',
    bytesToHex(bobGuardPubCheck),
  );
  if (!arraysEqual(bobGuardHash160Check, bobCovGuardHash160)) {
    throw new Error('RPA receiver-side guard key mismatch – RPA derivation broke');
  }
  console.log('  ✅ Bob’s receiver-side RPA derivation matches Alice’s covenant guard key.');

  // Encrypt amount to Bob (ephemeral + Bob static pub)
  const encryptedAmount = encryptAmount(aliceEphemPriv, bobPubBytes, sendAmount);

  /* ---------------------------------------------------------------------- */
  /* 2) Build funding envelope and token                                     */
  /* ---------------------------------------------------------------------- */

  const {
    envelope: fundingEnvelope,
    proofHashBytes,
    coreHashBytes,
    commitment33,
  } = computeFundingEnvelope(
    aliceEphemPubBytes,
    sendAmount,
    categoryBytes, // tokenCategory32 / assetId32
    1,             // outIndex for the covenant output
  );  

  // Create CashToken with commitment from same proof
  const token = createToken(categoryBytes, commitment33);

  // Use H160(child pub) for the covenant’s Bob-only guard
  // and commit proofHashBytes directly inside the covenant script.
  const { covenantBytecode, covenantScript } =
    createCovenant(bobCovGuardHash160, proofHashBytes);

  // Sanity check for Schnorr activation
  const tip = await getTipHeader(NETWORK);
  console.log('Tip Height:', tip.height, 'Timestamp:', tip.timestamp);
  const MTP_SCHNORR = 1557921600n;
  const tipTs =
    typeof tip.timestamp === 'bigint'
      ? tip.timestamp
      : BigInt(tip.timestamp ?? 0);
  if (tipTs < MTP_SCHNORR) {
    throw new Error(
      'Schnorr not activated on this network (MTP < 1557921600). ' +
        'Switch to testnet or chipnet in config.js.',
    );
  }

  /* ---------------------------------------------------------------------- */
  /* 3) Alice funds the covenant                                            */
  /* ---------------------------------------------------------------------- */

  const sendTxId = await buildAliceSendTx(
    alice,
    aliceUtxo,
    derivedHash160,
    covenantScript,
    token,
    sendAmount,
    DUST,
    alice.hash160,
    alice.privBytes,
    NETWORK,
  );

  const fundingTxId = sendTxId; // for clarity in the final report

  console.log('\n[2B] Alice → covenant funding transaction');
  console.log('✅ Alice funded covenant TX:', sendTxId);
  console.log('  vout[0]: dust → Bob base address (explorer-friendly marker)');
  console.log('  vout[1]: 100000 sats → covenant P2SH + CashToken NFT');
  console.log('  vout[2]: change → Alice base wallet address (no RPA self-change yet)');
  console.log('  (In next phases, solution to shield change address will be developed.)');

  // ------------------------------------------------------------------------
  // Optional: PSBT-like RPA export for the covenant funding output (vout[1])
  // ------------------------------------------------------------------------
  if (exportPsbt) {
    // RPA context for the Bob-only covenant guard key (Alice → covenant).
    const rpaCtxV1 = makeRpaContextV1FromHex({
      mode: RpaModeId.CONF_ASSET,
      index: rpaContext.index,
      prevoutVout: rpaContext.prevoutN,
      prevoutTxidHex: rpaContext.prevoutTxidHex,
      // Sender is Alice's funding pubkey (appears in input[0] scriptSig).
      senderPubkeyHex: bytesToHex(aliceSenderPub33),
    });

    // Minimal PSBT-like structure: we only care about outputs + unknownKeyVals.
    //  - outputs[0] = marker to Bob
    //  - outputs[1] = covenant P2SH + NFT (our RPA/conf-asset focus)
    //  - outputs[2] = Alice change
    const psbtLike = {
      network: NETWORK,
      fundingTxId: sendTxId,
      outputs: [{}, {}, {}],
    };

    // Attach RPA context + proofHash + zkSeed to the covenant output (index 1).
    attachRpaContextToPsbtOutput(psbtLike, 1, rpaCtxV1);
    attachProofHashToPsbtOutput(psbtLike, 1, proofHashBytes);
    attachZkSeedToPsbtOutput(psbtLike, 1, rpaSession.zkSeed);

    // Pretty-print with Buffers/Uint8Arrays rendered as hex.
    const psbtJson = JSON.stringify(
      psbtLike,
      (key, value) => {
        if (value && typeof value === 'object') {
          // unknownKeyVals: show key/value as hex strings
          if (key === 'unknownKeyVals' && Array.isArray(value)) {
            return value.map((kv) => ({
              keyHex: bytesToHex(kv.key),
              valueHex: bytesToHex(kv.value),
            }));
          }
          // Buffers/Uint8Arrays → hex
          if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
            return bytesToHex(value);
          }
        }
        return value;
      },
      2,
    );

    console.log('\n[PSBT-RPA draft export for covenant funding output]');
    console.log(psbtJson);
    console.log(
      '\n(Note: this is a PSBT-like JSON with proprietary RPA fields; ' +
        'Phase-1.5 will later map this into a full BIP-174 PSBT for Seedcash / HW signers.)\n',
    );
  }

  const txDetails = await getTxDetails(sendTxId, NETWORK);

  /* ---------------------------------------------------------------------- */
  /* 4) Off-chain: Bob receives ephemPub + ciphertext & decrypts amount     */
  /* ---------------------------------------------------------------------- */

  const ephemPubReceived = aliceEphemPubBytes;
  const encryptedAmountReceived = encryptedAmount;

  let decryptedAmountStr;
  let decryptedAmount;
  try {
    decryptedAmountStr = decryptAmount(
      bob.privBytes,
      ephemPubReceived,
      encryptedAmountReceived,
    );
    console.log('Decrypted raw string:', decryptedAmountStr);
    const parsed = JSON.parse(decryptedAmountStr);
    if (typeof parsed.v !== 'number') {
      throw new Error('Invalid decrypted format (expected {"v": <number>})');
    }
    decryptedAmount = parsed.v;
    console.log('Decrypted amount:', decryptedAmount);
  } catch (err) {
    console.error('Decryption failed:', err);
    throw err;
  }

  // Bob consolidates his UTXOs (for fees)
  // We don't actually use the specific UTXO here – this just ensures Bob is funded.
  await ensureFundedUtxo(
    bob.address,
    bob.privBytes,
    'Bob',
    true, // optional consolidation mode (your existing behavior)
  );

  /* ---------------------------------------------------------------------- */
  /* 5) Locate covenant UTXO on-chain                                       */
  /* ---------------------------------------------------------------------- */

  const fullCovenantScript = txDetails.outputs[1].scriptPubKey; // covenant + token prefix
  const covenantUtxo = await getCovenantUtxoFromTxId(sendTxId, NETWORK);

  /* ---------------------------------------------------------------------- */
  /* 6) Bob re-generates proof off-chain for his own verification           */
  /* ---------------------------------------------------------------------- */

  /* ---------------------------------------------------------------------- */
  /* 6) Bob re-generates proof off-chain for his own verification           */
  /* ---------------------------------------------------------------------- */

  // Same deterministic seed as funding phase:
  //   seed = sha256(ephemPub33 || uint64le(amount))
  const seed = sha256(concat(ephemPubReceived, uint64le(decryptedAmount)));

  // Rebuild the *core* Sigma proof (no envelope)
  const regeneratedProof = generateSigmaRangeProof(decryptedAmount, seed);
  const regeneratedProofBytes = serializeProof(regeneratedProof);

  // Hash of regenerated core proof
  const regeneratedCoreHashBytes = computeProofHash(regeneratedProofBytes);
  const regeneratedCoreHashHex   = bytesToHex(regeneratedCoreHashBytes);

  // Original hashes from funding step
  const originalCoreHashHex   = bytesToHex(coreHashBytes);   // hash256(coreProofBytes)
  const originalProofHashHex  = bytesToHex(proofHashBytes);  // hash256(envelope)

  const regeneratedCommitment = regeneratedProof.C_bytes;
  const nftCommitment         = covenantUtxo.token_data.nft.commitment;

  console.log('--- Bob verification of confidential asset ---');
  console.log('  original coreHash (hash256(coreProofBytes)):   ', originalCoreHashHex);
  console.log('  regenerated coreHash (hash256(regenProofBytes)):', regeneratedCoreHashHex);
  console.log('  original proofHash (hash256(envelope)):        ', originalProofHashHex);

  if (!arraysEqual(regeneratedCommitment, nftCommitment)) {
    throw new Error('Regenerated commitment does not match NFT commitment');
  }
  console.log('✅ Regenerated commitment matches NFT commitment in token prefix');

  // This is the *intended* binding: Bob must see the same core proof hash
  // that Alice committed to when minting the NFT.
  if (regeneratedCoreHashHex !== originalCoreHashHex) {
    throw new Error('Regenerated core proofHash does not match original funding coreHash');
  }
  console.log('✅ Regenerated core proofHash matches original funding coreHash');

  /* ---------------------------------------------------------------------- */
  /* 7) Bob spends covenant → Alice (RPA/paycode-derived address)          */
  /* ---------------------------------------------------------------------- */

  const { returnTxId, rpaSenderContext } = await buildBobReturnTx(
    bob,
    covenantUtxo,
    alicePaycode,
    ephemPubReceived,
    encryptedAmountReceived,
    NETWORK,
  );
  
  console.log('✅ Bob returned funds Tx ID:', returnTxId);  
  console.log(
    'Verifying covenant enforcement: TX success implies ZKP hash, NFT bind, and Bob-only spend were all satisfied.',
  );
  console.log('--- Demo Complete: Phase 1 PZ-SQH Transfer ---');

  /* ---------------------------------------------------------------------- */
  /* 8) Alice reconstructs RPA one-time key for vout[0] of Bob’s return TX  */
  /* ---------------------------------------------------------------------- */

  const returnDetails = await getTxDetails(returnTxId, NETWORK);
  const returnOut0 = returnDetails.outputs[0]; // vout[0] = NFT → Alice (paycode-derived)

  // Split token prefix and P2PKH script for the paycode-derived output
  const { prefix: retTokenPrefix, locking: retLockingScript } =
    splitTokenPrefix(returnOut0.scriptPubKey);

  if (!retLockingScript) {
    throw new Error('Missing locking script for paycode-derived output');
  }

  // Expect standard P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
  if (
    retLockingScript.length !== 25 ||
    retLockingScript[0] !== 0x76 || // OP_DUP
    retLockingScript[1] !== 0xa9 || // OP_HASH160
    retLockingScript[2] !== 0x14 || // push 20
    retLockingScript[23] !== 0x88 || // OP_EQUALVERIFY
    retLockingScript[24] !== 0xac // OP_CHECKSIG
  ) {
    throw new Error('Unexpected script for paycode-derived output (expected P2PKH)');
  }

  const hash160FromScript = retLockingScript.slice(3, 23);

  // Human-readable RPA child address Alice received from Bob
  const prefix = NETWORK === 'chipnet' ? 'bchtest' : 'bitcoincash';
  aliceRpaAddress = encodeCashAddr(prefix, 'P2PKH', hash160FromScript);
  console.log(
    'RPA-derived one-time address (Bob → Alice, vout[0]):',
    aliceRpaAddress,
  );
  
  // RPA receiver side:
  // In a full wallet, Alice would parse Bob's sender pubkey from the input
  // scriptSig and use its outpoint. In this demo, we reuse the known context
  // that Bob returned from buildBobReturnTx.
  const { senderPrivBytes, prevoutHashHex, prevoutN } = rpaSenderContext;

  // Sender pub P from Bob's input (recomputed from priv for the demo)
  const senderPub33 = secp256k1.getPublicKey(senderPrivBytes, true);

  // Use RPA helper to derive Alice's one-time private key
  const { oneTimePriv } = deriveRpaOneTimePrivReceiver(
    alice.scanPrivBytes,
    alice.spendPrivBytes,
    senderPub33,
    prevoutHashHex,
    prevoutN,
    0
  );

  const aliceDerivedPriv = oneTimePriv;
  const aliceDerivedPubCheck = secp256k1.getPublicKey(aliceDerivedPriv, true);
  const hash160AliceDerived = _hash160(aliceDerivedPubCheck);


  console.log('\n--- Closing the paycode-derived (RPA) loop ---');
  logSection('Step 5: Alice discovers and spends her paycode-derived RPA output');
  console.log('[5A] Alice parses vout[0] of Bob→Alice tx as a standard P2PKH:');
  console.log('  - script hash160:', bytesToHex(hash160FromScript));
  console.log('  - this came from Bob’s RPA derivation from Alice’s paycode.');
  console.log('[5B] Using RPA receiver-side logic, Alice derives the matching one-time privkey from:');
  console.log('  - her paycode scan/spend privkeys (d,f)');
  console.log('  - Bob’s sender pubkey P from the fee input scriptSig');
  console.log('  - that fee input’s outpoint (prev txid + vout)');
  console.log('  - index = 0');  
  console.log(
    'Alice derived one-time pub (hex):',
    bytesToHex(aliceDerivedPubCheck),
  );
  console.log(
    'HASH160(derived Alice one-time pub):',
    bytesToHex(hash160AliceDerived),
  );
  console.log(
    'HASH160 from vout0 script:             ',
    bytesToHex(hash160FromScript),
  );

  if (!arraysEqual(hash160AliceDerived, hash160FromScript)) {
    throw new Error('Alice derived key mismatch – RPA loop failed');
  }
  console.log(
    '✅ Closed loop: Alice’s derived one-time key matches the paycode-derived output she received.',
  );


  /* ---------------------------------------------------------------------- */
  /* 9) Alice spends paycode-derived UTXO → original source wallet          */
  /* ---------------------------------------------------------------------- */

  const derivedValue = returnOut0.value; // BigInt is fine; buildAliceRpaSpendTx uses BigInt()

  const rpaSpendTxId = await buildAliceRpaSpendTx(
    aliceDerivedPriv,   // one-time spend key for vout[0]
    returnTxId,
    0,                  // vout index of derived output
    derivedValue,    // value of that UTXO in sats (BigInt)
    retTokenPrefix,     // reuse NFT token prefix
    alice.hash160,      // Alice's original P2PKH hash
    NETWORK,
  );

  console.log('✅ Alice paycode-derived → source wallet txid:', rpaSpendTxId);

  // --- Final summary with Chaingraph links ---
  const explorerBase =
    NETWORK === 'chipnet'
      ? 'https://chipnet.chaingraph.cash/tx'
      : 'https://chaingraph.cash/tx';

  console.log('\nYou now have three txids to inspect on a block explorer:');
  console.log(`- Alice → covenant lock: ${sendTxId}`);
  console.log(`  ${explorerBase}/${sendTxId}`);
  console.log(`- Bob → Alice (paycode-derived address from RPA flow): ${returnTxId}`);
  console.log(`  ${explorerBase}/${returnTxId}`);
  console.log(`- Alice paycode-derived → original source wallet (loop fully closed): ${rpaSpendTxId}`);
  console.log(`  ${explorerBase}/${rpaSpendTxId}`);

  printPhase1Report({
    aliceAddress: alice.address,
    alicePaycode,
    bobAddress: bob.address,
    bobPaycode,
    fundingTxId,      // Alice → covenant
    returnTxId,       // Bob → Alice (RPA child)
    rpaSpendTxId,     // Alice RPA child → Alice base
    aliceRpaAddress,  // the child address Bob paid to (decoded from vout[0])
  });
}

/* -------------------------------------------------------------------------- */
/* CLI entrypoint                                                             */
/* -------------------------------------------------------------------------- */

async function mainCli(argv) {
  // Preserve legacy 'fund' behavior: `node demo.js fund`
  if (argv[2] === 'fund') {
    console.log('Running fund_schnorr.js (legacy fund helper)...');
    // eslint-disable-next-line global-require
    require('./fund_schnorr.js');
    return;
  }

  // New: pool_hash_fold demo shortcut
  if (argv[2] === 'pool') {
    const versionArg = argv[3] || 'v0';
    const version =
      versionArg === 'v1'   ? POOL_HASH_FOLD_VERSION.V1   :
      versionArg === 'v1_1' ? POOL_HASH_FOLD_VERSION.V1_1 :
      POOL_HASH_FOLD_VERSION.V0;

    const { alice } = await getWallets();
    const res = await demoPoolHashFold(alice, NETWORK, { version });
    console.log('\nPool hash fold summary:', res);
    return;
  }

  const program = new Command();
  program
    .name('pz-sqh-demo')
    .description(
      'Phase-1 PZ-SQH demo (RPA front-end for confidential assets / stealth / PQ vaults)',
    )
    .option(
      '--mode <mode>',
      'RPA mode: conf-asset | stealth-p2pkh | pq-vault',
      RPA_MODE_CONF_ASSET,
    )
    .option(
      '--export-psbt',
      'Export a PSBT-like structure (with RPA metadata) instead of just running the on-chain demo',
      false,
    );

  program.parse(argv);
  const opts = program.opts();
  const mode = normalizeRpaMode(opts.mode);
  const exportPsbt = !!opts.exportPsbt;

  console.log(`\n[CLI] Selected RPA mode: ${mode}`);
  if (exportPsbt) {
    console.log('[CLI] PSBT export: enabled (draft, RPA metadata only)\n');
  } else {
    console.log('');
  }

  if (mode === RPA_MODE_STEALTH_P2PKH) {
    await demoStealthP2PKH();
  } else if (mode === RPA_MODE_PQ_VAULT) {
    await demoPqVaultStub();
  } else {
    // Default / full confidential-asset demo
    await demoSilentTransfer({ exportPsbt });
  }
}

// Allow programmatic import (tests) without auto-running the CLI.
if (typeof require !== 'undefined' && require.main === module) {
  mainCli(process.argv).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}