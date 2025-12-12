// src/pool_hash_fold_demo.js
import { sha256 } from '@noble/hashes/sha2.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  consolidateUtxos,
  buildRawTx,
  getP2PKHScript,
  estimateTxSize,
  addTokenToScript,
} from './tx.js';
import { broadcastTx, getFeeRate, parseTx } from './electrum.js';
import {
  concat,
  pushDataPrefix,
  bytesToHex,
  hexToBytes,
  _hash160,
  reverseBytes,
  minimalScriptNumber
} from './utils.js';
import {
  getPoolHashFoldBytecode,
  POOL_HASH_FOLD_VERSION,
} from './pool_hash_fold_script.js';
import { DUST } from './config.js';

function hash256(u8) {
  return sha256(sha256(u8));
}

/**
 * Compute finalAcc = fold(oldCommit, limbs...) with the same ordering:
 *
 *   acc0 = oldCommit
 *   for k = N-1..0:
 *     acc = HASH256(acc || limb_k)
 */
export function computePoolHashFold(oldCommit, limbs) {
  let acc = oldCommit;
  for (let i = limbs.length - 1; i >= 0; i--) {
    acc = hash256(concat(acc, limbs[i]));
  }
  return acc;
}

// Minimal script-number pushes for 0..16
// 0  -> OP_0 (0x00)
// 1–16 -> OP_1..OP_16 (0x51..0x60)
function opSmallInt(n) {
  if (n === 0) return Uint8Array.of(0x00); // OP_0
  if (n >= 1 && n <= 16) return Uint8Array.of(0x50 + n); // OP_1..OP_16

  throw new Error(`opSmallInt: out of range (${n})`);
}

function pushLimb(v) {
  if (typeof v === 'number') {
    if (v >= 0 && v <= 16) return opSmallInt(v);
    const b = minimalScriptNumber(BigInt(v));
    return concat(pushDataPrefix(b.length), b);
  }
  if (v instanceof Uint8Array) {
    return concat(pushDataPrefix(v.length), v);
  }
  throw new Error('unsupported limb type');
}

function buildPoolHashFoldUnlockingV0() {
  // 1-byte limb values we want in the fold:
  const limbValues = [1, 2, 3];

  // Actual bytes that the hash fold will see:
  const limbs = limbValues.map((v) => Uint8Array.of(v));

  const oldCommit = new Uint8Array(32); // all zeros

  // Correct order: (oldCommit, limbs)
  const expectedNewCommit = computePoolHashFold(oldCommit, limbs);

  const pushes = [];

  // MINIMALDATA: push 1, 2, 3 as OP_1, OP_2, OP_3
  for (const v of limbValues) pushes.push(pushLimb(v));

  // oldCommit (32 bytes)
  pushes.push(pushDataPrefix(oldCommit.length), oldCommit);

  // expectedNewCommit (32 bytes)
  pushes.push(
    pushDataPrefix(expectedNewCommit.length),
    expectedNewCommit
  );

  // Use the existing concat helper
  const unlocking = concat(...pushes);

  return { limbValues, limbs, oldCommit, expectedNewCommit, unlocking };
}

function buildPoolHashFoldUnlockingV1(limbValues = [1, 2, 3], noteHash32 = null) {
  const limbs = limbValues.map((v) => Uint8Array.of(v));

  const pushes = [];
  for (const v of limbValues) pushes.push(opSmallInt(v));

  // If provided, push noteHash as the LAST item (top of stack)
  if (noteHash32) {
    if (!(noteHash32 instanceof Uint8Array) || noteHash32.length !== 32) {
      throw new Error('noteHash32 must be Uint8Array(32)');
    }
    pushes.push(pushDataPrefix(noteHash32.length), noteHash32);
    limbs.push(noteHash32); // IMPORTANT: include it in off-chain fold computation
  }

  const unlocking = concat(...pushes);
  return { limbValues, limbs, unlocking, noteHash32 };
}

/**
 * Fund a covenant UTXO locked by pool_hash_fold, with version switch:
 *
 * version 'v0':
 *   - Bare script (no tokens): scriptPubKey = POOL_HASH_FOLD_V0
 *
 * version 'v1':
 *   - Tokenized + introspective:
 *       scriptPubKey = tokenPrefix(NFT(commitment=oldCommit)) + POOL_HASH_FOLD_V1
 *
 * Returns:
 *   {
 *     txid,
 *     vout,
 *     value,
 *     version,
 *     // v1-only extras:
 *     tokenCategory?, // Uint8Array(32)
 *     oldCommit?,     // Uint8Array(32)
 *   }
 */
export async function fundPoolHashFoldUtxo(
  alice,
  network,
  { version = POOL_HASH_FOLD_VERSION.V0 } = {}
) {
  const alicePriv = alice.privBytes; // 32-byte Uint8Array
  const alicePub33 = secp256k1.getPublicKey(alicePriv, true);
  const aliceHash160 = _hash160(alicePub33);
  const aliceP2PKH = getP2PKHScript(aliceHash160);

  // Ensure Alice has a single vout=0 UTXO
  const baseUtxo = await consolidateUtxos(alice.address, alicePriv, network, false);
  console.log(`[fundPoolHashFoldUtxo:${version}] Base UTXO:`, baseUtxo);

  const rate = await getFeeRate();
  console.log('Fee rate:', rate, 'sat/byte');

  const covenantValue = 10_000; // sats for this test
  const dummyInputs = 1;
  const dummyOutputs = 2; // covenant + change

  const baseSize = estimateTxSize(dummyInputs, dummyOutputs);
  const fee = Math.ceil(baseSize * rate) + 50;
  const change = baseUtxo.value - covenantValue - fee;

  if (change < DUST) {
    throw new Error(`Insufficient funds for covenant funding; change=${change}`);
  }

  let covenantScriptPubKey;
  let tokenCategory = null;
  let oldCommit = null;

  if (version === POOL_HASH_FOLD_VERSION.V0) {
    // Bare script
    const v0Bytecode = await getPoolHashFoldBytecode(POOL_HASH_FOLD_VERSION.V0);
    covenantScriptPubKey = v0Bytecode;
  } else if (version === POOL_HASH_FOLD_VERSION.V1) {
    // Tokenized, introspective NFT with commitment = oldCommit (zeros)
    const txidBytes = hexToBytes(baseUtxo.txid);
    tokenCategory = reverseBytes(txidBytes); // simple category choice for demo

    oldCommit = new Uint8Array(32); // 32 zero bytes as initial pool state

    const token = {
      category: tokenCategory,
      nft: {
        capability: 'mutable',   // allows commitment updates
        commitment: oldCommit,
      },
    };    

    const v1Bytecode = await getPoolHashFoldBytecode(POOL_HASH_FOLD_VERSION.V1);
    covenantScriptPubKey = addTokenToScript(token, v1Bytecode);
  } else {
    throw new Error(`Unknown pool_hash_fold version: ${version}`);
  }

  const tx = {
    version: 1,
    inputs: [
      {
        txid: baseUtxo.txid,
        vout: baseUtxo.vout,
        sequence: 0xffffffff,
        scriptSig: new Uint8Array(),
      },
    ],
    outputs: [
      // vout0: covenant-locked UTXO
      { value: covenantValue, scriptPubKey: covenantScriptPubKey },

      // vout1: change back to Alice P2PKH
      { value: change, scriptPubKey: aliceP2PKH },
    ],
    locktime: 0,
  };

  const { signInput } = await import('./tx.js');
  signInput(tx, 0, alicePriv, aliceP2PKH, baseUtxo.value);

  const txHex = buildRawTx(tx);
  console.log(`[fundPoolHashFoldUtxo:${version}] funding tx hex:`, txHex);

  const txid = await broadcastTx(txHex, network);
  console.log(`✅ pool_hash_fold (${version}) funding txid:`, txid);

  return {
    txid,
    vout: 0,
    value: covenantValue,
    version,
    tokenCategory,
    oldCommit,
  };
}

export async function spendPoolHashFoldUtxo(
  alice,
  covenantUtxo,
  network,
  {
    version = POOL_HASH_FOLD_VERSION.V0,
    limbValues,
    limbs,                 // <- alias
  } = {}
) {
  // Normalize: prefer explicit limbValues, else limbs, else default
  const normalizedLimbValues = limbValues ?? limbs ?? [1, 2, 3];

  const alicePriv = alice.privBytes;
  const alicePub33 = secp256k1.getPublicKey(alicePriv, true);
  const aliceHash160 = _hash160(alicePub33);
  const aliceP2PKH = getP2PKHScript(aliceHash160);

  console.log(`[spendPoolHashFoldUtxo:${version}] covenant UTXO:`, covenantUtxo);

  const fee = 500;

  if (version === POOL_HASH_FOLD_VERSION.V0) {
    // --- v0: bare script, manual commits, P2PKH payout to Alice ---

    const { unlocking } = buildPoolHashFoldUnlockingV0();
    console.log('pool_hash_fold v0 unlocking hex:', bytesToHex(unlocking));

    if (covenantUtxo.value - fee < DUST) {
      throw new Error('Covenant UTXO too small to pay fee cleanly (v0)');
    }

    const sendValue = covenantUtxo.value - fee;

    const tx = {
      version: 1,
      inputs: [
        {
          txid: covenantUtxo.txid,
          vout: covenantUtxo.vout,
          sequence: 0xffffffff,
          scriptSig: unlocking, // no signature; covenant enforces correctness
        },
      ],
      outputs: [
        {
          value: sendValue,
          scriptPubKey: aliceP2PKH,
        },
      ],
      locktime: 0,
    };

    const txHex = buildRawTx(tx);
    console.log('pool_hash_fold v0 spend tx hex:', txHex);

    const txid = await broadcastTx(txHex, network);
    console.log('✅ pool_hash_fold v0 spend txid:', txid);

    return txid;
  }

  if (version === POOL_HASH_FOLD_VERSION.V1) {
    // --- v1: tokenized, introspective NFT state update ---

    if (!covenantUtxo.tokenCategory || !covenantUtxo.oldCommit) {
      throw new Error(
        'v1 spend requires tokenCategory and oldCommit from funding step'
      );
    }
    
    // example: deterministic plaintext note hash
    const noteHash32 = sha256(
      concat(
        Uint8Array.of(0x01),                 // domain separator
        Uint8Array.from(normalizedLimbValues)
      )
    );

    const { unlocking, limbs } = buildPoolHashFoldUnlockingV1(normalizedLimbValues, noteHash32);
    console.log('pool_hash_fold v1 unlocking hex:', bytesToHex(unlocking));

    if (covenantUtxo.value - fee < DUST) {
      throw new Error('Covenant UTXO too small to pay fee cleanly (v1)');
    }

    const newValue = covenantUtxo.value - fee;
    const oldCommit = covenantUtxo.oldCommit;
    const newCommit = computePoolHashFold(oldCommit, limbs);

    console.log('pool_hash_fold v1 commitments:');
    console.log('  oldCommit:', bytesToHex(oldCommit));
    console.log('  newCommit:', bytesToHex(newCommit));

    // build output[0] covenant script with updated commitment
    const token = {
      category: covenantUtxo.tokenCategory,
      nft: { capability: 'mutable', commitment: newCommit },
    };
    const v1Bytecode = await getPoolHashFoldBytecode(POOL_HASH_FOLD_VERSION.V1);
    const newCovenantScript = addTokenToScript(token, v1Bytecode);
   
    const tx = {
      version: 1,
      inputs: [
        {
          txid: covenantUtxo.txid,
          vout: covenantUtxo.vout,
          sequence: 0xffffffff,
          scriptSig: unlocking,
        },
      ],
      outputs: [
        {
          value: newValue,
          scriptPubKey: newCovenantScript,
        },
      ],
      locktime: 0,
    };

    const txHex = buildRawTx(tx);
    console.log('pool_hash_fold v1 spend tx hex:', txHex);
    
    // ✅ sanity-check: parse the tx we are about to broadcast
    const parsed = parseTx(txHex);
    const out0 = parsed.outputs[0];
    const outCommit = out0.token_data?.nft?.commitment;
    
    if (!outCommit || bytesToHex(outCommit) !== bytesToHex(newCommit)) {
      console.error('computed newCommit:', bytesToHex(newCommit));
      console.error('parsed outCommit   :', outCommit ? bytesToHex(outCommit) : null);
      throw new Error('Output commitment mismatch vs computed newCommit');
    }
    
    const txid = await broadcastTx(txHex, network);
    console.log('✅ pool_hash_fold v1 spend txid:', txid);
    console.log(
      '  (NFT commitment updated via introspective fold; BCH balance shrank by fee.)'
    );
    const nextCovenantUtxo = {
      txid,
      vout: 0,
      value: newValue,
      version: POOL_HASH_FOLD_VERSION.V1,
      tokenCategory: covenantUtxo.tokenCategory,
      oldCommit: newCommit, // <- state baton pass
    };

    return { txid, txHex, oldCommit, newCommit, limbValues, normalizedLimbValues, nextCovenantUtxo };
  }

  throw new Error(`Unknown pool_hash_fold version: ${version}`);
}

export async function demoPoolHashFold(
  alice,
  network,
  { version = POOL_HASH_FOLD_VERSION.V0 } = {}
) {
  console.log(`=== pool_hash_fold_${version} chipnet demo ===`);

  const covUtxo = await fundPoolHashFoldUtxo(alice, network, { version });
  const spendTxId = await spendPoolHashFoldUtxo(alice, covUtxo, network, { version });

  console.log('Done. pool_hash_fold funding + spend completed.');
  return { fundingTxId: covUtxo.txid, spendTxId, version };
}
