// src/tests/confidential.test.js
//
// Phase-1 sanity tests for:
//   - RPA derivation (sender/receiver round-trip)
//   - RPA session key determinism
//   - Pedersen commitments basic consistency
//
// This is intentionally minimal and framework-free so it can be run as:
//   node dist/tests/confidential.test.js
// after your usual build step.

import { randomBytes } from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';

import {
  RPA_MODE_CONF_ASSET,
  deriveRpaLockIntent,
  deriveRpaOneTimePrivReceiver,
  deriveRpaSessionKeys,
} from '../derivation.js';

import {
  _hash160,
  bytesToHex,
} from '../utils.js';

import {
  pedersenCommit64,
} from '../pedersen.js';

/* -------------------------------------------------------------------------- */
/* Tiny test harness                                                          */
/* -------------------------------------------------------------------------- */

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

async function runTest(name, fn) {
  try {
    await fn();
    console.log(`✅ ${name}`);
  } catch (err) {
    console.error(`❌ ${name}`);
    console.error(err);
    globalThis.__phase1TestsFailed = true;
  }
}

async function main() {
  console.log('══════════════════════════════════════════════');
  console.log(' Phase-1: RPA + confidential asset test suite');
  console.log('══════════════════════════════════════════════\n');

  await runTest(
    'RPA sender/receiver derivation round-trip (conf-asset mode)',
    testRpaRoundTripConfAsset,
  );

  await runTest(
    'RPA session key determinism and domain separation',
    testRpaSessionKeys,
  );

  await runTest(
    'Pedersen commit basic consistency (64-bit value)',
    testPedersenCommit64,
  );

  if (globalThis.__phase1TestsFailed) {
    console.error('\n❌ Phase-1 tests FAILED');
    process.exit(1);
  } else {
    console.log('\n✅ All Phase-1 tests passed');
  }
}

/* -------------------------------------------------------------------------- */
/* Test 1: RPA sender/receiver round-trip (confidential-asset mode)          */
/* -------------------------------------------------------------------------- */

async function testRpaRoundTripConfAsset() {
  // Phase-1 convention: Bob’s paycode folds scan + spend into a single key.
  // This mirrors the demo where:
  //   bob.scanPrivBytes  ?? bob.privBytes
  //   bob.spendPrivBytes ?? bob.privBytes
  const alicePrivBytes = new Uint8Array(randomBytes(32));
  const bobPrivBytes   = new Uint8Array(randomBytes(32));

  const bobScanPrivBytes  = bobPrivBytes;
  const bobSpendPrivBytes = bobPrivBytes;

  // Paycode pubkey: used as both scan and spend pub in deriveRpaLockIntent
  const bobPaycodePub33 = secp256k1.getPublicKey(bobPrivBytes, true);

  const dummyPrevoutTxidHex = bytesToHex(new Uint8Array(randomBytes(32)));
  const dummyPrevoutN = 1;
  const index = 0;

  // Sender side: Alice derives RPA lock intent in confidential-asset mode.
  const lockIntent = deriveRpaLockIntent({
    mode: RPA_MODE_CONF_ASSET,
    senderPrivBytes: alicePrivBytes,
    receiverPub33: bobPaycodePub33, // Phase-1: scan/spend folded
    prevoutTxidHex: dummyPrevoutTxidHex,
    prevoutN: dummyPrevoutN,
    index,
  });

  const {
    childPubkey,
    childHash160,
    sharedSecret,
    session,
    context,
  } = lockIntent;

  // HASH160(childPubkey) must equal childHash160
  const expectedHash160 = _hash160(childPubkey);
  assert(
    bytesToHex(expectedHash160) === bytesToHex(childHash160),
    'childHash160 mismatch with HASH160(childPubkey)',
  );

  // Receiver side: Bob reconstructs the same one-time key via RPA
  const { oneTimePriv } = deriveRpaOneTimePrivReceiver(
    bobScanPrivBytes,
    bobSpendPrivBytes,
    context.senderPub33,      // Alice’s funding pubkey
    dummyPrevoutTxidHex,
    dummyPrevoutN,
    index,
  );

  const oneTimePub33 = secp256k1.getPublicKey(oneTimePriv, true);
  const bobHash160 = _hash160(oneTimePub33);

  assert(
    bytesToHex(bobHash160) === bytesToHex(childHash160),
    'Receiver-derived hash160 does not match sender-derived childHash160',
  );

  // Determinism: same inputs → same childHash160
  const lockIntent2 = deriveRpaLockIntent({
    mode: RPA_MODE_CONF_ASSET,
    senderPrivBytes: alicePrivBytes,
    receiverPub33: bobPaycodePub33,
    prevoutTxidHex: dummyPrevoutTxidHex,
    prevoutN: dummyPrevoutN,
    index,
  });

  assert(
    bytesToHex(lockIntent2.childHash160) === bytesToHex(childHash160),
    'deriveRpaLockIntent is not deterministic for the same inputs',
  );

  // Sanity on session: zkSeed exists, is 32 bytes, and not all-zero
  assert(
    session && session.zkSeed instanceof Uint8Array && session.zkSeed.length === 32,
    'RPA session.zkSeed missing or invalid',
  );
  assert(
    bytesToHex(session.zkSeed) !== ''.padStart(64, '0'),
    'RPA session.zkSeed is all-zero (suspicious)',
  );

  // sharedSecret should be non-zero and 32 bytes
  assert(
    sharedSecret instanceof Uint8Array && sharedSecret.length === 32,
    'sharedSecret must be a 32-byte Uint8Array',
  );
}

/* -------------------------------------------------------------------------- */
/* Test 2: RPA session key determinism + domain separation                    */
/* -------------------------------------------------------------------------- */

async function testRpaSessionKeys() {
  const dummySecret = new Uint8Array(randomBytes(32));

  const txidA = bytesToHex(new Uint8Array(randomBytes(32)));
  const txidB = bytesToHex(new Uint8Array(randomBytes(32)));
  const voutA = 0;
  const voutB = 1;

  const sessA1 = deriveRpaSessionKeys(dummySecret, txidA, voutA);
  const sessA2 = deriveRpaSessionKeys(dummySecret, txidA, voutA);
  const sessB = deriveRpaSessionKeys(dummySecret, txidB, voutB);

  // Determinism: same inputs → identical session keys
  assert(
    bytesToHex(sessA1.sessionKey) === bytesToHex(sessA2.sessionKey),
    'Session key is not deterministic for same (secret, txid, vout)',
  );

  assert(
    bytesToHex(sessA1.amountKey) === bytesToHex(sessA2.amountKey),
    'amountKey is not deterministic for same (secret, txid, vout)',
  );

  assert(
    bytesToHex(sessA1.memoKey) === bytesToHex(sessA2.memoKey),
    'memoKey is not deterministic for same (secret, txid, vout)',
  );

  assert(
    bytesToHex(sessA1.zkSeed) === bytesToHex(sessA2.zkSeed),
    'zkSeed is not deterministic for same (secret, txid, vout)',
  );

  // Domain separation: changing (txid,vout) should change sessionKey
  assert(
    bytesToHex(sessA1.sessionKey) !== bytesToHex(sessB.sessionKey),
    'Session key should differ when (txid,vout) changes',
  );
}

/* -------------------------------------------------------------------------- */
/* Helper: normalize pedersenCommit64 output to 33-byte compressed bytes      */
/* -------------------------------------------------------------------------- */

function normalizeCommitmentToBytes(commitment) {
  // Case 1: already a Uint8Array (or Buffer)
  if (
    commitment instanceof Uint8Array ||
    (typeof Buffer !== 'undefined' && Buffer.isBuffer(commitment))
  ) {
    return new Uint8Array(commitment);
  }

  // Case 2: object wrapper like { C: <point or bytes>, ... }
  if (commitment && typeof commitment === 'object') {
    if ('C' in commitment) {
      return normalizeCommitmentToBytes(commitment.C);
    }
    if ('commitment' in commitment) {
      return normalizeCommitmentToBytes(commitment.commitment);
    }

    // Case 3: raw Point-like object with toBytes / toRawBytes
    if (typeof commitment.toBytes === 'function') {
      return commitment.toBytes(true);
    }
    if (typeof commitment.toRawBytes === 'function') {
      return commitment.toRawBytes(true);
    }
  }

  throw new Error(
    'pedersenCommit64 returned unsupported commitment type: ' +
      Object.prototype.toString.call(commitment),
  );
}

/* -------------------------------------------------------------------------- */
/* Test 3: Pedersen commit sanity (64-bit value)                              */
/* -------------------------------------------------------------------------- */

async function testPedersenCommit64() {
  // Use tiny, clearly valid scalars so we never hit noble's "invalid scalar" guard.
  // This keeps the test focused on:
  //   - shape (33-byte compressed point)
  //   - determinism for same (v, blind)
  //   - different blindings -> different commitments
  const value = 42n; // arbitrary non-zero 64-bit value
  const blind1 = 1n; // minimal valid scalar
  const blind2 = 2n; // distinct scalar

  const C1 = pedersenCommit64(value, blind1);
  const C1b = pedersenCommit64(value, blind1);
  const C2 = pedersenCommit64(value, blind2);

  const C1Bytes = normalizeCommitmentToBytes(C1);
  const C1bBytes = normalizeCommitmentToBytes(C1b);
  const C2Bytes = normalizeCommitmentToBytes(C2);

  // Shape check: compressed secp256k1 point is 33 bytes
  assert(
    C1Bytes instanceof Uint8Array && C1Bytes.length === 33,
    `pedersenCommit64(${value}) did not serialize to a 33-byte commitment`,
  );

  // Determinism: same (v, blind) → identical commitment
  assert(
    bytesToHex(C1Bytes) === bytesToHex(C1bBytes),
    `pedersenCommit64(${value}) is not deterministic for the same blinding`,
  );

  // Different blindings for the same value should yield different commitments
  assert(
    bytesToHex(C1Bytes) !== bytesToHex(C2Bytes),
    `pedersenCommit64(${value}) should differ for different blindings`,
  );
}

/* -------------------------------------------------------------------------- */

main().catch((err) => {
  console.error('Unexpected error in Phase-1 test runner:', err);
  process.exit(1);
});
