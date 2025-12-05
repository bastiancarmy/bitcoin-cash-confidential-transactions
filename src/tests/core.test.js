// src/tests/core.test.js
// -----------------------------------------------------------------------------
// Minimal self-tests:
//  - Electrum connectivity (non-fatal, best-effort)
//  - RPA intent + legacy ephemeral amount encryption (Phase 1 demo)
// -----------------------------------------------------------------------------
// Run after build: `node dist/tests/core.test.js`
// -----------------------------------------------------------------------------

import { connectElectrum } from '../electrum.js';
import { NETWORK } from '../config.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { randomBytes } from 'crypto';
import { bytesToHex } from '../utils.js';
import {
  deriveRpaLockIntent,
  RPA_MODE_CONF_ASSET,
  encryptAmount,
  decryptAmount,
} from '../derivation.js';

/* ========================================================================== */
/* Electrum connectivity test (non-fatal)                                     */
/* ========================================================================== */

async function testElectrum() {
  console.log('\n=== Electrum connectivity self-test ===');

  let client;

  try {
    client = await connectElectrum(NETWORK);
    console.log('Electrum client connected for network:', NETWORK);

    try {
      const tip = await client.request('blockchain.headers.subscribe');
      console.log('Tip:', tip);
    } catch (rpcErr) {
      console.warn(
        '⚠️ Electrum RPC test failed (non-fatal):',
        rpcErr?.message ?? rpcErr,
      );
    }
  } catch (err) {
    console.warn(
      '⚠️ Electrum connection test failed (non-fatal):',
      err?.message ?? err,
    );
  } finally {
    if (client) {
      try {
        await client.disconnect();
      } catch {
        // ignore disconnect errors
      }
    }
  }
}

/* ========================================================================== */
/* RPA + amount encryption self-test                                          */
/* ========================================================================== */

async function testRpaAndAmountEncryption() {
  console.log('\n=== RPA + amount encryption self-test ===');

  const senderPriv = randomBytes(32);
  const receiverPriv = randomBytes(32);
  const receiverPub33 = secp256k1.getPublicKey(receiverPriv, true);

  const fakePrevoutTxidHex =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const fakePrevoutN = 0;

  const intent = deriveRpaLockIntent({
    mode: RPA_MODE_CONF_ASSET,
    senderPrivBytes: senderPriv,
    receiverPub33,
    prevoutTxidHex: fakePrevoutTxidHex,
    prevoutN: fakePrevoutN,
    index: 0,
  });

  console.log('RPA intent (conf-asset) address:', intent.address);
  console.log('RPA childHash160:', bytesToHex(intent.childHash160));
  console.log(
    'RPA zkSeed (for ZK/PQ vault sessions):',
    bytesToHex(intent.session.zkSeed),
  );

  const ephemPriv = randomBytes(32);
  const ephemPub = secp256k1.getPublicKey(ephemPriv, true);

  const originalAmount = 123456789;

  const envelope = encryptAmount(ephemPriv, receiverPub33, originalAmount);

  const decryptedStr = decryptAmount(receiverPriv, ephemPub, envelope);
  const parsed = JSON.parse(decryptedStr);

  if (typeof parsed.v !== 'number') {
    throw new Error('Invalid decrypted format: expected {"v": <number>}');
  }

  const decryptedAmount = parsed.v;

  console.log('Original amount:', originalAmount.toString());
  console.log('Decrypted amount:', decryptedAmount.toString());

  if (decryptedAmount !== originalAmount) {
    throw new Error('RPA/amount encryption self-test failed');
  }

  console.log('✅ RPA + amount encryption self-test passed');
}

/* ========================================================================== */
/* Entrypoint                                                                 */
/* ========================================================================== */

async function main() {
  await testElectrum();
  await testRpaAndAmountEncryption();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
