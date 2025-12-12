// src/index_pool_demo.js
import { NETWORK } from './config.js';
import { getWallets } from './wallets.js';
import { fundPoolHashFoldUtxo, spendPoolHashFoldUtxo } from './pool_hash_fold_demo.js';
import { POOL_HASH_FOLD_VERSION } from './pool_hash_fold_script.js';
import { bytesToHex } from './utils.js';

export async function demoPoolHashFold(
  alice,
  network,
  {
    version = POOL_HASH_FOLD_VERSION.V0,
    sequences = [
      [1, 2, 3],
      [4, 5, 6],
      [7, 8, 9],
    ],
  } = {}
) {
  console.log(`=== pool_hash_fold_${version} chipnet demo ===`);

  let covenant = await fundPoolHashFoldUtxo(alice, network, { version });

  if (version === POOL_HASH_FOLD_VERSION.V0) {
    const spendTxId = await spendPoolHashFoldUtxo(alice, covenant, network, { version });
    console.log('Done. pool_hash_fold funding + spend completed.');
    return { fundingTxId: covenant.txid, spendTxId, version };
  }

  // v1: multi-step state machine
  console.log('v1 commitment sequence:');
  console.log('  state 0:', bytesToHex(covenant.oldCommit));

  const updates = [];

  for (let i = 0; i < sequences.length; i++) {
    const limbSeq = sequences[i];

    const res = await spendPoolHashFoldUtxo(alice, covenant, network, {
      version,
      limbs: limbSeq, // uses the alias we added
    });

    console.log(`  + [${limbSeq.join(',')}] →`, bytesToHex(res.newCommit));

    updates.push({
      i: i + 1,
      limbs: limbSeq,
      txid: res.txid,
      oldCommit: bytesToHex(res.oldCommit),
      newCommit: bytesToHex(res.newCommit),
    });

    // baton pass: next covenant becomes the output[0] we just created
    covenant = res.nextCovenantUtxo;
  }

  console.log('Done. v1 multi-step updates completed.');
  return {
    fundingTxId: updates.length ? updates[0].txid : covenant.txid,
    lastTxId: updates.length ? updates[updates.length - 1].txid : null,
    version,
    updates,
  };
}