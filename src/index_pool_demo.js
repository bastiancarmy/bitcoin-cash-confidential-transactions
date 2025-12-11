// src/index_pool_demo.js
import { NETWORK } from './config.js';
import { getWallets } from './wallets.js';
import {
  fundPoolHashFoldUtxo,
  spendPoolHashFoldUtxo,
} from './pool_hash_fold_demo.js';

export async function demoPoolHashFold(alice, network) {
  console.log('=== pool_hash_fold_v0 chipnet demo ===');

  const covUtxo = await fundPoolHashFoldUtxo(alice, network);
  const spendTxId = await spendPoolHashFoldUtxo(alice, covUtxo, network);

  console.log('Done. pool_hash_fold funding + spend completed.');
  return { fundingTxId: covUtxo.txid, spendTxId };
}

// Optional simple CLI for just the pool demo
async function main() {
  const { alice } = await getWallets();
  await demoPoolHashFold(alice, NETWORK);
}

if (typeof require !== 'undefined' && require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
