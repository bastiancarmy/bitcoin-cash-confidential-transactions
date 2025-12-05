// src/prompts.js
// User input prompts
// No changes in phase 1

import { AMOUNT, FEE, DUST, NETWORK } from './config.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex } from './utils.js';

export async function promptFundAddress(address) {
  console.log(`Please fund this ${NETWORK} address with at least ${AMOUNT + FEE + DUST} sat: ${address}`);
  console.log('Use your wallet or exchange to send BCH.');
  console.log('Press Enter after funding...');
  await new Promise(resolve => process.stdin.once('data', resolve));
}

export async function promptPrivKey(role) {
  console.log(`Enter ${role} private key (hex) or press Enter to generate new:`);
  return new Promise(resolve => {
    process.stdin.once('data', input => {
      const privHex = input.toString().trim();
      resolve(privHex || bytesToHex(secp256k1.utils.randomSecretKey()));
    });
  });
}