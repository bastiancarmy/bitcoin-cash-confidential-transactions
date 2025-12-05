// src/keygen.js
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ensureEvenYPriv, bytesToHex, hexToBytes, getXOnlyPub } from './utils.js';
import { encodeCashAddr } from './cashaddr.js';
import { _hash160 } from './utils.js';
import { NETWORK } from './config.js';
import { randomBytes } from 'crypto';

// Generate or adjust privkey for even-y, output details
export function generateOrAdjustPrivKey(originalPrivHex = null, name = 'Key') {
  let privBytes;
  if (originalPrivHex) {
    privBytes = hexToBytes(originalPrivHex);
    console.log(`Adjusting existing ${name} privkey: ${originalPrivHex}`);
  } else {
    privBytes = randomBytes(32); // Fresh random
    console.log(`Generating new ${name} privkey...`);
  }

  // Enforce even-y
  const adjustedPrivBytes = ensureEvenYPriv(privBytes);
  const adjustedPrivHex = bytesToHex(adjustedPrivBytes);

  const fullPubBytes = secp256k1.getPublicKey(adjustedPrivBytes, true); // 33 bytes
  const xOnlyPub = getXOnlyPub(fullPubBytes); // 32 bytes
  const hash160 = _hash160(xOnlyPub);
  const prefix = NETWORK === 'mainnet' ? 'bitcoincash' : 'bchtest';
  const address = encodeCashAddr(prefix, 0, hash160);

  console.log(`--- ${name} Key Details ---`);
  console.log(`Private Key (hex): ${adjustedPrivHex}`);
  console.log(`Full Pubkey (hex): ${bytesToHex(fullPubBytes)}`);
  console.log(`X-Only Pubkey (hex): ${bytesToHex(xOnlyPub)}`);
  console.log(`Address: ${address}`);
  console.log(`Save to env: export ${name.toUpperCase()}_PRIV_KEY=${adjustedPrivHex}`);
  console.log('------------------------');

  return {
    privHex: adjustedPrivHex,
    pubHex: bytesToHex(fullPubBytes),
    address
  };
}

// Example usage: Run with existing or generate new
if (require.main === module) {
  const alicePriv = process.env.ALICE_PRIV_KEY || null;
  const bobPriv = process.env.BOB_PRIV_KEY || null;

  generateOrAdjustPrivKey(alicePriv, 'Alice');
  generateOrAdjustPrivKey(bobPriv, 'Bob');
}