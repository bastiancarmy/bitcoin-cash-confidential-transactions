// src/keys.js
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hexToBytes, bytesToHex, _hash160, getXOnlyPub, getXOnlyPub, ensureEvenYPriv } from './utils.js';
import { encodeCashAddr } from './cashaddr.js';
import { NETWORK } from './config.js';

export function keyPairFromPriv(privHex) {
  let privBytes = hexToBytes(privHex);
  privBytes = ensureEvenYPriv(privBytes);
  privHex = bytesToHex(privBytes);
  const pubBytes = secp256k1.getPublicKey(privBytes, true);
  try {
    secp256k1.Point.fromHex(bytesToHex(pubBytes));
  } catch (e) {
    throw new Error(`Invalid generated pubKey: ${e.message}`);
  }
  const pub = bytesToHex(pubBytes);
  const xOnlyPub = getXOnlyPub(pubBytes);
  const hash160 = _hash160(xOnlyPub);
  const prefix = NETWORK === 'mainnet' ? 'bitcoincash' : 'bchtest';
  const address = encodeCashAddr(prefix, 0, hash160);
  return { priv: privHex, pub, address, privBytes, pubBytes };
}