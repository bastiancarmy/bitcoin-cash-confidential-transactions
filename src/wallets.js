// src/wallets.js
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { _hash160, hexToBytes, bytesToHex, ensureEvenYPriv } from './utils.js';
import { encodeCashAddr } from './cashaddr.js';
import { promptPrivKey } from './prompts.js';
import { NETWORK } from './config.js';

import fs from 'fs';
import path from 'path';

// Store wallets.local.json in the directory where you run `node dist/demo.js`
// (typically the repo root). This avoids import.meta/ESM vs CJS issues.
const WALLET_FILE = path.resolve(process.cwd(), 'wallets.local.json');

function loadLocalWalletPrivs() {
  try {
    if (!fs.existsSync(WALLET_FILE)) return null;
    const raw = fs.readFileSync(WALLET_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.alicePriv === 'string' && typeof parsed.bobPriv === 'string') {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

function saveLocalWalletPrivs(alicePriv, bobPriv) {
  try {
    const data = {
      alicePriv,
      bobPriv,
    };
    fs.writeFileSync(WALLET_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
    // Don’t log here to avoid noisy “saved” on every run.
  } catch (e) {
    console.warn('Warning: could not save wallets.local.json:', e.message);
  }
}

// src/wallets.js

export function createWallet(name, privKeyHex) {
  if (!privKeyHex || typeof privKeyHex !== 'string') {
    throw new Error(`createWallet(${name}) requires a hex private key string`);
  }

  let privBytes = hexToBytes(privKeyHex);
  privBytes = ensureEvenYPriv(privBytes);
  privKeyHex = bytesToHex(privBytes);

  const pubBytes = secp256k1.getPublicKey(privBytes, true);
  try {
    secp256k1.Point.fromHex(bytesToHex(pubBytes));
  } catch (e) {
    throw new Error(`Invalid generated pubKey: ${e.message}`);
  }

  const pub = bytesToHex(pubBytes);
  const hash160 = _hash160(pubBytes);

  const prefix = NETWORK === 'mainnet' ? 'bitcoincash' : 'bchtest';
  const address = encodeCashAddr(prefix, 'P2PKH', hash160);

  return { priv: privKeyHex, pub, privBytes, pubBytes, hash160, address };
}

export async function getWallets() {
  // 1) Load from local file if present
  let alicePriv, bobPriv;
  const local = loadLocalWalletPrivs();
  if (local) {
    alicePriv = local.alicePriv;
    bobPriv   = local.bobPriv;
  }

  // 2) Allow advanced override via env vars (optional)
  if (process.env.ALICE_PRIV_KEY) alicePriv = process.env.ALICE_PRIV_KEY;
  if (process.env.BOB_PRIV_KEY)   bobPriv   = process.env.BOB_PRIV_KEY;

  // 3) If still missing, prompt + generate + persist
  if (!alicePriv) {
    console.log('No Alice key found. Generating/entering one now…');
    alicePriv = await promptPrivKey('Alice');
  }
  if (!bobPriv) {
    console.log('No Bob key found. Generating/entering one now…');
    bobPriv = await promptPrivKey('Bob');
  }

  // Save (unless we *only* want persisted from file; up to you)
  saveLocalWalletPrivs(alicePriv, bobPriv);

  const alice = createWallet('Alice', alicePriv);
  const bob   = createWallet('Bob', bobPriv);

  console.log('--- Obtaining Alice Wallet ---');
  console.log('Alice Pub:', alice.pub);
  console.log('Alice Address:', alice.address);

  console.log('--- Obtaining Bob Wallet ---');
  console.log('Bob Pub:', bob.pub);
  console.log('Bob Address:', bob.address);

  console.log('\nNote: These wallets are persisted in wallets.local.json (DO NOT COMMIT THIS FILE).');
  console.log('If you want to override them, set ALICE_PRIV_KEY and BOB_PRIV_KEY in your environment.\n');

  return { alice, bob };
}