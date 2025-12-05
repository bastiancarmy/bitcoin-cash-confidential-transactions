// fund_schnorr.js - Transfer funds from old Alice address to new Schnorr-compatible address
// Run: node fund_schnorr.js
// Set env: export ALICE_PRIV_KEY=your_original_priv_here (e.g., a23d5826f63c64a119e4dc8febbdb66811f2fa15ee486e86485177f301dcde35)
// Adjust NETWORK in config.js if needed

import readline from 'readline';
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { numberToBytesBE } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { _hash160, hexToBytes, bytesToHex, ensureEvenYPriv, getXOnlyPub, concat, varInt, bchSchnorrSign,bchSchnorrVerify } from './utils.js';
import { encodeCashAddr } from './cashaddr.js';
import { getUtxos, getFeeRate, broadcastTx, getTipHeader } from './electrum.js';
import { getP2PKHScript, buildRawTx, estimateTxSize, getAllPrevOut, getAllSequences, getOutpoint, getAllOutputs, normalizeSats } from './tx.js';
import { NETWORK, DUST } from './config.js';
import { base58checkEncode } from './base58.js';

// Updated signInput to use custom BCH Schnorr, local verify with full pub, push full pub in scriptSig
function signInput(tx, inputIndex, privBytes, scriptPubKey, value) {
  if (!(privBytes instanceof Uint8Array)) throw new Error('privBytes must be Uint8Array');
  if (!(scriptPubKey instanceof Uint8Array)) throw new Error('scriptPubKey must be Uint8Array');

  console.log('Entering signInput for input', inputIndex);
  console.log('privBytes length:', privBytes.length);
  console.log('scriptPubKey:', bytesToHex(scriptPubKey));

  const fullPub = secp256k1.getPublicKey(privBytes, true); // 33 bytes compressed, no normalization needed for Schnorr

  // Precompute shared sighash parts
  const versionBytes = numberToBytesBE(BigInt(tx.version ?? 1), 4);
  const locktimeBytes = numberToBytesBE(BigInt(tx.locktime ?? 0), 4);
  const sighashTypeBytes = numberToBytesBE(0x41n, 4);
  const hashPrevouts = sha256(sha256(getAllPrevOut(tx.inputs)));
  const hashSequence = sha256(sha256(getAllSequences(tx.inputs)));
  const hashOutputs = sha256(sha256(getAllOutputs(tx.outputs)));

  const input = tx.inputs[inputIndex];
  const outpoint = getOutpoint(input);
  const sequence = numberToBytesBE(BigInt(input.sequence ?? 0xffffffff), 4);
  const valueBytes = numberToBytesBE(BigInt(normalizeSats(value)), 8);
  const scriptCodeLen = varInt(scriptPubKey.length);

  const preimage = concat(
    versionBytes,
    hashPrevouts,
    hashSequence,
    outpoint,
    scriptCodeLen,
    scriptPubKey,
    valueBytes,
    sequence,
    hashOutputs,
    locktimeBytes,
    sighashTypeBytes
  );
  console.log('Preimage hex:', bytesToHex(preimage));

  const sighash = sha256(sha256(preimage));
  console.log('Sighash hex:', bytesToHex(sighash));

  const sig64 = bchSchnorrSign(sighash, privBytes, fullPub);
  console.log('Signature (64 bytes) hex:', bytesToHex(sig64));

  const verified = bchSchnorrVerify(sig64, sighash, fullPub);
  console.log('Schnorr signature verification:', verified ? '✅ Passed' : '❌ Failed');
  if (!verified) throw new Error('Schnorr verification failed');

  const sigWithType = concat(sig64, new Uint8Array([0x41]));

  tx.inputs[inputIndex].scriptSig = concat(
    varInt(sigWithType.length), sigWithType,
    varInt(fullPub.length), fullPub  // Push full 33-byte pub for P2PKH hash160 match
  );
  console.log('ScriptSig hex:', bytesToHex(tx.inputs[inputIndex].scriptSig));
  return tx;
}

export async function prompt(question) {
  return new Promise(resolve => rl.question(question, resolve));
}

export async function fundNewSchnorrAddress() {
  const originalPrivHex = process.env.ALICE_PRIV_KEY;
  if (!originalPrivHex) throw new Error('Set ALICE_PRIV_KEY in env');

  const originalPrivBytes = hexToBytes(originalPrivHex);
  const originalFullPub = secp256k1.getPublicKey(originalPrivBytes, true);
  const originalHash160 = _hash160(originalFullPub);
  const prefix = NETWORK === 'mainnet' ? 'bitcoincash' : 'bchtest';
  const oldAddress = encodeCashAddr(prefix, 0, originalHash160);
  console.log('Old Address:', oldAddress);

  console.log('\n--- Step 1: Fetching UTXOs for old address ---');
  const utxos = await getUtxos(oldAddress, NETWORK);
  if (utxos.length === 0) {
    console.log('No UTXOs found for original address.');
  } else {
    console.log('Found UTXOs:');
    console.log(utxos);
  }

  console.log('\n--- Step 2: Generating new Schnorr keypair info ---');
  const adjustedPrivBytes = ensureEvenYPriv(originalPrivBytes);
  const adjustedPrivHex = bytesToHex(adjustedPrivBytes);
  const newFullPub = secp256k1.getPublicKey(adjustedPrivBytes, true);
  const newHash160 = _hash160(newFullPub); // Use full pub for standard P2PKH address
  const newAddress = encodeCashAddr(prefix, 0, newHash160);
  console.log('New Privkey Hex (adjusted if needed):', adjustedPrivHex);
  console.log('New Full Pubkey Hex:', bytesToHex(newFullPub));
  console.log('X-Only Pubkey Hex:', bytesToHex(getXOnlyPub(newFullPub))); // For logging only
  console.log('New Schnorr Address:', newAddress);

  // Compute WIF for new privkey (testnet version 0xef, compressed)
  const wifVersion = NETWORK === 'mainnet' ? 0x80 : 0xef;
  const wifPayload = concat(adjustedPrivBytes, new Uint8Array([0x01]));
  const wif = base58checkEncode(wifVersion, wifPayload);
  console.log('New Privkey WIF (for Electron Cash import):', wif);

  console.log('\n--- Step 3: Prompt for sats to transfer ---');
  const amountSatStr = await prompt('Enter number of sats to transfer (or "all" for max minus fee): ');
  const totalIn = utxos.reduce((sum, u) => sum + u.value, 0);
  const rate = await getFeeRate();
  const estSize = estimateTxSize(utxos.length, 2); // Inputs + output + change
  const fee = Math.ceil(estSize * rate);
  let amountSat = amountSatStr.toLowerCase() === 'all' ? totalIn - fee - DUST : parseInt(amountSatStr, 10);
  if (isNaN(amountSat) || amountSat < DUST || amountSat + fee + DUST > totalIn) {
    throw new Error('Invalid amount or insufficient funds');
  }
  console.log(`Transferring ${amountSat} sats (fee: ${fee})`);

  console.log('\n--- Step 4: Generating TX ---');
  const tx = {
    version: 1,
    inputs: utxos.map(u => ({
      txid: u.txid,
      vout: u.vout,
      sequence: 0xffffffff,
      scriptSig: new Uint8Array()
    })),
    outputs: [
      { value: amountSat, scriptPubKey: getP2PKHScript(newHash160) },
      { value: totalIn - amountSat - fee, scriptPubKey: getP2PKHScript(originalHash160) } // Change to old
    ],
    locktime: 0
  };

  for (let i = 0; i < tx.inputs.length; i++) {
    const scriptCode = getP2PKHScript(originalHash160);
    signInput(tx, i, originalPrivBytes, scriptCode, utxos[i].value);
  }

  const txHex = buildRawTx(tx);
  console.log('Generated TX Hex:', txHex);

  const confirm = await prompt('Confirm broadcast? (y/n): ');
  if (confirm.toLowerCase() !== 'y') {
    console.log('Cancelled');
    rl.close();
    return;
  }

  const tip = await getTipHeader(NETWORK);
  console.log('Tip Height:', tip.height, 'Timestamp:', tip.timestamp);
  if (tip.timestamp < 1557921600) {
    throw new Error('Schnorr not activated on this network (MTP < 1557921600)');
  }

  const txId = await broadcastTx(txHex);
  console.log('TX Broadcasted:', txId);

  console.log('\n--- Step 5: Checking received sats at new address ---');
  let received = 0;
  for (let attempt = 0; attempt < 10; attempt++) {
    const newUtxos = await getUtxos(newAddress, NETWORK);
    received = newUtxos.reduce((sum, u) => sum + u.value, 0);
    if (received >= amountSat) break;
    await new Promise(r => setTimeout(r, 5000)); // Poll every 5s
  }
  console.log(`Received ${received} sats at new address`);

  rl.close();
}

fundNewSchnorrAddress().catch(err => {
  console.error(err);
  rl.close();
});