// src/tokens.js (minor: ensure commitment is 33 bytes compressed point)
import { reverseBytes, hexToBytes, bytesToHex, arraysEqual } from './utils.js';

export function createToken(categoryBytes, commitment) {
  // Commitment validation moved to addTokenToScript for centralized checks
  const token = { 
    category: categoryBytes, 
    nft: {
      capability: 1, // mutable
      commitment 
    }
  };
  console.log('NFT commitment (Pedersen C=vH+rG):', bytesToHex(commitment), `${commitment.length} bytes`);
  return token;
}

export function validateTokenCategory(inputTxHash, categoryBytes) {
  console.log('=== Token Category Validation ===');
  console.log('Input tx_hash bytes (BE):', bytesToHex(inputTxHash));
  console.log('Token category bytes (LE):', bytesToHex(categoryBytes));
  const leInputTxHash = reverseBytes(inputTxHash);
  const match = arraysEqual(leInputTxHash, categoryBytes);
  console.log('Bytes match:', match);
  if (!match) {
    throw new Error('Category mismatch');
  }
  console.log('✅ Category matches genesis input (vout=0)');
}