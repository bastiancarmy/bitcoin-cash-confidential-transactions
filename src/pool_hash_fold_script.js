// src/pool_hash_fold_script.js
import { bytesToHex } from './utils.js';
import v0Casm from './cashassembly/pool_hash_fold_v0.casm';
import v1Casm from './cashassembly/pool_hash_fold_v1.casm';
import v11Casm from './cashassembly/pool_hash_fold_v1_1.casm';

export const POOL_HASH_FOLD_VERSION = {
  V0: 'v0',
  V1: 'v1',
  V1_1: 'v1_1',
};

// Cache the libauth module so we only import it once
async function getLibauth() {
  if (!getLibauth._modulePromise) {
    getLibauth._modulePromise = import('@bitauth/libauth');
  }
  return getLibauth._modulePromise;
}

async function compileCasm(casmSource, label) {
  const { cashAssemblyToBin } = await getLibauth();

  // ✅ libauth 3.0.0 expects a string here
  const result = cashAssemblyToBin(casmSource);

  // In 3.0.0 this is either a Uint8Array (success) or a string (error message)
  if (!(result instanceof Uint8Array)) {
    console.error(`❌ Error compiling ${label}`);
    console.error(result);
    throw new Error(`${label} compilation failed: ${result}`);
  }

  console.log(
    `[pool_hash_fold] Compiled ${label}:`,
    bytesToHex(result)
  );

  return result;
}

// Lazy, cached compilation per version
let cachedV0 = null;
let cachedV1 = null;
let cachedV11 = null;

export async function getPoolHashFoldBytecode(version) {
  if (version === POOL_HASH_FOLD_VERSION.V0) {
    if (!cachedV0) {
      cachedV0 = await compileCasm(v0Casm, 'pool_hash_fold_v0.casm');
    }
    return cachedV0;
  }

  if (version === POOL_HASH_FOLD_VERSION.V1) {
    if (!cachedV1) {
      cachedV1 = await compileCasm(v1Casm, 'pool_hash_fold_v1.casm');
    }
    return cachedV1;
  }

  if (version === POOL_HASH_FOLD_VERSION.V1_1) {
      if (!cachedV11) cachedV11 = await compileCasm(v11Casm, 'pool_hash_fold_v1_1.casm');
      return cachedV11;
    }

  throw new Error(`Unknown pool_hash_fold version: ${version}`);
}