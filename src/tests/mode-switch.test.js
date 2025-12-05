// src/tests/mode-switch.test.js
//
// Lightweight tests for RPA mode demos:
//   - stealth-p2pkh demo should complete without throwing.
//   - pq-vault stub demo should complete without throwing.
//
// These tests do NOT hit the network; they rely only on pure crypto paths.

import {
    demoStealthP2PKH,
    demoPqVaultStub,
  } from '../demo.js';
  
  /* -------------------------------------------------------------------------- */
  /* Tiny test harness                                                          */
  /* -------------------------------------------------------------------------- */
  
  function assert(condition, message) {
    if (!condition) {
      throw new Error(message || 'Assertion failed');
    }
  }
  
  async function runTest(name, fn) {
    try {
      await fn();
      console.log(`✅ ${name}`);
    } catch (err) {
      console.error(`❌ ${name}`);
      console.error(err);
      globalThis.__modeTestsFailed = true;
    }
  }
  
  async function main() {
    console.log('══════════════════════════════════════════════');
    console.log(' Phase-1: RPA mode toggle demo tests');
    console.log('══════════════════════════════════════════════\n');
  
    assert(
      typeof demoStealthP2PKH === 'function',
      'demoStealthP2PKH is not a function',
    );
    assert(
      typeof demoPqVaultStub === 'function',
      'demoPqVaultStub is not a function',
    );
  
    await runTest('stealth-p2pkh demo completes', async () => {
      await demoStealthP2PKH();
    });
  
    await runTest('pq-vault stub demo completes', async () => {
      await demoPqVaultStub();
    });
  
    if (globalThis.__modeTestsFailed) {
      console.error('\n❌ RPA mode demo tests FAILED');
      process.exit(1);
    } else {
      console.log('\n✅ RPA mode demo tests passed');
    }
  }
  
  main().catch((err) => {
    console.error('Unexpected error in mode-switch test runner:', err);
    process.exit(1);
  });
  