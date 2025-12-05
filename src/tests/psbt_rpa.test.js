// src/tests/psbt_rpa.test.js

// Minimal test harness so we can run with plain `node dist/tests/psbt_rpa.test.js`.
function describe(name, fn) {
    console.log(`\n${name}`);
    fn();
  }
  
  function it(name, fn) {
    try {
      fn();
      console.log(`  ✓ ${name}`);
    } catch (err) {
      console.error(`  ✗ ${name}`);
      console.error(err);
      // non-zero exit so CI / scripts can detect failure
      process.exitCode = 1;
    }
  }
  
  import assert from 'assert';
  import {
    encodeRpaContextV1,
    decodeRpaContextV1,
    makeRpaContextV1FromHex,
    buildRpaProprietaryKey,
    parseRpaProprietaryKey,
    attachRpaContextToPsbtOutput,
    extractRpaContextFromPsbtOutput,
    attachProofHashToPsbtOutput,
    extractProofHashFromPsbtOutput,
    attachZkSeedToPsbtOutput,
    extractZkSeedFromPsbtOutput,
    RpaPsbtSubType,
  } from '../psbt_rpa.js';
  
  describe('psbt_rpa – RpaContextV1 encoding', () => {
    it('round-trips context encode/decode', () => {
      const ctxHex = {
        mode: 3,
        index: 0,
        prevoutVout: 0,
        prevoutTxidHex:
          'f95093254228a48ef3065cd58cb4f6db745bd6ba0aa6f07e15f802c68d2ef506',
        senderPubkeyHex:
          '02ef030d836f701cf22cd84e6c80905285cda2b182baedf2df0b7e05932641e55b',
      };
  
      const ctx = makeRpaContextV1FromHex(ctxHex);
      const encoded = encodeRpaContextV1(ctx);
      const decoded = decodeRpaContextV1(encoded);
  
      assert.strictEqual(decoded.version, 0x01);
      assert.strictEqual(decoded.mode, ctx.mode);
      assert.strictEqual(decoded.index, ctx.index);
      assert.strictEqual(decoded.prevoutVout, ctx.prevoutVout);
      assert.strictEqual(
        decoded.prevoutTxid.toString('hex'),
        ctx.prevoutTxid.toString('hex'),
      );
      assert.strictEqual(
        decoded.senderPubkey.toString('hex'),
        ctx.senderPubkey.toString('hex'),
      );
    });
  
    it('rejects wrong length on decode', () => {
      assert.throws(
        () => decodeRpaContextV1(Buffer.alloc(10)),
        /expected 77 bytes/,
      );
    });
  });
  
  describe('psbt_rpa – proprietary key parsing', () => {
    it('builds and parses proprietary keys', () => {
      const key = buildRpaProprietaryKey(RpaPsbtSubType.CONTEXT);
      const parsed = parseRpaProprietaryKey(key);
      assert.ok(parsed);
      assert.strictEqual(parsed.subType, RpaPsbtSubType.CONTEXT);
      assert.strictEqual(parsed.keyData.length, 0);
    });
  
    it('returns null for non-RPA keys', () => {
      const key = Buffer.from([0x01, 0x02, 0x03]);
      const parsed = parseRpaProprietaryKey(key);
      assert.strictEqual(parsed, null);
    });
  });
  
  describe('psbt_rpa – attach/extract from PSBT outputs', () => {
    it('attaches and extracts context from a PSBT-like object', () => {
      const ctx = makeRpaContextV1FromHex({
        mode: 3,
        index: 1,
        prevoutVout: 0,
        prevoutTxidHex:
          'f95093254228a48ef3065cd58cb4f6db745bd6ba0aa6f07e15f802c68d2ef506',
        senderPubkeyHex:
          '02ef030d836f701cf22cd84e6c80905285cda2b182baedf2df0b7e05932641e55b',
      });
  
      /** @type {{ outputs: any[] }} */
      const psbt = {
        outputs: [{}],
      };
  
      attachRpaContextToPsbtOutput(psbt, 0, ctx);
      const decoded = extractRpaContextFromPsbtOutput(psbt.outputs[0]);
  
      assert.ok(decoded);
      assert.strictEqual(decoded.mode, ctx.mode);
      assert.strictEqual(decoded.index, ctx.index);
      assert.strictEqual(
        decoded.prevoutTxid.toString('hex'),
        ctx.prevoutTxid.toString('hex'),
      );
    });
  
    it('attaches and extracts proofHash and zkSeed', () => {
      const proofHash = Buffer.alloc(32, 0x11);
      const zkSeed = Buffer.alloc(32, 0x22);
  
      const psbt = { outputs: [{}] };
  
      attachProofHashToPsbtOutput(psbt, 0, proofHash);
      attachZkSeedToPsbtOutput(psbt, 0, zkSeed);
  
      const gotProofHash = extractProofHashFromPsbtOutput(psbt.outputs[0]);
      const gotZkSeed = extractZkSeedFromPsbtOutput(psbt.outputs[0]);
  
      assert.ok(gotProofHash);
      assert.ok(gotZkSeed);
      assert.strictEqual(
        gotProofHash.toString('hex'),
        proofHash.toString('hex'),
      );
      assert.strictEqual(gotZkSeed.toString('hex'), zkSeed.toString('hex'));
    });
  
    it('throws on invalid length proofHash/zkSeed', () => {
      const psbt = { outputs: [{}] };
  
      assert.throws(
        () => attachProofHashToPsbtOutput(psbt, 0, Buffer.alloc(31)),
        /proofHash must be 32 bytes/,
      );
      assert.throws(
        () => attachZkSeedToPsbtOutput(psbt, 0, Buffer.alloc(31)),
        /zkSeed must be 32 bytes/,
      );
    });
  });
  