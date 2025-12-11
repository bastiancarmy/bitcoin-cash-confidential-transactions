// test/zk_identity.test.js

const {
    ZK_ID_PROTOCOL_TAG,
    buildIdentityPublicInputs,
    encodeIdentityPublicInputs,
    decodeIdentityPublicInputs,
    provePaycodeIdentity,
    verifyPaycodeIdentity,
  } = require('../src/zk_identity'); // adjust path
  
  function randomBytes(len) {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = (Math.random() * 256) | 0;
    return out;
  }
  
  describe('ZK Identity ABI (Goal 1)', () => {
    test('encode/decode public inputs round-trip', () => {
      const inputs = buildIdentityPublicInputs({
        paycodeHash32: randomBytes(32),
        commitmentC33: randomBytes(33),
        sessionId32: randomBytes(32),
        rangeBits: 52,
        envHash32: randomBytes(32),
      });
  
      const encoded = encodeIdentityPublicInputs(inputs);
      const decoded = decodeIdentityPublicInputs(encoded);
  
      expect(decoded.protocolTag).toBe(ZK_ID_PROTOCOL_TAG);
      expect(decoded.rangeBits).toBe(52);
      expect(Buffer.from(decoded.paycodeHash32))
        .toStrictEqual(Buffer.from(inputs.paycodeHash32));
      expect(Buffer.from(decoded.commitmentC33))
        .toStrictEqual(Buffer.from(inputs.commitmentC33));
      expect(Buffer.from(decoded.sessionId32))
        .toStrictEqual(Buffer.from(inputs.sessionId32));
      expect(Buffer.from(decoded.envHash32))
        .toStrictEqual(Buffer.from(inputs.envHash32));
    });
  
    test('dummy backend proof verifies', () => {
      const inputs = buildIdentityPublicInputs({
        paycodeHash32: randomBytes(32),
        commitmentC33: randomBytes(33),
        sessionId32: randomBytes(32),
        rangeBits: 52,
        envHash32: null,
      });
  
      const proof = provePaycodeIdentity({}, inputs);
      expect(verifyPaycodeIdentity(proof)).toBe(true);
    });
  });
  