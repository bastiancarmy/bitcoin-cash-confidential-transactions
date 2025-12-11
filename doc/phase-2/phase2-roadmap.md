# Phase 2 Roadmap – ZK Identity & ZK-Aware Covenants for CTv1

_Status: Phase 1 + CTv1 envelope (“Phase 1.5”) complete on chipnet._  
_This document defines Phase 2 tasks and stretch work toward Phase 3._

---

## 0. Current Status (Phase 1 + 1.5)

Phase 1 (`--mode=conf-asset`) demonstrates an end-to-end **paycode → covenant → RPA return** flow on BCH chipnet:

- CashTokens NFT + BCH amount locked under a **paycode-derived covenant guard key**.
- **Pedersen commitment** bound into the NFT commitment.
- **Off-chain Sigma-style range proof (Sigma64)** with a CTv1 **amount envelope**, and a proof hash bound into the covenant.
- Three real on-chain transactions:
  - Alice → covenant,
  - Bob → Alice (RPA one-time address),
  - Alice (RPA child) → Alice (base wallet).

Phase 1.5 adds:

- A concrete **Sigma64 range proof** implementation over secp256k1 with:
  - deterministic prover seeded as `seed = sha256(ephemPub33 || uint64le(amount))`,
  - a shared Pedersen generator `H` reused across Pedersen commitments and ZK.
- A CTv1 **amount envelope format**:
  - `protocolTag = "BCH-CT/Sigma64-v1"`,
  - `rangeBits = 64`,
  - binding `ephemPub33`, `H33`, optional `assetId32`, `outIndex`, and `extraCtx`,
  - carrying the serialized Sigma64 core proof.
- A **test harness** (`confidential.test.js`) and logs covering:
  - RPA derivation,
  - session keys,
  - Pedersen commitments,
  - CTv1 amount envelope round-trip (including tamper detection).

This roadmap treats that as the foundation and focuses Phase 2 on **identity ZK**, **ZK-aware covenants**, and **wallet-ready integration**, while keeping the proof system modular enough to later swap in **post-quantum / <100KB** proof systems when they exist.

---

## 1. Phase 2 High-Level Goals

**Goal 1 – ZK identity for paycodes**

Replace “Bob reveals an RPA pubkey + signature” with a **zero-knowledge proof** that:

- Bob knows the secret key(s) behind a given paycode hash (or identity root),
- The amount he spends is consistent with the NFT commitment and CTv1 amount envelope,
- The amount lies in a valid range.

Initially this can use a classical (non-PQ) system (Sigma-like, Bulletproof-ish, SNARK, etc.), but the **spec and ABI must be proof-system agnostic** so it can later host a **post-quantum, <100KB proof** when such systems are practical.

**Goal 2 – ZK-aware covenants**

Upgrade the existing covenants so they:

- Accept **proof blobs + public inputs** as unlock data,
- Bind proof hashes into the existing NFT commitment / script logic,
- Maintain the same overall transaction shape (CashTokens NFT + covenant + RPA),
- Keep the **on-chain footprint minimal** (ideally still just 32-byte hashes and small public input blobs) to minimize TX fees.

**Goal 3 – Wallet-ready integration**

Extract reusable libraries and documentation so that **wallets and apps** can:

- Generate paycodes,
- Use RPA to send and receive confidential assets,
- Plug into ZK identity proofs via PSBT-like metadata,
- Treat the proof system as an implementation detail behind stable APIs.

**Goal 4 – Prepare for 2026 Cash VM**

Design circuits, proof formats, and on-chain data layouts so they can be **ported to on-chain verification** when:

- bounded loops,
- script functions, and
- Pay-to-Script (P2S)

become available, while preserving the ability to swap in future **post-quantum, succinct** proof systems.

---

## 2. Milestones Overview

Phase 2 is structured into three concrete milestones plus a stretch design milestone for Phase 3:

1. **Milestone 0 – CTv1 Sigma64 & Envelope (completed)**
2. **Milestone 1 – ZK Paycode Identity Spec & Off-Chain Prover**
3. **Milestone 2 – ZK-Aware Covenant & Demo Mode**
4. **Milestone 3 – Libraries & Wallet Integration Guide**
5. **Stretch – Phase 3 Design: Fully Confidential Amounts & Pools**

Milestone 0 is complete; Milestones 1–3 are the remaining work for Phase 2.

---

## 3. Milestone 0 – CTv1 Sigma64 & Envelope (Completed)

**What’s already done**

- **M0.1 – Sigma64 range proof implementation**
  - 64-bit Sigma range proof over secp256k1 using a shared Pedersen generator `H`.
  - Deterministic prover randomness:
    - `seed = sha256(ephemPub33 || uint64le(amount))`.

- **M0.2 – CTv1 amount envelope**
  - Envelope builder and verifier:
    - `protocolTag = "BCH-CT/Sigma64-v1"`,
    - `rangeBits = 64`,
    - fields for `ephemPub33`, `H33`, `assetId32` (optional), `outIndex`, `extraCtx`,
    - `coreProofBytes` serialized Sigma64 proof.
  - Hashes:
    - `coreHash = hash256(coreProofBytes)` for identity / note binding,
    - `proofHash = hash256(envelope)` for covenant binding.

- **M0.3 – Binding to NFT and covenant**
  - NFT commitment uses `commitmentC33` (compressed `C`) from the Sigma64 proof.
  - Covenant script commits to `proofHash` so spending requires a consistent CTv1 envelope.

- **M0.4 – Test harness & vectors**
  - Phase-1 tests now cover amount envelope round-trip, including tampering.
  - Logs expose:
    - seed, ephemPub33, envelope size,
    - `proofHash`, `commitmentC33`,
    - any header fields exposed by the transcript layer.

These foundations are assumed by the remaining milestones.

---

## 4. Milestone 1 – ZK Paycode Identity Spec & Off-Chain Prover

### 4.1. Formal statement & spec

**Tasks**

- **M1.1 – Define the proof statement.**  
  Precisely specify what the ZK proof should assert. For example:

  > “I know secret(s) such that:  
  >  - `pk = sk · G` participates in the paycode derivation,  
  >  - `H(paycodeParams) = paycodeHash` (or identity root),  
  >  - The Pedersen commitment `C` encodes an amount `v` in `[0, 2^k)` with blinding `r`,  
  >  - `v` matches the decrypted value from the CTv1 amount envelope,  
  >  - (Optionally) this spend respects a user-defined policy (e.g. limits, KYF checks).”

- **M1.2 – Define public inputs.**  
  Enumerate what the contract / verifier sees as public inputs:

  - `paycodeHash` or identity root,
  - NFT commitment (`C`) – or its compressed form `commitmentC33`,
  - `coreHash` and/or `proofHash` from the CTv1 envelope,
  - any RPA context hashes (session identifiers, transcript tags),
  - optional Merkle roots (if planning for pools),
  - optional chain context (block height, txid prefixes, etc., if needed).

- **M1.3 – Define witness.**  
  Enumerate what the prover must know:

  - Paycode secret key(s) (scan/spend),
  - Blinding factor `r`,
  - Logical amount `v`,
  - Any note / leaf preimages if designing ahead for pool semantics,
  - Optional identity / compliance attributes (for future policy checks).

- **M1.4 – Document security assumptions.**  
  Capture assumptions so cryptographers can review:

  - Group choice (currently secp256k1; not post-quantum),
  - Hash functions and soundness levels (96 bits or higher),
  - ZK properties (no information about `v` or `sk` beyond the statement),
  - The fact that the **spec is proof-system agnostic**:
    - classical Sigma64 + CTv1 now,
    - future post-quantum, <100KB systems later.

### 4.2. Prototype circuits & off-chain prover/verifier

**Tasks**

- **M1.5 – Choose reference proof system(s) for prototyping.**  
  For Phase 2, pick a practical system for **off-chain** identity proofs, e.g.:

  - Bulletproof-like constructions,
  - Groth16 / Plonk variants,
  - Custom Sigma protocols extended beyond Sigma64.

  The key is to treat this as a **reference implementation**, not a forever choice. The proof format and ABI should allow swapping in future **post-quantum / succinct (<100KB)** systems when available.

- **M1.6 – Implement core circuits.**  
  Implement circuits or gadgets for:

  - Identity knowledge: “I know `sk` for `paycodeHash`”.
  - Commitment correctness: `C = v · H + r · G`.
  - Range proof: `v` within bounds (can reuse or reference the existing Sigma64 logic conceptually).
  - (Optional) Note / pool preimage checks for Phase 3.

- **M1.7 – Implement reference prover/verifier.**  
  Provide:

  - A prover: `(witness, publicInputs) → zkProofBytes`,
  - A verifier: `(zkProofBytes, publicInputs) → true/false`,
  - A thin interface that abstracts over the specific proof system.

- **M1.8 – Test harness + vectors.**  
  Add a CLI or test harness that:

  - Generates random paycodes, commitments, amounts,
  - Produces valid proofs and checks them,
  - Outputs JSON test vectors capturing:
    - paycode inputs,
    - `C`, `coreHash`, `proofHash`,
    - public inputs and `zkProofBytes`.

**Outputs**

- `docs/zk-identity-spec.md` – human-readable spec of the identity proof statement and ABI.
- `src/zk_identity/` – reference prover/verifier code and tests.
- JSON test vectors for identity ZK, designed to be reused by Cash VM implementers and other ecosystems.

---

## 5. Milestone 2 – ZK-Aware Covenant & Demo Mode

### 5.1. Extend the covenant unlock ABI

**Tasks**

- **M2.1 – Define the ZK unlock ABI.**  
  Specify the stack layout for ZK unlocks, e.g.:

  ```text
  [ zkProofBytes ] [ publicInputsBytes ] [ redeemScript ]
  ```

  where `publicInputsBytes` encodes the same public inputs defined in Milestone 1, potentially including:

  - `paycodeHash`,
  - `commitmentC33`,
  - `coreHash` and/or `proofHash` (CTv1),
  - RPA context identifiers,
  - any pool / note indices (future use).

- **M2.2 – Bind proof hashes to NFT commitment & script.**  
  Decide how the identity proof is committed to:

  - Compute `idProofHash = hash256(zkProofBytes || publicInputsBytes)`,
  - Integrate `idProofHash` with:
    - the NFT commitment (e.g. in a commitment tree),
    - the covenant script (e.g. via script constants),
  - Ensure consistency across spends (*same identity root, same C, same CTv1 coreHash*).

- **M2.3 – Update covenant builders.**  
  Extend existing covenant builders to:

  - Accept ZK-related parameters (`zkProofBytes`, `publicInputsBytes`, `idProofHash`),
  - Include the required hash glue and script changes,
  - Preserve backward compatibility for existing `--mode=conf-asset` demo where possible.

### 5.2. New demo mode: `--mode=conf-identity`

**Tasks**

- **M2.4 – Implement `conf-identity` flow.**  
  Add a new CLI mode in `src/demo.js` that:

  1. Performs the same overall flow as Phase 1:
     - Alice → covenant,
     - Bob → Alice (RPA one-time address),
     - Alice (RPA child) → Alice (base).
  2. But in the **Bob → covenant** step, uses:
     - `zkProofBytes + publicInputsBytes` instead of “RPA pubkey + signature” as evidence of:
       - Bob’s identity (ownership of the paycode),
       - consistency between `v`, `C`, and the CTv1 envelope.

- **M2.5 – Integrate off-chain identity verifier.**  
  Before signing, the demo should:

  - Construct `publicInputsBytes` from wallet + chain state,
  - Generate the identity ZK proof,
  - Verify it locally (defensive assertion),
  - Bind `idProofHash` into the NFT / covenant and PSBT metadata.

- **M2.6 – Logging & explorer guidance.**  
  Extend logs to show:

  - The three txids (as in Phase 1),
  - Human-readable info about:
    - the CTv1 envelope (size, `proofHash`, `coreHash`),
    - the identity proof (`zkProofBytes` size, `idProofHash`),
  - Clear notes about which parts are off-chain vs on-chain enforced.

### 5.3. PSBT-like metadata export (ZK edition)

**Tasks**

- **M2.7 – Extend PSBT-like JSON export.**  
  Add proprietary PSBT fields for:

  - `zkProofBytes` (identity proof),
  - `publicInputsBytes`,
  - `idProofHash`,
  - existing CTv1 `proofHash` and `coreHash`,
  - RPA context and `zkSeed` (where appropriate).

- **M2.8 – Document PSBT extensions.**  
  Create `docs/psbt-zk-metadata.md` describing:

  - Key format and semantics (proprietary PSBT key types),
  - Example PSBT blobs for identity ZK spends,
  - How hardware wallets/airgapped signers should interpret them, keeping the proof system pluggable.

**Outputs**

- Updated `src/covenants.js` and covenant builders.
- New demo mode: `--mode=conf-identity`.
- Extended PSBT-style ZK metadata export.
- Docs explaining the ZK unlock ABI and metadata layout.

---

## 6. Milestone 3 – Libraries & Wallet Integration Guide

### 6.1. Extract reusable libraries

**Tasks**

- **M3.1 – Factor paycode + RPA logic.**  
  Package existing paycode and RPA derivation into a library, e.g.:

  - `@bch-confidential/paycodes`,
  - API for:
    - creating paycodes,
    - deriving one-time addresses (sender),
    - recovering one-time keys (receiver),
    - exposing RPA context data for ZK/public inputs.

- **M3.2 – Factor ZK identity module.**  
  Provide a library for:

  - Constructing public inputs from wallet + CTv1 state,
  - Calling the identity ZK prover,
  - Verifying proofs off-chain,
  - Abstracting over proof-system details (classical now, PQ later).

- **M3.3 – Covenant & transaction helpers.**  
  Provide helpers for:

  - Building `conf-asset` and `conf-identity` spends,
  - Handling token prefixes, commitments, CTv1 envelopes, and covenant scripts,
  - Managing fee inputs & RPA change outputs.

### 6.2. Wallet integration patterns

**Tasks**

- **M3.4 – “How to integrate in a wallet” docs.**  
  Write developer documentation explaining how a wallet:

  - Generates and displays paycodes,
  - Scans for RPA-derived outputs,
  - Uses CTv1 envelopes and Sigma64 proofs,
  - Calls the identity ZK module on send/receive,
  - Surfaces user-friendly flows (“Send confidential BCH to this paycode”).

- **M3.5 – Sample integration (CLI or plugin).**  
  Implement at least one:

  - Sample CLI wallet script, or
  - Proof-of-concept plugin for an existing BCH wallet (if feasible).

**Outputs**

- NPM-ready packages (or equivalents) for:
  - paycodes/RPA,
  - ZK identity,
  - covenant/CTv1 helpers.
- `docs/wallet-integration.md` with integration guidance.
- Example code for a minimal wallet using the libraries.

---

## 7. Stretch – Phase 3 Design: Fully Confidential Amounts & Pools

This stretch work focuses on **Phase 3 design** without fully implementing it yet. It should remain compatible with future **post-quantum, succinct (<100KB)** proof systems.

### 7.1. Fully confidential logical amounts

**Tasks**

- **S1 – Spec: logical amounts in commitments.**  
  Define how:

  - Logical user amounts live entirely in Pedersen commitments (no cleartext amounts),
  - On-chain `value` is primarily dust/fee anchor,
  - Range proofs ensure non-negative, bounded balances.

- **S2 – Spec: confidential UTXO model.**  
  Describe:

  - The structure of a “confidential UTXO” (tokenData + script + commitments + hashes),
  - Proof obligations during a spend:
    - no inflation,
    - balanced sums between inputs and outputs,
  - Interaction with transparent UTXOs and fee-paying.

### 7.2. Pools & multi-user flows

**Tasks**

- **S3 – Design zk-pool contracts.**  
  High-level spec for:

  - “Bob pool” and “Jane pool” covenants (or more general pools),
  - Rules for deposit, internal transfer, and withdrawal,
  - How NFT commitments encode pool state (e.g. Merkle roots over notes).

- **S4 – Identity integration.**  
  Show how paycode-based identity ZK extends to:

  - Ownership of specific notes in a pool,
  - Access control to pool operations,
  - Optional compliance hooks (if desired).

- **S5 – Map to 2026 Cash VM.**  
  Sketch how loops, functions, and P2S would:

  - Implement pool ZK verification on-chain,
  - Keep scripts analyzable and bounded,
  - Stay compatible with future PQ proof systems (e.g., STARK-like) when they become practical at <100KB.

**Outputs**

- `docs/phase3-confidential-pools-spec.md` – design-level document.
- Example JSON transaction flows for pool interactions.
- A clear “this is what we’ll implement once 2026 VM + PQ-friendly proofs are live” roadmap.

---

## 8. Alignment with 2026 Cash VM & Future PQ ZK

Phase 2 is explicitly designed so its ZK pieces can be ported into the upgraded VM and later host **post-quantum, succinct** proof systems.

### 8.1. Bounded loops (OP_BEGIN / OP_UNTIL)

Use cases:

- Iterating over bits/limbs of scalars in range proofs,
- Iterating over small sets of commitments/notes,
- Parsing proof blobs in structured ways.

**Design constraint**

- Circuits and proof formats should be expressible as simple per-bit/per-note operations wrapped in bounded loops with known worst-case costs.

### 8.2. Functions (OP_DEFINE / OP_INVOKE)

Use cases:

- Reusable primitives for:
  - point addition,
  - scalar multiplication,
  - hash permutations,
  - basic gadgets (e.g. “verify CTv1 envelope header”).

**Design constraint**

- Keep off-chain implementations modular:
  - `ec_add`, `ec_mul`, `verify_range_proof`, `verify_identity_proof`, etc.,
  - so they map directly to script-level functions later.

### 8.3. Pay-to-Script (P2S)

Use cases:

- Make shielded/confidential contracts first-class outputs:
  - Contracts are paid directly (no P2SH wrappers),
  - Shielded UTXOs blend naturally into the UTXO set.

**Design constraint**

- Treat Phase-2 contracts as early versions of scripts that will eventually be deployed as P2S contracts in Phase 3.

---

## 9. Phase 2 Deliverables Checklist

By the end of Phase 2, the project should have:

- ✅ A **formal ZK identity spec** for paycodes and commitments.
- ✅ A working **off-chain identity prover & verifier** with test vectors.
- ✅ ZK-aware **covenant builders** and a new `--mode=conf-identity` demo.
- ✅ Extended **PSBT-like metadata** that carries ZK context.
- ✅ Reusable **libraries** for:
  - paycodes/RPA,
  - ZK identity,
  - CTv1/covenant helpers.
- ✅ Developer-facing **wallet integration docs** and example code.
- 🟡 (Stretch) A written **Phase-3 spec** for confidential amounts and pools that anticipates:
  - 2026 Cash VM loops/functions/P2S, and
  - future post-quantum, succinct (<100KB) proof systems.
