# Phase 2 – ZK Proof Spec for Confidential Assets on Bitcoin Cash

> **Status:** Draft design  
> **Scope:** Define the proof statement, public inputs, witness, and algebra for the Phase‑2 “identity + amount” ZK proof, building on the Phase‑1 demo.

Phase 1 showed that we can:

- Lock value to **RPA (paycode)–derived keys** on Bitcoin Cash.  
- Attach a **Pedersen commitment** to a CashTokens NFT.  
- Enforce a **Bob‑only covenant** which checks that the on‑chain output value equals the decrypted amount.  

Phase 2 upgrades this flow so that **Bob proves ownership of the paycode and the committed amount _without_ revealing his key**. This document defines the algebra and the proof statement we are targeting, independent of any particular proof system implementation (Sigma/Bulletproof/Halo2/etc.).

The goal is to be compatible with:

- The **Confidential Transactions / Confidential Assets** model (Poelstra et al., Elements/Liquid), and  
- The planned **2026 Cash VM improvements** on BCH (bounded loops, functions, and P2S), so that later we can move verification on‑chain.

---

## 1. Algebra and Primitives

This section pins down the group, generators, and hash functions we use. The aim is to **reuse the same algebraic setting as Liquid CT** wherever possible so that existing libraries and tooling remain applicable.

### 1.1 Groups

- Let \( \mathbb{G} \) be the elliptic curve group used by Bitcoin Cash (secp256k1).  
- Let \( q \) be the prime order of \( \mathbb{G} \).  
- Let \( G \in \mathbb{G} \) be the standard generator (same as for BCH keys).

We assume standard hardness assumptions for secp256k1:

- **Discrete log hardness** in \( \mathbb{G} \).  
- **Computational Diffie–Hellman (CDH)** hardness in \( \mathbb{G} \).

### 1.2 Generators for Commitments

We require at least one **independent generator** \( H \in \mathbb{G} \) for amount commitments, and optionally more generators for asset types or other tags later.

- Define \( H = \mathrm{HashToPoint}(	ext{"amount-generator"} ) \).  
- For future confidential asset types, we may also define asset‑specific generators:  
  \[ H_	ext{asset} = \mathrm{HashToPoint}(	ext{"asset-generator"} \parallel 	ext{assetTag}) \]

For Phase 2 we only need a **single amount generator** \( H \). Asset‑type hiding is a Phase‑3 / future extension.

### 1.3 Pedersen Commitments

We use standard **additively homomorphic Pedersen commitments**:

- For amount \( v \in \mathbb{Z}_q \) and blinding factor \( r \in \mathbb{Z}_q \):  
  \[ C = \mathrm{Commit}(v, r) = v \cdot H + r \cdot G \in \mathbb{G}. \]

Properties:

- **Hiding**: Given \( C \), it is hard to learn \( v \) without the blinding \( r \).  
- **Binding**: It is hard to find \( (v, r) 
eq (v', r') \) with \( vH + rG = v'H + r'G \), under discrete log hardness.  
- **Additive homomorphism**:  
  \[ \mathrm{Commit}(v_1, r_1) + \mathrm{Commit}(v_2, r_2) = \mathrm{Commit}(v_1 + v_2, r_1 + r_2). \]

In Phase 1, this \( C \) is stored as the **NFT commitment** in the CashTokens prefix. Phase 2 keeps that representation.

### 1.4 Hash Functions and Encodings

We assume access to the usual BCH hash functions:

- \( \mathrm{SHA256} \) and \( \mathrm{HASH256} = \mathrm{SHA256}(\mathrm{SHA256}(\cdot)) \).  
- \( \mathrm{HASH160} = \mathrm{RIPEMD160}(\mathrm{SHA256}(\cdot)) \).  

We also assume a generic **hash‑to‑field** and **hash‑to‑curve** mechanism:

- \( \mathrm{H2F} : \{0,1\}^* 	o \mathbb{Z}_q \) (hash to scalar).  
- \( \mathrm{HashToPoint} : \{0,1\}^* 	o \mathbb{G} \) (hash to group element).  

For deterministic encodings, we use:

- `encodePoint(P)` and `decodePoint(bytes)` for group elements.  
- `encodeScalar(x)` and `decodeScalar(bytes)` for \( \mathbb{Z}_q \) elements.  
- CBOR/JSON or a custom binary format for structured values (envelope, public inputs).

---

## 2. Paycodes and RPA Context

Phase 2 does **not** change the high‑level paycode / RPA story from Phase 1; instead, we use the same identities as inputs to the ZK proof.

### 2.1 Paycode Parameters

Each user (e.g. Bob) has a long‑lived **paycode** with secrets and publics:

- Secrets:  
  - \( x_	ext{scan}, x_	ext{spend} \in \mathbb{Z}_q \).  
- Publics:  
  - \( P_	ext{scan} = x_	ext{scan} G \).  
  - \( P_	ext{spend} = x_	ext{spend} G \).  

The paycode string encodes `(P_scan, P_spend, metadata)` and is hashed into a short identifier:

- \( 	ext{paycodeEnc} = \mathrm{EncodePaycode}(P_	ext{scan}, P_	ext{spend}, \dots) \).  
- \( 	ext{paycodeHash} = \mathrm{HASH256}(	ext{paycodeEnc}) \).

This `paycodeHash` is what the covenant will see as an **identity tag**; the actual public keys never appear on‑chain in Phase 2’s target design.

### 2.2 RPA Session Binding

RPA (Reusable Payment Addresses) derive one‑time child keys per payment from:

- sender secret key,  
- receiver paycode pubkeys,  
- on‑chain outpoint(s),  
- an index `i`, and  
- optional transcript metadata.

We define a generic **session identifier**:

\[
	ext{sessionID} = \mathrm{HASH256}(
  	ext{"RPA-session"} \parallel 	ext{paycodeHash} \parallel 	ext{outpoint} \parallel i \parallel 	ext{extra}
).
\]

This `sessionID` will be **available as a public input** to the proof and is already present in Phase‑1 code as the `zkSeed` / “transcript seed” concept.

---

## 3. Amount Commitment and Envelope

We preserve the Phase‑1 pattern of encrypting the logical amount and committing to it via \( C \).

### 3.1 Logical Amount Range

We work with logical amounts \( v \) in a fixed range:

- \( v \in [0, 2^k) \) with \( k \leq 52 \) by default.  
  - 52 bits matches typical CT deployments and comfortably covers BCH‑sized amounts.  
- The actual BCH `value` field of the covenant UTXO is used as **fee + dust anchor**, not as the logical amount.

### 3.2 Pedersen Commitment in NFT

The NFT commitment field holds:

- \( C = vH + rG \), where:
  - \( v \) = logical asset amount,  
  - \( r \) = blinding factor derived from the RPA transcript (e.g. via `H2F(sessionID || "blind")`).

This makes the NFT act as a **handle for a blinded balance**, carried across spends.

### 3.3 Encrypted Amount Envelope

The sender (Alice) also encrypts \( v \) for Bob using a shared secret derived from:

- Alice’s ephemeral keypair \( (a, A = aG) \).  
- Bob’s static paycode public(s), typically \( P_	ext{scan} \).

For a shared secret:

- \( s = \mathrm{KDF}(a \cdot P_	ext{scan}) \in \{0,1\}^{\lambda} \),  

we define a symmetric encryption scheme:

- \( c = \mathrm{Enc}_s(	ext{encode}(v, 	ext{metadata})) \).

The **envelope** \( E \) carries:

- `A` (ephemeral pubkey),  
- `c` (ciphertext),  
- optional proof metadata and transcript tags.

In Phase 2, we treat the equality  
\( v = \mathrm{Dec}_s(c) \)  
primarily as an **off‑chain check**; we record it in the proof statement so the circuit _can_ enforce it later, but initial implementations may elide this and rely on wallet‑side checks instead.

---

## 4. Proof Statement (Single‑Spend Case)

We now define precisely what the Phase‑2 ZK proof should assert for a **single covenant spend** (e.g. Bob spending a covenant UTXO locked to his paycode).

### 4.1 Public Inputs

The contract (covenant) and verifiers see the following public inputs:

1. **Identity tag**
   - \( 	ext{paycodeHash} \in \{0,1\}^{256} \).  

2. **Commitment**
   - \( C \in \mathbb{G} \): the NFT commitment taken from the CashTokens prefix.  

3. **Session / transcript binding**
   - \( 	ext{sessionID} \in \{0,1\}^{256} \) – typically a hash of:
     - `paycodeHash`,  
     - covenant funding outpoint,  
     - index and mode flags.  

4. **Range bound**
   - \( k \) such that \( 0 \le v < 2^k \).  (Can be fixed protocol‑wide.)  

5. **Optional ciphertext binding (off‑chain for now)**
   - The envelope hash:  
     \( 	ext{envHash} = \mathrm{HASH256}(E) \).  
   - The covenant can store `envHash` in a field or script constant; the proof may treat it as an input for future designs.

6. **Chain context (optional / future)**
   - Block height, timelocks, or additional Merkle roots (e.g. for note trees) if we extend to pool semantics.

### 4.2 Witness (Secrets Held by the Prover)

Bob (the prover) holds the following secrets:

1. **Paycode secret keys**
   - \( x_	ext{scan}, x_	ext{spend} \in \mathbb{Z}_q \),  
   - with public keys \( P_	ext{scan} = x_	ext{scan} G \), \( P_	ext{spend} = x_	ext{spend} G \).

2. **Commitment opening**
   - Logical amount \( v \in [0, 2^k) \).  
   - Blinding \( r \in \mathbb{Z}_q \), such that \( C = vH + rG \).

3. **(Optional) Envelope secret**
   - Shared secret \( s = \mathrm{KDF}(x_	ext{scan} \cdot A) \) with Alice’s ephemeral pubkey \( A \).  
   - The decrypted plaintext `m = Dec_s(c)` which encodes \( v \) and metadata.

4. **RPA child key material (for current scheme compatibility)**
   - One‑time child key \( x_	ext{child} \) (derived from RPA receiver function).  
   - Relation to paycode secrets and `sessionID`:
     - e.g. \( x_	ext{child} = x_	ext{spend} + \mathrm{H2F}(	ext{sessionID}) \mod q \).  
   - The actual on‑chain script in Phase 2 may no longer reveal `childPub`, but we include this relation so the proof can tie the spend to the same RPA context used in Phase 1.

### 4.3 Relations to Be Proven

The proof must demonstrate that the witness satisfies all of the following relations with respect to the public inputs.

#### R1 – Paycode correctness

There exist \( x_	ext{scan}, x_	ext{spend} \) such that:

1. \( P_	ext{scan} = x_	ext{scan} G \).  
2. \( P_	ext{spend} = x_	ext{spend} G \).  
3. \( 	ext{paycodeHash} = \mathrm{HASH256}(\mathrm{EncodePaycode}(P_	ext{scan}, P_	ext{spend}, \dots)) \).

This proves that the prover **controls the same identity** that the covenant is parameterized with, without revealing the keys or the raw paycode.

#### R2 – Commitment opening

There exist \( v, r \) such that:

1. \( C = vH + rG \).  
2. \( 0 \le v < 2^k \).

This is a **range proof** that the commitment corresponds to a valid, non‑negative amount in bounded range.

#### R3 – Session binding / RPA consistency

Given \( x_	ext{spend} \) and \( 	ext{sessionID} \):

1. Define \( \delta = \mathrm{H2F}(	ext{sessionID}) \).  
2. Define a conceptual **child key**:  
   \[ x_	ext{child} = x_	ext{spend} + \delta \mod q. \]

The proof must ensure that all constraints and any external signature logic that refer to `sessionID` are **consistent with this derived child key**.

- In Phase 2a (hybrid approach), the chain may still see a **public child key** and a signature; the proof’s role is to ensure that this child key is derived from the same paycode secrets as the commitment, while future versions may remove the explicit key from the script entirely.

#### R4 – (Optional) Envelope correctness

For future, fully circuit‑verified designs, the proof should optionally show that:

1. \( s = \mathrm{KDF}(x_	ext{scan} \cdot A) \).  
2. \( 	ext{Dec}_s(c) = 	ext{encode}(v, 	ext{metadata}) \).  
3. \( 	ext{envHash} = \mathrm{HASH256}(E) \).

This binds the **off‑chain encrypted envelope** to the commitment and the paycode identity in a way that auditors and counterparties can verify via the same proof. For the first Phase‑2 implementation, we can leave R4 as **informative** rather than mandatory (wallet‑only validation).

### 4.4 Combined Statement

Summarizing: the ZK proof asserts that the prover knows

\[
(x_	ext{scan}, x_	ext{spend}, v, r, x_	ext{child}, s, \dots)
\]

such that:

1. `paycodeHash` encodes the same paycode params corresponding to \( (x_	ext{scan}, x_	ext{spend}) \).  
2. `C` is a valid Pedersen commitment to amount \( v \in [0, 2^k) \).  
3. The RPA session (`sessionID`) is consistent with the derived child key used for this spend.  
4. (Optional initially) The encrypted envelope \( E \) decrypts to `v` under a key derived from the same paycode secrets.

All of this is proven **without revealing** \( x_	ext{scan} \), \( x_	ext{spend} \), \( v \), \( r \), or \( x_	ext{child} \).

---

## 5. Relation to Blockstream Confidential Transactions / Assets

This design is intentionally close to the CT / Confidential Assets model used in Elements/Liquid:

- **Same group and commitment form**  
  - We use secp256k1 and Pedersen commitments \( C = vH + rG \), as in CT.  
- **Same range proof goal**  
  - We want a ZK proof that \( v \) is in a valid range and that **no inflation** occurs once we generalize to multi‑input, multi‑output updates.  
- **Different environment**  
  - On Liquid, CT verification is wired into the Elements consensus engine.  
  - On BCH, we must implement verification using the **Cash VM**, so the 2026 features (bounded loops, functions, and P2S) are key to making on‑chain verification manageable.

Compatibility notes:

- We can **reuse existing CT libraries** for:
  - Constructing commitments and range proofs off‑chain.  
  - Potentially verifying them off‑chain for wallet or auditor use.  
- On-chain, we can:
  - Start with **hybrid verification** (off‑chain proof checking + on‑chain sanity checks), then  
  - Move to full on-chain verification once the Cash VM features and performance constraints are clear.

The main divergence from Liquid is that we additionally tie commitments to a **paycode‑based identity** (`paycodeHash`) and an **RPA session**, which is specific to the BCH/RPA story in this repo.

---

## 6. Security Assumptions

For review by cryptographers, we make the following explicit assumptions:

1. **Group assumptions**
   - secp256k1 has prime order \( q \) and is resistant to:
     - Discrete log attacks in \( \mathbb{G} \),  
     - CDH and related hardness assumptions.

2. **Commitment security**
   - \( H \) is generated as an independent generator with no known discrete log relative to \( G \).  
   - Pedersen commitments are:
     - Computationally binding under discrete log hardness.  
     - Perfectly hiding when \( r \) is chosen uniformly at random.

3. **Hash functions**
   - HASH256, HASH160, H2F, and HashToPoint behave as random oracles in the security analysis.  

4. **Proof system soundness and zero-knowledge**
   - The chosen ZK system (Sigma, Bulletproofs, Plonkish, etc.) is:
     - **Sound**: no adversary can produce a valid proof for a false statement except with negligible probability.  
     - **Zero-knowledge**: proofs leak no information beyond the truth of the statement.  
     - **Composably secure** when combined with commitments and hash‑based transcripts.

5. **Encryption scheme**
   - The symmetric encryption (e.g. ChaCha20‑Poly1305 or AES‑GCM) used for the amount envelope is:
     - IND‑CPA or IND‑CCA secure, as required, under keys derived from the ECDH shared secret.

6. **Implementation assumptions**
   - Private keys, blinds, and seeds are generated with sufficient entropy and never reused in ways that break the hiding property.  
   - Proper side‑channel resistance is required in production implementations.

---

## 7. Notes Toward Implementation Milestones

This spec is intentionally proof‑system‑agnostic. For concrete Phase‑2 work, we can break it down as:

1. **M2.1 – Circuit skeleton**
   - Encode R1 (paycode), R2 (commitment + range), and R3 (session binding) in a chosen proof framework (e.g. a Bulletproofs‑style circuit or a Plonkish system).

2. **M2.2 – Library integration**
   - Wrap the circuit in a simple API:  
     - `prove_identity_amount(paycode, C, sessionID, witness)`  
     - `verify_identity_amount(publicInputs, proof)`.

3. **M2.3 – Wire to Phase‑1 demo**
   - Replace “Bob signs with RPA key” with:
     - “Bob attaches ZK proof π + minimal on-chain linkage” in the covenant unlock path.  
   - Keep Schnorr signatures for basic authorization as needed, but move **identity revelation** into the proof instead of the script.

4. **M2.4 – Cash VM mapping (2026 target)**
   - Map the verification equations to 2026 Cash VM capabilities (loops + functions).  
   - Design a covenant template that can verify proofs / or at least check commitments and session IDs while relying on off‑chain verification for heavy math initially.

This document should be kept in `doc/phase2-proof.md` and updated as we refine the exact proof system and any BCH‑specific constraints that emerge.
