# Phase 1 – Paycode → Covenant → RPA Return

_Status: Experimental • Phase 1 complete • Phase 2–3 in design_

This document explains what the **Phase-1 paycode → covenant → RPA return demo** does and how the pieces fit together. It is intended as a **deeper design companion** to the top-level README.

The Phase-1 demo produces **three on-chain transactions** you can inspect on a chipnet block explorer:

1. **Alice → covenant** – lock NFT + amount under a Bob-only RPA guard.
2. **Bob → Alice (RPA)** – return NFT + amount to a one-time address derived from Alice's paycode.
3. **Alice (RPA child) → Alice (base)** – close the loop by spending the one-time output back to Alice's base wallet.

From the outside, each UTXO just looks like a normal **tokenized P2PKH or P2SH output**. The privacy and binding come from how keys, commitments, and covenants are constructed.

---

## 1. High-Level Story

### Actors

- **Alice** – a BCH wallet on chipnet holding BCH (base P2PKH keypair).
- **Bob** – another BCH wallet on chipnet.
- **Paycodes (RPA)** – long-lived _receive identifiers_ for Alice and Bob. Each paycode encodes public keys that can be used to derive one-time addresses for stealthy payments (RPA-style, outpoint-based).

At a high level, Phase 1 is a **stealth gift-card / confidential asset** flow:

- Alice **mints and funds** an NFT that represents a private balance.
- She **locks it** into a covenant that only a **Bob paycode-derived key** can spend.
- Bob later **redeems** the NFT by spending from that paycode-derived one-time key.
- In this Phase-1 demo, Bob simply **returns the value back to Alice**, but in general he could send it anywhere BCH is accepted.
- Finally, Alice **claims the funds** from the paycode-derived address back into her **normal wallet address**, so standard wallets can control the UTXO again.

All of this happens on **L1 BCH** with:

- Native BCH value on every hop,
- An NFT commitment that ties the value to a **Pedersen commitment / ZK context**,
- A **covenant** that enforces correct spending using introspection (equality checks).

This Phase-1 flow is the core pattern:

> **Paycode → (ZK envelope) → Scripted covenant → Hash-bound return**

and is the first phase of a larger reference architecture that wallets can reuse and extend.

---

## 2. Actors and Identifiers

### Base wallets

The demo uses two base wallets:

- **Alice base P2PKH address**  
  (derived from Alice's base compressed pubkey)
- **Bob base P2PKH address**

These are ordinary BCH chipnet addresses. The demo expects each to be funded with at least:

- `AMOUNT + FEE + DUST` sats (from `src/config.js`),
- e.g. 105546 sats in the default configuration.

### Paycodes

For each base wallet, the demo derives a **paycode**:

- **Alice paycode** – used for “Bob → Alice” payments.
- **Bob paycode** – used for “Alice → Bob” payments.

Paycodes are:

- Long-lived identifiers encoding “scan” and “spend” public keys,
- Safe to share (they do **not** reveal private keys),
- **Never used directly on-chain** – every on-chain address is a **one-time child** derived via RPA.

---

## 3. Layer 1: RPA – One-Time Addressing

The RPA layer (implemented in `src/derivation.js`) turns:

- Sender key material,
- Receiver paycode pubkey(s),
- An on-chain outpoint (`txid:vout`),
- A derivation `index`,

into a **one-time child key** and associated metadata:

- `childPubkey` / `childHash160`,
- A standard `bchtest:` P2PKH address,
- A shared secret and session keys (`amountKey`, `memoKey`, `zkSeed`),
- A small `context` object suitable for future PSBT embedding.

### How RPA is used in Phase 1

In Phase 1:

1. **Alice → covenant guard (Bob-only)**  
   Alice uses **RPA sender-side** to derive a **Bob-only guard key** for the covenant output from:
   - Her funding private key (`e`),
   - Bob’s paycode public keys (`Q/R`),
   - The funding input outpoint (`txid:vout`),
   - `index = 0`.

   She embeds `HASH160(childPubkey)` as the first 20 bytes of the covenant `redeemScript`. Only Bob can later reconstruct this child key using his paycode secrets.

2. **Bob → covenant (receiver)**  
   Bob uses **RPA receiver-side** to reconstruct that same guard key from:
   - His paycode scan/spend secrets,
   - Alice’s funding pubkey (from the funding input `scriptSig`),
   - The same outpoint,
   - `index = 0`.

   This proves that he is the unique intended spender for the covenant.

3. **Bob → Alice one-time address**  
   Bob then uses **RPA sender-side** from his **fee input** to derive a **one-time child address for Alice** from:
   - His fee input private key,
   - Alice’s paycode public keys,
   - His fee input outpoint (`txid:vout`),
   - `index = 0`.

4. **Alice → base wallet**  
   Finally, Alice uses **RPA receiver-side** to:
   - Discover that Bob’s RPA-derived output belongs to her,
   - Derive the corresponding one-time private key,
   - Spend it back to her base P2PKH address.

Crucially:

- The blockchain sees only **child keys and hash160s**.
- Paycodes themselves never appear on-chain.

---

## 4. Layer 2: Confidential Asset + Covenant

On top of RPA, the demo adds a **confidential asset primitive** using:

- **CashTokens NFT**,
- **Pedersen commitments**, and
- A simple **introspective covenant**.

### 4.1 NFT + Pedersen commitment

Alice mints a **mutable NFT** whose commitment holds a Pedersen commitment:

- `C = v · H + r · G`, where:
  - `v` = the amount (e.g. 100000 sats),
  - `r` = a blinding factor derived from a transcript and `zkSeed`,
  - `G` = secp256k1 base point,
  - `H` = a secondary generator.

This commitment is written into the NFT’s **CashTokens prefix** and travels with the NFT for the entire flow.

### 4.2 Covenant script

The **covenant script** is a compact introspective program that enforces:

1. The HASH160 of the one-time child pubkey **matches** the guard hash embedded in the `redeemScript`.
2. The BCH value of `vout[0]` **equals** the amount provided by the spender (Bob), which Bob learned by decrypting Alice’s encrypted payload.

In practice, this is implemented as:

- A **P2SH redeemScript** that commits to Bob’s one-time `hash160(childPubkey)`,
- An unlocking script that pushes:
  - The decrypted amount (as a minimally encoded script number),
  - The one-time pubkey,
  - A Schnorr signature,
  - And the `redeemScript` itself (standard P2SH pattern),
- A covenant that introspects the transaction and checks equality.

If any of these checks fail, Bob’s spend from the covenant will be invalid.

---

## 5. Layer 3: Encrypted Amount & ZK Proof Binding

To keep Bob’s spend logic tied to a specific **confidential context**, Phase 1 also wires in:

- **Encrypted amounts**, and
- A **ZK proof envelope** bound to the RPA session.

### 5.1 Encrypted amount

Alice:

1. Generates an **ephemeral keypair** `(a, A = aG)`.
2. Uses an ECDH shared secret `s = a · BobPaycodePub` to encrypt the JSON payload:

   ```json
   {"v": 100000}
   ```

3. Sends `(ephemPub, encryptedAmount)` to Bob off-chain (simulated in-process in the demo).

Bob then uses his paycode private key `b` to compute the same shared secret:

- `s = b · ephemPub`,
- Decrypts `encryptedAmount` to recover `{"v": 100000}`,
- Uses this `v` to populate the covenant unlock (and `OUTPUTVALUE(0)` equality constraint).

### 5.2 ZK proof envelope (scaffolding)

Phase-1 also includes ZK scaffolding:

- A range-proof envelope is built around the amount and commitment,
- A transcript seeded by `zkSeed` from the RPA session produces:
  - `coreHash = HASH256(coreProofBytes)`,
  - `proofHash = HASH256(envelopeBytes)`.

These hashes are:

- Used to bind the NFT commitment to a specific confidential context,
- Recomputed by Bob when he receives the envelope.

In Phase 1, the covenant **does not yet enforce** the full range proof. Instead, the ZK layer acts as:

- A **consistency check** (Bob recomputes and compares hashes),
- A scaffold for Phase 2, where proof-hash binding and verification can move closer to the consensus path.

If the proof hash ever diverges from what was committed/logged, a wallet implementation should refuse to sign.

---

## 6. How the Three Transactions Fit Together

### [1] Alice → covenant

Inputs:

- **Alice base wallet UTXO** (consolidated to `vout=0` when necessary).

Outputs:

1. **Small “marker” P2PKH to Bob’s base address**  
   Optional – used in the demo for explorer/debug visibility.

2. **Covenant-locked NFT + amount**  
   - BCH `value = AMOUNT` (e.g. 100000 sats),
   - CashTokens prefix with:
     - NFT category (derived from Alice’s funding UTXO),
     - Capability = `mutable`,
     - Commitment = Pedersen commitment `C`,
   - P2SH covenant script:
     - Guarded by `HASH160(childPubkey)` derived from **Bob’s paycode** via RPA.

3. **Change back to Alice’s base P2PKH**  
   In Phase 1, **change does not go to RPA-derived addresses** by default (to avoid UX issues with wallets that can’t scan for paycode outputs).

This transaction commits:

- The NFT and its confidential commitment,
- The BCH value attached to it,
- The fact that only a **Bob paycode-derived key** can unlock the covenant.

---

### [2] Bob → Alice (RPA return)

Bob:

1. **Decrypts the amount** using Alice’s ephemeral pubkey + his paycode secret.
2. **Reconstructs the covenant guard key** using RPA receiver logic and confirms it matches the guard hash in the `redeemScript`.
3. **Verifies the P2SH binding** – hash of the `redeemScript` matches the covenant UTXO script.
4. Selects a **fee input** from his base wallet.
5. Uses **RPA sender-side** on that fee input to derive a **one-time child address for Alice** from her paycode.

Inputs:

- Covenant P2SH UTXO (containing NFT + amount),
- Bob base wallet fee UTXO.

Outputs:

1. **NFT + amount to Alice’s RPA-derived one-time address**  
   This is `vout[0]` and from the outside it looks like:
   - A CashTokens prefix (NFT + commitment) followed by
   - A standard P2PKH script.

2. **Change back to Bob’s base wallet** (if any).

From an outside observer’s perspective, `vout[0]` is just a tokenized P2PKH address with no obvious link to Alice’s base wallet or her paycode.

---

### [3] Alice (RPA child) → Alice (base)

Alice:

1. **Scans Bob’s transaction** using her paycode secrets.
2. For each candidate UTXO, attempts **RPA receiver-side derivation**:
   - Uses her scan/spend secrets,
   - Uses Bob’s sender pubkey from his fee input scriptSig,
   - Uses Bob’s fee input outpoint (`txid:vout`) and an index (`0`),
   - Derives a candidate child pubkey and hash160.
3. When the derived `hash160` matches the P2PKH script in `vout[0]`, she knows this UTXO belongs to her.
4. She **spends** from the one-time child key back to her base wallet, preserving the NFT token prefix.

Inputs:

- One-time P2PKH UTXO derived from Alice’s paycode (Bob → Alice RPA output).

Outputs:

- Tokenized P2PKH back to **Alice’s base wallet**.

From the chain’s perspective, this is indistinguishable from a **normal token transfer back to a wallet**.

At this point:

- Alice’s base wallet holds a **standard BCH + NFT UTXO**,
- Bob has spent his fee UTXO and no longer controls the covenant-locked asset,
- The entire confidential asset loop has completed.

---

## 7. Relationship to the Main Demo

The main CLI entry point:

```bash
node dist/demo.js --mode=conf-asset
```

or:

```bash
yarn demo:conf
```

runs exactly this **Phase-1 flow**:

- Wallet discovery/creation (`wallets.local.json` + env overrides),
- Paycode derivation,
- Alice → covenant lock,
- Bob → Alice return (RPA one-time address),
- Alice (RPA child) → Alice (base wallet),
- Summary of the three txids with explorer links.

This document is the **design reference** for that flow. For installation, build, runtime flags, and wallet UX details, see the top-level **README**.

---

## 8. How This Evolves Toward PQ Vaults (Phase 2+)

Phase-1 intentionally separates concerns:

- **RPA + paycodes** – long-lived addressing and discovery, with per-payment one-time keys.
- **Confidential asset + covenant** – current guard and equality enforcement over a BCH + NFT UTXO.
- **ZK proof envelope** – a compact representation of a confidential amount proof bound to an RPA session.

In later phases:

- The **covenant script** can evolve into a richer “vault” script (e.g. Quantumroot-style) that enforces:
  - PQ-safe keys,
  - Spending delays and recovery paths,
  - Multi-factor or multi-party rules,
  - Policy-driven redemption.
- The **RPA / paycode layer** and **NFT commitments** can stay mostly the same:
  - RPA still derives one-time keys and session IDs,
  - The NFT continues to act as an **access token** and commitment carrier for vault state,
  - `zkSeed` and `proofHash` (or successors) can bind vault state and proofs into PSBTs and hardware-wallet policies.

The goal is that Phase-1 already behaves like a **thin confidential/PQ-ready front-end**:

- Wallets only need to understand paycodes, RPA derivations, and the covenant’s basic guarantees,
- The back-end script (covenant/vault) can be upgraded over time without changing how wallets identify and address outputs.

---

## 9. Glossary

- **Paycode / Reusable Payment Address (RPA)** – A long-lived receive identifier from which one-time payment addresses can be derived using sender/receiver keys and outpoints, offering better privacy than reusing a single address.
- **Paycode-derived address** – A one-time address derived from a paycode for a specific payment. Appears on-chain as an ordinary BCH address; only the paycode owner can derive its key.
- **CashToken NFT** – A non-fungible token on BCH with an optional capability and commitment. Here, we use a **mutable** NFT with its commitment bound to a Pedersen commitment of the transferred amount.
- **Covenant** – A script that constrains not just who can spend a UTXO, but **how the outputs must look**, e.g. “output 0’s value must equal this decrypted amount and be signed by this paycode-derived key.”
- **Pedersen commitment** – A cryptographic commitment scheme used here to bind a confidential amount to an NFT, with blinding.
- **Range proof** – A zero-knowledge proof that a committed amount lies in a given range without revealing the exact amount; in this phase the envelope is constructed, but enforcement still relies on equality checks and decrypted amounts.

This document, together with the main README and future Phase-2/3 docs, defines the reference architecture for **paycode-driven confidential assets on BCH layer 1**.
