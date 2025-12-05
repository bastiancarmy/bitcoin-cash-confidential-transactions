# Confidential Assets on Bitcoin Cash – Phase 1 Demo

> **Status:** Phase 1 is implemented and running end‑to‑end on BCH chipnet.  
> This repository is an experimental research prototype, **not** a production wallet.

This project demonstrates **confidential assets on Bitcoin Cash** using only:

- Standard **P2PKH / P2SH** scripts
- **CashTokens** (for covenant + NFT binding)
- An **off‑chain confidential amount proof** (Sigma‑style range proof)
- An **on‑chain hash** of that proof inside a covenant
- A **Pedersen commitment** bound into the CashTokens NFT commitment
- **Reusable paycodes** (RPA) that let senders derive one‑time, unlinkable payment addresses

Phase 1 focuses on proving that this construction works **end‑to‑end on chipnet** using standard BCH primitives and CashTokens. It also exports draft PSBT‑style metadata so hardware wallets and other signers can integrate later.

---

## Table of Contents

- [Conceptual Overview](#conceptual-overview)
- [Repository Layout](#repository-layout)
- [Requirements](#requirements)
- [Install & Build](#install--build)
- [Wallet & Demo Usability](#wallet--demo-usability)
  - [How wallets are created](#how-wallets-are-created)
  - [Where wallets are stored](#where-wallets-are-stored)
- [Runtime Flags & RPA Modes](#runtime-flags--rpa-modes)
  - [CLI flags](#cli-flags)
  - [Environment variables](#environment-variables)
- [Funding the Demo Wallets on Chipnet](#funding-the-demo-wallets-on-chipnet)
- [Running the Phase‑1 Confidential Asset Demo](#running-the-phase-1-confidential-asset-demo)
  - [What you’ll see on first run](#what-youll-see-on-first-run)
  - [End‑to‑end flow](#end-to-end-flow)
- [Other Demo Entry Points](#other-demo-entry-points)
- [What’s Private in Phase‑1](#whats-private-in-phase-1)
- [What’s Not Private Yet (Phase‑2 Targets)](#whats-not-private-yet-phase-2-targets)
- [Caveats & Safety](#caveats--safety)
- [License](#license)

---

## Conceptual Overview

Phase 1 shows how to create and transfer a **confidential asset** on Bitcoin Cash:

1. Alice locks a CashTokens **NFT** + BCH amount into a **covenant P2SH** output.
2. The covenant script commits to:
   - a **hash of an off‑chain confidential amount proof** (`HASH256(proofBytes)`),
   - a **one‑time “guard” pubkey hash** tied to Bob via his paycode,
   - and a **Pedersen commitment** stored in the NFT commitment field.
3. Only Bob can satisfy the covenant, because:
   - he’s the only one who can regenerate the same **one‑time child key** from his paycode,
   - he can decrypt the amount and recompute the same proof hash + commitment.
4. Bob spends from the covenant and returns the NFT + amount to a **one‑time address derived from Alice’s paycode**.
5. Alice discovers and spends that one‑time output **back to her base wallet**, closing the loop.

All three transactions look like **standard BCH/CashTokens transactions** in a block explorer, but they secretly carry a **confidential asset transfer** with a covenant‑enforced amount check.

---

## Repository Layout

The build script bundles several entry points:

```js
// build.mjs
esbuild.build({
  entryPoints: [
    'src/demo.js',
    'src/fund_schnorr.js',
    'src/tests/core.test.js',
    'src/tests/confidential.test.js',
    'src/tests/mode-switch.test.js',
    'src/tests/psbt_rpa.test.js',
  ],
  outdir: 'dist',
  // ...
});
```

Key files:

- `src/demo.js`  
  Main Phase‑1 **confidential asset + RPA demo**.  
  This is the script you’ll run most of the time (bundled to `dist/demo.js`).

- `src/fund_schnorr.js`  
  Helper CLI to construct and broadcast a Schnorr‑signed funding transaction used in some tests/demos.

- `src/keygen.js`  
  Helper CLI to generate wallet keypairs and their associated **paycodes** for testing or manual key management.

- `src/wallets.js`  
  Loads/creates Alice and Bob wallets, prompts for keys if needed, and persists them to `wallets.local.json`.

- `src/prompts.js`  
  User prompts (`promptPrivKey`, `promptFundAddress`) used by the CLI.

- `src/tests/core.test.js`  
  Core cryptographic and utility tests / demos.

- `src/tests/confidential.test.js`  
  Tests around the **confidential asset** construction (proof hash, commitments, covenant behavior, etc.).

- `src/tests/mode-switch.test.js`  
  Tests/demo for switching between different **RPA modes** (confidential asset, stealth P2PKH, PQ vault stub).

- `src/tests/psbt_rpa.test.js`  
  Tests/demo for exporting proprietary **RPA metadata** into PSBT‑like structures for future HW‑wallet integration.

All of these are bundled into `dist/` as separate Node CLI entry points.

---

## Requirements

- **Node.js:** v20+ recommended
- **npm** or **yarn**
- Access to **BCH chipnet** (testnet):
  - Either a local node or a public chipnet node via ElectrumX.
  - Test coins from a **chipnet faucet** or your own mining.

> ⚠️ The demo is hard‑wired to connect to `chipnet.imaginary.cash:50004` over WebSocket (`wss`).  
> For production or long‑term usage, you should run your own infrastructure and update `src/config.js`.

---

## Install & Build

```bash
# Clone this repository
git clone https://github.com/bastiancarmy/bitcoin-cash-confidential-transactions.git
cd bitcoin-cash-confidential-transactions

# Install dependencies
yarn install

# Build all entry points into dist/
yarn build
```

After this, you should see:

```bash
❯ ls dist
demo.js
demo.js.map
fund_schnorr.js
fund_schnorr.js.map
tests
```

And under `dist/tests/`:

```bash
❯ ls dist/tests
confidential.test.js
confidential.test.js.map
core.test.js
core.test.js.map
mode-switch.test.js
mode-switch.test.js.map
psbt_rpa.test.js
psbt_rpa.test.js.map
```

You can also use the npm scripts:

```bash
# Main demo (default mode = conf-asset)
yarn demo           # node dist/demo.js

# Explicit modes
yarn demo:conf      # node dist/demo.js --mode=conf-asset
yarn demo:stealth   # node dist/demo.js --mode=stealth-p2pkh
yarn demo:pq-vault  # node dist/demo.js --mode=pq-vault

# Test harnesses
yarn test:core
yarn test:confidential
yarn test:modes
yarn test:phase1    # runs the three above in sequence
```

---

## Wallet & Demo Usability

### How wallets are created

On first run, the demo creates (or imports) two wallets:

- **Alice** – the initial asset minter / sender.
- **Bob** – the covenant‑locked asset recipient and redeemer.

Wallets are loaded as follows (see `src/wallets.js`):

1. **From `wallets.local.json` (if it exists)**  
   If a `wallets.local.json` file is present in the current working directory, the demo loads Alice and Bob’s private keys from there.

2. **From environment variables (optional override)**  
   If set, `ALICE_PRIV_KEY` and `BOB_PRIV_KEY` **override** the values from `wallets.local.json`.

3. **From interactive prompts (fallback)**  
   If either key is still missing, the demo prints:

   ```text
   No Alice key found. Generating/entering one now…
   Enter Alice private key (hex) or press Enter to generate new:

   No Bob key found. Generating/entering one now…
   Enter Bob private key (hex) or press Enter to generate new:
   ```

   At each prompt you can either:

   - Paste an existing **32‑byte hex private key**, or  
   - Press **Enter** to let the demo generate a fresh random key.

   After this, you’ll see something like:

   ```text
   --- Obtaining Alice Wallet ---
   Alice Pub: 0213...
   Alice Address: bchtest:...

   --- Obtaining Bob Wallet ---
   Bob Pub: 02e8...
   Bob Address: bchtest:...
   ```

### Where wallets are stored

Once keys are known, the demo writes them to:

- **`wallets.local.json`** in the directory where you run `node dist/demo.js`.

You’ll also see:

```text
Note: These wallets are persisted in wallets.local.json (DO NOT COMMIT THIS FILE).
If you want to override them, set ALICE_PRIV_KEY and BOB_PRIV_KEY in your environment.
```

Guidance:

- Treat `wallets.local.json` as **sensitive** – it contains raw private keys.
- Add it to `.gitignore` and **never commit** it to a public repo.
- To reset the demo with fresh wallets, simply delete `wallets.local.json` and rerun the demo.

---

## Runtime Flags & RPA Modes

### CLI flags

The main entry point is `dist/demo.js`, which exposes:

```bash
node dist/demo.js [--mode <mode>] [--export-psbt]
```

Internally, CLI parsing is done with `commander`:

- `--mode <mode>`  
  Selects which **RPA demo mode** to run. Valid values (case‑insensitive):

  - `conf-asset` (default)  
    - Alias: `conf`, `confidential-asset`  
    - Runs the full **Phase 1 on‑chain confidential asset + covenant demo** on chipnet.
    - Creates real transactions using Alice/Bob wallets and BCH chipnet funds.

  - `stealth-p2pkh`  
    - Alias: `stealth`  
    - Runs an **off‑chain stealth P2PKH demo** (`demoStealthP2PKH()`):
      - Generates local‑only keys (not persisted).
      - Uses paycodes + RPA derivation to produce a one‑time P2PKH‑style address.
      - Demonstrates ECDH‑based amount encryption/decryption in memory.
      - **No network access, no real UTXOs, no wallet prompts.**

  - `pq-vault`  
    - Alias: `pq`, `pq_vault`  
    - Runs a **PQ vault front‑door stub** (`demoPqVaultStub()`):
      - Derives a one‑time address and PSBT‑friendly context using `RPA_MODE_PQ_VAULT`.
      - Prints the session `zkSeed` and other context that would parameterize a future Quantumroot‑style vault script.
      - Entirely local; **no network**, **no persistent wallets**.

- `--export-psbt` (boolean flag)  
  - When used with `--mode=conf-asset`, the demo still performs the full on‑chain run, **and** additionally prints a **PSBT‑like JSON export** of the covenant funding transaction, including:
    - RPA context for the Bob‑only covenant guard key,
    - Proof hash,
    - `zkSeed`.
  - This is intended as a draft format for hardware wallets / signing services.  
  - In the other modes (`stealth-p2pkh`, `pq-vault`), this flag currently has no effect.

Example invocations:

```bash
# Full Phase-1 on-chain demo (default)
node dist/demo.js

# Explicit confidential-asset mode with PSBT-like export
node dist/demo.js --mode=conf-asset --export-psbt

# Stealth P2PKH local demo (no network, no wallets.local.json)
node dist/demo.js --mode=stealth-p2pkh

# PQ vault front-door stub (local-only)
node dist/demo.js --mode=pq-vault
```

### Environment variables

Advanced users can tweak behavior via env vars:

- **Wallet control**
  - `ALICE_PRIV_KEY` – hex private key for Alice (overrides `wallets.local.json`).
  - `BOB_PRIV_KEY` – hex private key for Bob (overrides `wallets.local.json`).
  - `GENERATE_KEYS=true` – when set for `conf-asset` mode:

    ```bash
    GENERATE_KEYS=true node dist/demo.js --mode=conf-asset
    ```

    the demo will:
    - Run `keygen.js` to generate/adjust keys (ensuring even‑Y, etc.),
    - Print the new keys and addresses,
    - Exit with instructions to **update env vars** and re‑run without `GENERATE_KEYS=true`.

- **Amount / asset tuning**
  - `SEND_AMOUNT` – override the default send amount (in satoshis) for the confidential asset:
    - Default: `100000` sats (see `src/config.js`).
    - Example: `SEND_AMOUNT=250000 node dist/demo.js --mode=conf-asset`.

- **Logging**
  - `LOG_LEVEL` – one of `error`, `warn`, `info`, `debug` (default: `info`).
    - Example: `LOG_LEVEL=debug node dist/demo.js --mode=conf-asset`.
  - `LOG_FORMAT` – `plain` (default) or `json`.
  - `DEBUG` – if set, enables some low‑level `debugLog(...)` output in utilities.

---

## Funding the Demo Wallets on Chipnet

The confidential asset demo (`--mode=conf-asset`) requires **real chipnet BCH** for:

- Alice’s funding transaction (minting the NFT + locking into the covenant).
- Bob’s redemption transaction fees when he spends the covenant and returns funds to Alice.

All amounts are currently controlled from `src/config.js`:

```js
export const NETWORK  = 'chipnet';
export const DUST     = 546;        // minimum satoshis for a non-dust output
export const AMOUNT   = 100000;     // sats to lock into the covenant
export const FEE      = 5000;       // rough fee budget
// AMOUNT + FEE + DUST = 105546 sats minimum funding per wallet
```

The helper prompt in `src/prompts.js` matches this:

```js
export async function promptFundAddress(address) {
  console.log(`Please fund this ${NETWORK} address with at least ${AMOUNT + FEE + DUST} sat: ${address}`);
  console.log('Use your wallet or exchange to send BCH.');
  console.log('Press Enter after funding...');
  await new Promise(resolve => process.stdin.once('data', resolve));
}
```

So whenever a wallet has no usable UTXOs, you’ll see something like:

```text
[Alice] No UTXOs found on-chain yet.
Please fund this chipnet address with at least 105546 sat: bchtest:...
Use your wallet or exchange to send BCH.
Press Enter after funding...
```

Steps:

1. Copy the printed `bchtest:` address into a **chipnet wallet** or faucet.
2. Send **at least 105546 sats** (0.00105546 BCH) to that address.
3. Wait for the transaction to propagate (0‑conf is fine on chipnet).
4. Return to the terminal and press **Enter** to continue.

The same funding flow is used for:

- Alice’s first funding UTXO.
- Bob’s fee UTXO when he prepares the covenant‑spend transaction.

If UTXOs are present but fragmented, the demo uses `consolidateUtxos(...)` to merge them into a single `vout=0` UTXO for clarity.

---

## Running the Phase‑1 Confidential Asset Demo

The primary on‑chain demo is:

```bash
node dist/demo.js --mode=conf-asset
# or simply
yarn demo:conf
```

### What you’ll see on first run

1. **Mode selection**

   ```text
   [CLI] Selected RPA mode: confidential-asset
   ```

2. **Wallet discovery / creation**

   If `wallets.local.json` is missing and no env vars are set, you’ll see:

   ```text
   No Alice key found. Generating/entering one now…
   Enter Alice private key (hex) or press Enter to generate new:

   No Bob key found. Generating/entering one now…
   Enter Bob private key (hex) or press Enter to generate new:
   ```

   After entering or generating keys, the demo prints each wallet and notes that
   they are persisted to `wallets.local.json`.

3. **Paycode generation**

   The demo derives a **paycode** from each wallet’s base pubkey and prints it:

   ```text
   Generating paycodes from static wallet keys...
     Alice base pubkey: 0213...
     Bob   base pubkey: 02e8...

   [1A] Bob’s static paycode (for Alice → Bob)
     Bob paycode: PM8TJVdT...

   [1B] Alice’s static paycode (for Bob → Alice)
     Alice paycode: PM8TJKP...
   ```

4. **Funding prompts**

   If Alice has no UTXOs yet, you’ll see:

   ```text
   [Alice] No UTXOs found on-chain yet.
   Please fund this chipnet address with at least 105546 sat: bchtest:...
   Use your wallet or exchange to send BCH.
   Press Enter after funding...
   ```

   After you fund and hit Enter, the script retries and continues.  
   The same pattern applies later if Bob needs funding for fees.

5. **Three on‑chain transactions**

   Once funded, the demo walks through:

   - **Alice → covenant lock** (NFT + amount into P2SH covenant)
   - **Bob → Alice (paycode‑derived one‑time address)** (Bob redeems covenant)
   - **Alice (one‑time address) → Alice base wallet** (closing the loop)

   At the end you’ll see a summary like:

   ```text
   === Phase 1: Paycode → Covenant → RPA Return Demo (PZ-SQH) ===

   [0] Base wallets and paycodes
     Alice base wallet:  bchtest:...
     Alice paycode:      PM8TJKP...
     Bob base wallet:    bchtest:...
     Bob paycode:        PM8TJVd...

   [1] Alice → covenant: lock NFT + amount under Bob-only guard
     Funding txid:
       2b05aa6d3a22...

   [2] Bob → Alice: return NFT + amount to a paycode-derived one-time address
     Return txid:
       4072e94d6f10...

   [3] Alice (RPA child) → Alice (base wallet)
     RPA spend txid:
       8d78b419100f...

   Explorer links:
     https://chipnet.chaingraph.cash/tx/...
   ```

### End‑to‑end flow

From the demo’s perspective, the flow is:

1. **Wallets & paycodes**
   - Load/create Alice and Bob wallets.
   - Derive **paycodes** (long‑lived, shareable identities).
   - Derive a one‑time **covenant guard key** for Bob from:
     - Alice’s funding key (ECDH sender),
     - Bob’s paycode pubkey,
     - The funding input outpoint (`txid:vout`),
     - An index (Phase 1 uses `0`).

2. **Alice prepares & funds the confidential asset**
   - Optionally consolidate Alice’s UTXOs.
   - Create a **CashTokens category genesis UTXO**.
   - Generate an **ephemeral key** for amount encryption.
   - Encrypt the amount for Bob, e.g. `{"v":100000}`.
   - Off‑chain:
     - Generate a **Sigma‑style range proof** for that amount.
     - Compute `coreHash = HASH256(coreProofBytes)`.
     - Compute `proofHash = HASH256(envelopeBytes)`.
     - Compute a **Pedersen commitment** `C = v·H + r·G`.

3. **Covenant & commitments**
   - Commit `proofHash` in the covenant script.
   - Store the Pedersen commitment `C` in the **NFT commitment**.
   - Lock everything under a **P2SH covenant** whose guard hash is Bob’s one‑time key.

4. **Bob redeems & returns to Alice**
   - Bob locates the covenant UTXO (Phase 1 uses a known txid).
   - Decrypts the amount using his paycode secrets + Alice’s ephemeral key.
   - Rebuilds the proof hash and commitment and verifies they match on‑chain.
   - Re‑derives the same guard key and confirms the covenant matches.
   - Spends:
     - `input[0]`: covenant P2SH.
     - `input[1]`: Bob’s fee UTXO.
     - `output[0]`: NFT + amount to a **one‑time address** from Alice’s paycode.
     - `output[1]`: change back to Bob’s base wallet.

5. **Alice closes the loop**
   - Alice scans outputs using her paycode secrets.
   - Recognizes the one‑time child address as hers.
   - Derives the corresponding one‑time **private key**.
   - Spends the one‑time UTXO back to her base P2PKH, preserving the token prefix.

From the chain’s point of view, the final spend looks like a **normal tokenized P2PKH** transaction.

---

## Other Demo Entry Points

Besides `dist/demo.js`, you can run:

### `fund_schnorr.js`

```bash
node dist/fund_schnorr.js
```

- Constructs and broadcasts a **Schnorr‑signed funding transaction**.
- Useful if you want to seed specific UTXOs for experiments.

### Test harnesses (`dist/tests/*.js`)

```bash
node dist/tests/core.test.js
node dist/tests/confidential.test.js
node dist/tests/mode-switch.test.js
node dist/tests/psbt_rpa.test.js
```

These are **CLI‑style test harnesses** (not tied to a test runner in the compiled form). They:

- Exercise core cryptographic utilities.
- Validate confidential asset construction (proof hash, commitments, covenant scripts).
- Explore **mode switching** between RPA modes.
- Round‑trip PSBT‑like confidential‑asset metadata.

---

## What’s Private in Phase‑1

✅ **Proof internals**  
Only a `HASH256(proofBytes)` (or similar) is committed on‑chain; the actual Sigma range proof stays **off‑chain**.

✅ **Pedersen binding to the NFT**  
The NFT commitment carries `C = v·H + r·G`, binding the confidential amount proof to a specific **asset/category**.

✅ **Bob‑only covenant spend path**  
The covenant script is locked to a **one‑time child key** derived from Bob’s paycode. Only Bob can derive this key and satisfy the guard hash.

✅ **One‑time address for Alice on return**  
Bob returns the NFT + amount to a **one‑time address derived from Alice’s paycode**. Externally this is just a normal P2PKH + token prefix; only Alice can recognize and spend it.

✅ **PSBT‑like metadata export**  
With `--export-psbt`, the demo prints a PSBT‑style JSON blob containing proprietary keys for:
- RPA context,
- proof hashes,
- `zkSeed` and related confidential context.

---

## What’s Not Private Yet (Phase‑2 Targets)

❌ **Amounts**  
Output values are still **plaintext on‑chain**. Phase 2 will focus on using the commitments as actual **confidential amounts** (hiding values on‑chain).

❌ **Spender identity at redemption**  
Bob’s covenant spend currently includes a P2PKH fee input from his **base wallet**, linking him to the redemption. Future work may obfuscate this with separate funding flows or coinjoin‑like techniques.

❌ **Beaconless binding**  
The encrypted envelope is still visible on chain (e.g. via script pushes / OP_RETURN). Phase 2 targets more **“cash‑like” note models** and **beaconless output binding**, hiding the link between ciphertext and output.

❌ **Change to confidential addresses (disabled by default)**  
The codebase already includes logic for deriving **paycode‑based change outputs** (so change is also unlinkable). For Phase 1’s demo, change is sent back to **base P2PKH** addresses by default to avoid UX issues with wallets that don’t scan for paycode‑derived outputs.

---

## Caveats & Safety

- This is **research code**, not production software.
- The cryptography and covenant logic have **not** been formally audited.
- Network settings are baked for **BCH chipnet**, not mainnet.
- The design is still evolving; expect **breaking changes** between versions.

Please **do not** use this code with real money. It’s intended for:

- BCH developers,
- wallet authors,
- protocol researchers,

who want to explore **confidential asset constructions** on Bitcoin Cash.

---

## Donate
If you’d like to support more of this kind of research and engineering, you can send a tip in Bitcoin Cash.

<div style="text-align:center; margin-top:1.5rem; margin-bottom:1.5rem;">

  <p><strong>Scan to donate in Bitcoin Cash</strong></p>

  <img
    src="https://tan-late-rodent-367.mypinata.cloud/ipfs/bafkreibyg3yizqzzgfnawifrk244frezabie7vr22zwhm2e43ts4crvttu"
    alt="Donate in Bitcoin Cash"
    style="max-width:220px; width:100%; height:auto;"
  />

  <p style="margin-top:0.75rem;font-family:monospace;font-size:0.95rem;word-break:break-all;">
    bitcoincash:qr399w3awgzgf86520tajj9qjsf8jnwtmurfp9gymc
  </p>

</div>

Every bit helps carve out time for the unglamorous parts of this work: writing specs, tightening scripts, building reference implementations, and iterating toward a privacy stack that’s actually deployable in wallets instead of just living in whitepapers.

## License

The intention is to release this work under a **permissive open‑source license** (e.g. MIT).  
See the `LICENSE` file in the repository for the final, authoritative terms once added.
